"""
Firebase privilege relay
========================

A small hosted service that holds the Firebase service-account private key so
the desktop application never has to.

Why this exists
---------------
The desktop app needs a handful of privileged Firebase operations: creating
staff accounts, setting role claims, and reading/writing a few Firestore
documents. Performing those locally means shipping the service-account private
key inside every customer's installer — and anyone who extracts that key gains
total control of the Firebase project: minting themselves admin accounts,
forging activation codes, and reading every other shop's data.

This relay keeps the key in one place you control. The desktop app calls it
over HTTPS and gets back only the specific result it asked for.

Protection layers
-----------------
1. Shared secret (X-Relay-Secret) — a coarse gate that keeps unrelated
   internet traffic out. It ships inside the app, so treat it as a filter and
   NOT as a credential. Nothing below may rely on it alone.
2. Caller identity — every operation that touches an account requires the
   caller's own Firebase ID token, verified here.
3. Entitlement — what the caller may then do is decided from data only the
   control panel can write (an `activationCodes` document, an `accounts`
   document), never from what the caller asks for.
4. Collection allow-list — Firestore access is limited to the exact
   collections this product uses, with per-collection rules.

The rule that has to hold
-------------------------
NO PATH MAY GRANT THE ADMIN ROLE ON THE STRENGTH OF THE SHARED SECRET, OR ON
THE STRENGTH OF THE CALLER SIMPLY BEING SIGNED IN.

An earlier version of this file broke that rule twice over. `user.set_claims`
accepted any caller setting claims on their OWN uid — so a cashier could name
themselves admin — and accepted a request with no caller at all as long as the
role being granted was "admin", on the strength of a comment saying the
desktop backend had checked an activation code first. The relay never verified
that, and could not: the check sat on the other side of a boundary the
attacker controls.

Both are gone. Becoming an admin now happens through exactly two operations,
`activation.claim` and `account.claim_admin`, and each decides FOR ITSELF,
from Firestore, both whether a grant is warranted and who receives it. The
caller supplies a code or a token — never a role, and never a target.

Deployment: see README.md.
"""

from __future__ import annotations

import datetime
import hmac
import logging
import os
from typing import Any, Optional

import firebase_admin
from firebase_admin import auth as fb_auth, credentials, firestore
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("relay")

RELAY_SECRET = (os.getenv("RELAY_SECRET") or "").strip()

# Rotating the shared secret invalidates every installer already in the field,
# because the secret is baked into the build. Accepting the previous one for a
# while makes a rotation something you can actually do: deploy the relay with
# both, ship the update, then clear this and deploy again. Leave it empty
# unless a rotation is in progress.
RELAY_SECRET_PREVIOUS = (os.getenv("RELAY_SECRET_PREVIOUS") or "").strip()

SERVICE_ACCOUNT = os.getenv(
    "FIREBASE_SERVICE_ACCOUNT", "/etc/secrets/firebase_service_account.json"
)

# Firestore collections this product legitimately touches. Anything else is
# refused, so a compromised client cannot roam the database.
ALLOWED_COLLECTIONS = {"accounts", "activationCodes", "mobile_dashboard"}

# Claims a client may cause to be written. A custom claim rides in every ID
# token the account presents afterwards, so an unbounded dict here is both an
# escalation surface and a way to push a token past Firebase's 1000-byte claim
# limit and lock an account out of logging in entirely.
ALLOWED_CLAIM_KEYS = {"role", "created_by", "account"}
ALLOWED_ROLES = {"admin", "cashier", "accountant", "warehouse"}

# ─── Online backups (Backblaze B2, S3-compatible) ─────────────────────────────
#
# Every shop uploads its database here nightly, and every shop must be able to
# see exactly one shop's backups: its own. Five hundred businesses that compete
# with each other are in this bucket, and their cost prices and margins are in
# those files.
#
# ── How the isolation actually works ────────────────────────────────────────
# The storage prefix is derived from the `account` custom claim inside the
# caller's Firebase ID token — a token this relay verified itself, against
# Google's signing keys, on this request. It is never read from the request
# body, never passed as an argument, and there is no operation that accepts one.
# So a shop cannot ask for another shop's prefix: there is no field in which to
# put it. That is the whole security model, and it is why every handler below
# calls _account_of(caller) as its first act.
#
# The shared secret is NOT part of that boundary. It is baked into every
# installer by design (see electron/write-relay-config.js), so anybody holding
# a copy of the app holds it. It gates the door; the claim decides the room.
B2_KEY_ID   = (os.getenv("B2_KEY_ID") or "").strip()
B2_APP_KEY  = (os.getenv("B2_APP_KEY") or "").strip()
B2_BUCKET   = (os.getenv("B2_BUCKET") or "").strip()
B2_ENDPOINT = (os.getenv("B2_ENDPOINT") or "").strip()   # e.g. https://s3.us-west-004.backblazeb2.com
B2_REGION   = (os.getenv("B2_REGION") or "us-west-004").strip()

BACKUP_ROOT = "backups"

# How many backups to keep per shop. The oldest beyond this are deleted when a
# new upload URL is issued, so a shop that runs every night keeps a rolling
# window rather than growing forever.
BACKUP_KEEP = int(os.getenv("BACKUP_KEEP") or 10)

# A ceiling per shop, checked before a URL is handed out. A presigned PUT does
# not limit what the client sends, so without this one installation could fill
# the bucket — by accident with a huge database, or on purpose.
BACKUP_QUOTA_BYTES = int(os.getenv("BACKUP_QUOTA_BYTES") or 5 * 1024 ** 3)
BACKUP_MAX_FILE_BYTES = int(os.getenv("BACKUP_MAX_FILE_BYTES") or 2 * 1024 ** 3)

# Short on purpose. The URL is a bearer credential for one object: long enough
# to upload a slow shop's database over a slow line, not long enough to be
# worth passing around.
BACKUP_URL_TTL = int(os.getenv("BACKUP_URL_TTL") or 900)

# An account id becomes a path segment, so it is validated as one. Without this
# an id containing "../" would walk out of its own prefix and into another
# shop's — the one way the model above could be defeated from inside.
ACCOUNT_ID_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{1,128}$")

_s3_client = None


def _s3():
    """The B2 client, or a 503 that says which setting is missing."""
    global _s3_client
    missing = [n for n, v in (
        ("B2_KEY_ID", B2_KEY_ID), ("B2_APP_KEY", B2_APP_KEY),
        ("B2_BUCKET", B2_BUCKET), ("B2_ENDPOINT", B2_ENDPOINT),
    ) if not v]
    if missing:
        raise HTTPException(503, "Online backup is not configured on the server: "
                                 f"missing {', '.join(missing)}")
    if _s3_client is None:
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise HTTPException(503, "Online backup is not available: boto3 is not installed")
        try:
            _s3_client = boto3.client(
                "s3",
                endpoint_url=B2_ENDPOINT,
                aws_access_key_id=B2_KEY_ID,
                aws_secret_access_key=B2_APP_KEY,
                region_name=B2_REGION,
                config=Config(signature_version="s3v4"),
            )
        except Exception as e:
            # Almost always B2_ENDPOINT without the https:// on the front.
            raise HTTPException(503, f"Online backup is misconfigured: B2_ENDPOINT is not a "
                                     f"usable address ({B2_ENDPOINT!r}). It must look like "
                                     f"https://s3.us-west-004.backblazeb2.com. [{type(e).__name__}]")
    return _s3_client


# ── Saying what B2 actually refused ──────────────────────────────────────────
#
# Every operation used to come back as "The operation could not be completed".
# That summarising is right for the Firebase operations — they touch customer
# records, and the shared secret is in every installer, so error text is a leak
# waiting to happen.
#
# It is wrong here. Everything that goes wrong with B2 is wrong with OUR OWN
# server configuration: a bucket name, a key, an endpoint. None of it is a
# shop's data, all of it is set by us in the Render dashboard, and the person
# reading the message is the one who can fix it. Told nothing, they have a
# working feature and a dead screen and no thread to pull.
_B2_REASONS = {
    "NoSuchBucket":         "B2_BUCKET names a bucket that does not exist",
    "InvalidAccessKeyId":   "B2_KEY_ID is not a valid application key id",
    "InvalidAccessKeyID":   "B2_KEY_ID is not a valid application key id",
    "SignatureDoesNotMatch": "B2_APP_KEY does not match B2_KEY_ID, or B2_REGION does not match B2_ENDPOINT",
    "AuthorizationHeaderMalformed": "B2_REGION does not match B2_ENDPOINT",
    "AccessDenied":         "the application key is not allowed to use this bucket — it must be scoped to B2_BUCKET with read and write",
    "Unauthorized":         "B2 rejected the application key",
    "NoSuchKey":            "that backup is no longer in the bucket",
}


def _b2(what: str, fn, *args, **kwargs):
    """Run one B2 call and turn a failure into a sentence that names the fix."""
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except Exception as e:
        code = ""
        try:
            code = e.response["Error"]["Code"]          # botocore ClientError
        except Exception:
            code = type(e).__name__
        reason = _B2_REASONS.get(code)
        if reason is None and "EndpointConnection" in code:
            reason = f"the storage endpoint could not be reached — check B2_ENDPOINT ({B2_ENDPOINT!r})"
        logger.error("B2 %s failed [%s]: %s", what, code, e, exc_info=True)
        if reason:
            raise HTTPException(502, f"Online backup storage refused the request: {reason}.")
        # Unknown: give the code, which is safe (it is B2's, about our bucket)
        # and is the one thing that makes the Render log findable.
        raise HTTPException(502, f"Online backup storage could not {what} [{code}]. "
                                 f"The relay log has the detail.")


def _account_of(caller: dict) -> str:
    """
    Which shop is asking — taken from the verified token and nowhere else.

    An admin with no `account` claim is an installation that was activated
    before the claim existed, or one that has never been activated. It is not
    an error in their shop; it just cannot be placed in the bucket, and
    guessing would put it in somebody else's folder.
    """
    account = str(caller.get("account") or "").strip()
    if not account:
        raise HTTPException(
            403,
            "This installation is not linked to a licence account yet, so there "
            "is nowhere to put its backups. Re-enter the activation code.",
        )
    if not ACCOUNT_ID_RE.match(account):
        raise HTTPException(403, "This installation's account id is not usable as a storage path")
    return account


def _account_prefix(account: str) -> str:
    return f"{BACKUP_ROOT}/{account}/"


def _list_backups(account: str) -> list:
    """Newest first. The bucket is the index — there is no database here."""
    prefix = _account_prefix(account)
    items, token = [], None
    while True:
        kwargs = {"Bucket": B2_BUCKET, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        page = _b2("list the backups", _s3().list_objects_v2, **kwargs)
        for obj in page.get("Contents", []):
            items.append({
                "key": obj["Key"],
                "size": int(obj.get("Size") or 0),
                "modified": obj["LastModified"].isoformat() if obj.get("LastModified") else "",
            })
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
    items.sort(key=lambda i: i["key"], reverse=True)
    return items


def _own_key_or_403(account: str, key: Any) -> str:
    """
    The one place a key arrives from the client, and the one place it is
    checked. Anything not inside this shop's own prefix is refused before it
    reaches the bucket — including the paths that look like they are.
    """
    key = str(key or "")
    prefix = _account_prefix(account)
    if ".." in key or not key.startswith(prefix) or len(key) <= len(prefix):
        raise HTTPException(403, "That backup does not belong to this shop")
    return key

app = FastAPI(title="RetailOS Firebase Relay", version="2.1.0")


# ── Why FieldFilter and not .where(field, "==", value) ──────────────────────
# google-cloud-firestore deprecated the positional form and warns on every call:
#
#   UserWarning: Detected filter using positional arguments. Prefer using the
#   'filter' keyword argument instead.
#
# It printed once per query into the shop's log, which is how a real error gets
# lost. The keyword form is the supported one and behaves identically.
def _eq(field: str, value):
    """An equality filter, in the form the library actually wants."""
    from google.cloud.firestore_v1.base_query import FieldFilter
    return FieldFilter(field, "==", value)


def key_project() -> str:
    """Which Firebase project the mounted key belongs to. Empty if unreadable."""
    try:
        import json as _json
        with open(SERVICE_ACCOUNT, "r", encoding="utf-8") as fh:
            return str(_json.load(fh).get("project_id") or "")
    except Exception:
        return ""             # no key mounted yet, or not a service-account file


# The project this relay is MEANT to serve, set on the service.
#
# /health already reports which project the key belongs to, but only somebody
# who thinks to look will see it. This turns the mismatch into a line in the
# deploy log at the moment it becomes true, which is the moment it is cheap to
# fix — rather than a fortnight later when a customer cannot activate.
EXPECTED_PROJECT = (os.getenv("FIREBASE_PROJECT_ID") or "").strip()


def key_problem() -> str:
    """
    What is wrong with the mounted key, in words, or "" if it is usable.

    Reports on the SHAPE of the file — whether it parses, which required fields
    are absent — and never on their values. The one field anybody would be
    tempted to describe is private_key, and describing it is precisely what
    must not happen.

    This exists because "present" and "usable" are different states and only
    the first was ever checked. A file uploaded as a truncated paste satisfies
    key_present(), then makes credentials.Certificate() raise ValueError from
    _init() — which sits outside the try in run_op, so FastAPI answers a bare
    500 "Internal Server Error" and the customer is told nothing at all.
    """
    if not key_present():
        return f"no file is mounted at {SERVICE_ACCOUNT}"
    try:
        with open(SERVICE_ACCOUNT, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except Exception as e:
        return f"the file at {SERVICE_ACCOUNT} could not be read ({type(e).__name__})"
    if not raw.strip():
        return f"the file at {SERVICE_ACCOUNT} is empty"
    try:
        import json as _json
        data = _json.loads(raw)
    except Exception as e:
        return (f"the file at {SERVICE_ACCOUNT} is not valid JSON ({e}) — "
                "usually a truncated paste; it must start with { and end with }")
    if not isinstance(data, dict):
        return "the file is JSON, but not an object"
    missing = [k for k in ("type", "project_id", "private_key", "client_email")
               if not data.get(k)]
    if missing:
        return ("the file parses but is missing " + ", ".join(missing) +
                " — paste the whole file Firebase downloaded, not a fragment")
    if "BEGIN PRIVATE KEY" not in str(data.get("private_key") or ""):
        return ("private_key is not a PEM block — the paste was reformatted "
                "somewhere on the way in")
    return ""


def key_present() -> bool:
    try:
        return os.path.isfile(SERVICE_ACCOUNT)
    except Exception:
        return False


def _init() -> None:
    """Bring up the Firebase SDK, lazily, and refuse clearly without a key.

    A missing key is a DEPLOYMENT state, not a crash. It is what every new
    service looks like between "create from blueprint" and "upload the Secret
    File", and the two cannot be done in the other order — Render has nowhere to
    put a secret file until the service exists.

    So this must not be fatal. It used to be: initialize_app was called from the
    startup hook, the missing file raised FileNotFoundError, and the whole
    process exited — over and over. Which means /health was unreachable exactly
    when somebody needed it to ask what was missing, and the log said
    "FileNotFoundError" instead of "upload the key".
    """
    if not key_present():
        raise HTTPException(503, (
            f"This relay has no service-account key. Upload one as a Render "
            f"Secret File named firebase_service_account.json (it mounts at "
            f"{SERVICE_ACCOUNT}), then redeploy."
        ))
    # Present is not the same as usable, and the gap between them used to be a
    # bare 500. Say which it is.
    problem = key_problem()
    if problem:
        logger.error("service-account key unusable: %s", problem)
        raise HTTPException(503, (
            f"This relay's service-account key cannot be used: {problem}. "
            f"Replace the Render Secret File named firebase_service_account.json "
            f"and redeploy."
        ))
    if not firebase_admin._apps:
        try:
            firebase_admin.initialize_app(credentials.Certificate(SERVICE_ACCOUNT))
        except Exception as e:
            # Shape was fine, Firebase still refused it — a revoked key, or one
            # belonging to a deleted project. The type is enough to act on; the
            # full text goes to the log, not to the caller.
            logger.error("Firebase refused the service-account key: %s", e, exc_info=True)
            raise HTTPException(503, (
                f"Firebase refused this relay's service-account key "
                f"({type(e).__name__}). Generate a fresh key in Firebase "
                f"Console -> Project settings -> Service accounts, upload it as "
                f"the Secret File, and redeploy."
            ))


@app.on_event("startup")
def _startup() -> None:
    if not RELAY_SECRET:
        logger.warning("RELAY_SECRET is not set — every request will be refused.")
    if RELAY_SECRET_PREVIOUS:
        logger.warning(
            "RELAY_SECRET_PREVIOUS is set — a secret rotation is in progress. "
            "Clear it once the updated build has reached every customer."
        )
    # Deliberately NOT fatal, and deliberately not _init() — see _init.
    # The service has to come up so that /health can say what is wrong.
    project = key_project()
    logger.info("Relay starting. Firebase project: %s. Allowed collections: %s",
                project or "NONE", sorted(ALLOWED_COLLECTIONS))
    if not key_present():
        logger.error(
            "NO SERVICE-ACCOUNT KEY at %s. The relay is up and will refuse every "
            "privileged request with a 503 until one is there. Upload it as a "
            "Render Secret File named firebase_service_account.json, then "
            "redeploy. /health reports this too.", SERVICE_ACCOUNT)
    elif not project:
        logger.error(
            "The file at %s is not a service-account JSON — no project_id in it. "
            "Paste the whole file Firebase downloaded, not a fragment.",
            SERVICE_ACCOUNT)
    elif EXPECTED_PROJECT and project != EXPECTED_PROJECT:
        logger.error(
            "PROJECT MISMATCH: this relay holds a key for '%s', but "
            "FIREBASE_PROJECT_ID says it should be serving '%s'. Activation "
            "codes written by the control panel will not be found here, and "
            "every customer will be told a valid code is invalid. Replace the "
            "Secret File.", project, EXPECTED_PROJECT)


class OpIn(BaseModel):
    op: str
    args: dict = {}


# ─── Caller identity ──────────────────────────────────────────────────────────

def _caller(authorization: Optional[str]) -> Optional[dict]:
    """Verified claims of the calling staff member, or None if absent."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    try:
        return fb_auth.verify_id_token(token)
    except Exception:
        raise HTTPException(401, "Invalid or expired caller token")


def _caller_uid(claims: dict) -> str:
    return str(claims.get("uid") or claims.get("user_id") or claims.get("sub") or "")


def _require_caller(claims: Optional[dict]) -> dict:
    if not claims:
        raise HTTPException(401, "This action requires a signed-in user")
    return claims


def _require_admin(claims: Optional[dict]) -> dict:
    _require_caller(claims)
    if claims.get("role") != "admin":
        raise HTTPException(403, "This action requires the admin role")
    return claims


def _check_collection(name: str) -> str:
    if name not in ALLOWED_COLLECTIONS:
        raise HTTPException(403, f"Collection '{name}' is not accessible through the relay")
    return name


def _clean_claims(raw: Any) -> dict:
    """Validate a claims dict down to the keys and values this product uses."""
    if not isinstance(raw, dict):
        raise HTTPException(400, "claims must be an object")
    unknown = set(raw) - ALLOWED_CLAIM_KEYS
    if unknown:
        raise HTTPException(400, f"Refusing to set unknown claims: {sorted(unknown)}")
    role = raw.get("role")
    if role not in ALLOWED_ROLES:
        raise HTTPException(400, f"Refusing to set unknown role '{role}'")
    cleaned = {"role": role}
    for key in ("created_by", "account"):
        value = raw.get(key)
        if value:
            if not isinstance(value, str) or len(value) > 128:
                raise HTTPException(400, f"Invalid value for claim '{key}'")
            cleaned[key] = value
    return cleaned


def _target_claims(uid: str) -> dict:
    """Existing claims of the account being acted on ({} if it has none)."""
    try:
        return fb_auth.get_user(uid).custom_claims or {}
    except Exception:
        raise HTTPException(404, "No such account")


def _may_manage(caller: dict, uid: str, target: dict) -> bool:
    """
    Whether an admin caller may act on this account.

    Every shop in the customer base shares one Firebase project, so "is an
    admin" is not by itself a reason to let somebody edit an account — it has
    to be an admin of the SAME shop. Ownership is read from claims the
    relay itself wrote: `created_by` (who created this staff member) and
    `account` (which panel account they belong to).

    Deliberately permissive in three places, each for a reason:
      • acting on oneself, which an admin re-stamping their own claims does;
      • an account with no role yet — the gap between user.create and the
        claim that gives it one;
      • an account with neither `created_by` nor `account`, which is what
        every staff member looked like before ownership tracking existed and
        is exactly what the claim-unowned migration is for.
    """
    if uid == _caller_uid(caller):
        return True
    if not target.get("role"):
        return True
    if not target.get("created_by") and not target.get("account"):
        return True
    if target.get("created_by") == _caller_uid(caller):
        return True
    caller_account = caller.get("account")
    return bool(caller_account and target.get("account") == caller_account)


def _require_may_manage(caller: dict, uid: str) -> dict:
    target = _target_claims(uid)
    if not _may_manage(caller, uid, target):
        raise HTTPException(403, "That account belongs to another shop")
    return target


def _user_dict(u) -> dict:
    return {
        "uid": u.uid,
        "email": u.email or "",
        "display_name": u.display_name or "",
        "disabled": bool(u.disabled),
        "custom_claims": u.custom_claims or {},
        "phone_number": getattr(u, "phone_number", "") or "",
    }


# ─── Operations ───────────────────────────────────────────────────────────────
# Each handler takes (args, caller_claims) and returns a JSON-serialisable
# result. Handlers decide their own authorisation requirements.

def _op_user_list(args: dict, caller: Optional[dict]):
    _require_admin(caller)
    return [_user_dict(u) for u in fb_auth.list_users().users]


def _op_user_get(args: dict, caller: Optional[dict]):
    _require_admin(caller)
    return _user_dict(fb_auth.get_user(args["uid"]))


def _op_user_get_by_email(args: dict, caller: Optional[dict]):
    # Was reachable on the shared secret alone, which made the relay an email
    # directory for the whole customer base: ask about an address, learn
    # whether it exists and what role it holds. The activation flow was the
    # reason it had to be open; activation.claim below no longer needs it.
    _require_admin(caller)
    return _user_dict(fb_auth.get_user_by_email(args["email"]))


def _op_user_create(args: dict, caller: Optional[dict]):
    _require_admin(caller)
    kwargs = {
        "email": args["email"],
        "password": args["password"],
        "display_name": args.get("display_name", ""),
    }
    if args.get("phone_number"):
        kwargs["phone_number"] = args["phone_number"]
    return _user_dict(fb_auth.create_user(**kwargs))


def _op_user_update(args: dict, caller: Optional[dict]):
    _require_admin(caller)
    _require_may_manage(caller, args["uid"])
    fields = args.get("fields") or {}
    allowed = {"display_name", "password", "disabled", "email", "phone_number"}
    unknown = set(fields) - allowed
    if unknown:
        raise HTTPException(400, f"Cannot update: {sorted(unknown)}")
    return _user_dict(fb_auth.update_user(args["uid"], **fields))


def _op_user_delete(args: dict, caller: Optional[dict]):
    _require_admin(caller)
    _require_may_manage(caller, args["uid"])
    fb_auth.delete_user(args["uid"])
    return None


def _op_user_set_claims(args: dict, caller: Optional[dict]):
    """
    Set an account's role. ADMIN CALLER ONLY, and only within their own
    shop.

    There is no bootstrap path through here any more, and that is the point.
    Becoming the first admin of an installation is not a claim change with a
    lenient rule in front of it; it is its own operation with its own proof —
    see activation.claim and account.claim_admin below.
    """
    _require_admin(caller)
    uid = args["uid"]
    claims = _clean_claims(args.get("claims") or {})
    _require_may_manage(caller, uid)
    fb_auth.set_custom_user_claims(uid, claims)
    return None


# ─── Becoming an admin ────────────────────────────────────────────────────────
# The only two ways. Both establish entitlement from a document the customer
# cannot write, and both choose the recipient themselves.

def _account_blocked(account_id: str) -> bool:
    if not account_id:
        return False
    try:
        snap = firestore.client().collection("accounts").document(account_id).get()
    except Exception:
        return False        # an unreadable account doc must not break activation
    return bool(snap.exists and (snap.to_dict() or {}).get("status") == "blocked")


def _op_activation_claim(args: dict, caller: Optional[dict]):
    """
    Redeem an activation code: verify it, burn it, and grant admin to the
    account the code names — all here, in one operation.

    The desktop app used to do this in three separate calls (read the code,
    write the claim, mark the code used), which meant the middle one had to be
    permitted to a caller who was not yet an admin. Possession of an unused
    code is the credential; splitting the check from the grant left the relay
    trusting a client's word that it had seen one.

    The code document decides who becomes admin. A caller cannot pass a uid.

    Returns the licence details the desktop app stores locally.
    """
    code = str(args.get("code") or "").strip().upper()
    if not code or not code.isalnum() or len(code) != 16:
        raise HTTPException(400, "Invalid activation code")

    client = firestore.client()
    code_ref = client.collection("activationCodes").document(code)

    # A transaction, because two tills redeeming the same code at the same
    # moment must not both succeed. Read-check-write inside one makes the
    # single-use rule real rather than merely likely.
    @firestore.transactional
    def _burn(transaction):
        snap = code_ref.get(transaction=transaction)
        if not snap.exists:
            raise HTTPException(400, "Invalid activation code")
        data = snap.to_dict() or {}
        if data.get("revoked"):
            raise HTTPException(400, "This activation code has been revoked")
        if data.get("used"):
            raise HTTPException(400, "This activation code has already been used")

        exp = str(data.get("exp") or "")
        if exp:
            try:
                if datetime.date.fromisoformat(exp) < datetime.date.today():
                    raise HTTPException(400, "This activation code has expired")
            except ValueError:
                pass        # an unparseable expiry is treated as no expiry

        if _account_blocked(str(data.get("accountId") or "")):
            raise HTTPException(403, "This account has been blocked. Contact the developer.")

        transaction.update(code_ref, {
            "used": True,
            "usedBy": data.get("adminEmail") or "",
            "usedAt": firestore.SERVER_TIMESTAMP,
        })
        return data

    data = _burn(client.transaction())

    account_id = str(data.get("accountId") or "")
    admin_email = str(data.get("adminEmail") or "").strip().lower()

    # Grant admin to the account the CODE names — not to whoever called.
    admin_granted = False
    if admin_email:
        try:
            target = fb_auth.get_user_by_email(admin_email)
            claims = dict(target.custom_claims or {})
            claims.update({"role": "admin", "account": account_id})
            fb_auth.set_custom_user_claims(target.uid, _clean_claims(claims))
            admin_granted = True
        except HTTPException:
            raise
        except Exception as e:
            # The licence is still valid; the login may simply not exist yet.
            logger.warning("activation %s: could not grant admin to %s: %s",
                           code, admin_email, e)

    return {
        "account_id": account_id,
        "account_name": str(data.get("accountName") or data.get("name") or ""),
        "exp": str(data.get("exp") or ""),
        "limits": data.get("limits") or {},
        "admin_email": admin_email,
        "admin_granted": admin_granted,
    }


def _op_account_claim_admin(args: dict, caller: Optional[dict]):
    """
    Grant admin to the CALLER, if the control panel created them as the admin
    of a customer account.

    Identity comes from the caller's verified ID token; entitlement comes from
    an `accounts` document only the panel owner can write. The caller supplies
    neither a uid nor a role, so there is nothing here to aim at somebody else.
    """
    caller = _require_caller(caller)
    uid = _caller_uid(caller)
    email = str(caller.get("email") or "").strip().lower()

    collection = firestore.client().collection("accounts")
    docs = list(collection.where(filter=_eq("adminUid", uid)).limit(1).get())
    if not docs and email and caller.get("email_verified"):
        # Matching on the email address only when Firebase has verified it.
        # Otherwise anyone could sign up claiming a customer's address and
        # inherit their shop.
        docs = list(collection.where(filter=_eq("adminEmail", email)).limit(1).get())

    if not docs:
        return None

    doc = docs[0]
    data = doc.to_dict() or {}
    if data.get("status") == "blocked":
        raise HTTPException(403, "This account has been blocked. Contact the developer.")

    claims = dict(fb_auth.get_user(uid).custom_claims or {})
    claims.update({"role": "admin", "account": doc.id})
    fb_auth.set_custom_user_claims(uid, _clean_claims(claims))

    # Record the uid so the next login matches on it directly.
    if not data.get("adminUid"):
        try:
            collection.document(doc.id).update({"adminUid": uid})
        except Exception:
            pass

    return {"account": doc.id, "account_name": str(data.get("accountName") or data.get("name") or "")}


# ─── Firestore ────────────────────────────────────────────────────────────────

def _op_fs_get(args: dict, caller: Optional[dict]):
    # Reading licence documents used to be open on the shared secret, because
    # that was how activation worked: fetch the code, decide locally. It also
    # let anyone holding the secret probe for valid codes at their leisure.
    # activation.claim replaced that flow, and nothing in the desktop app calls
    # this any more — so it takes an admin, like every other read here.
    _require_admin(caller)
    coll = _check_collection(args["collection"])
    snap = firestore.client().collection(coll).document(args["doc"]).get()
    return snap.to_dict() if snap.exists else None


def _op_fs_query(args: dict, caller: Optional[dict]):
    _require_admin(caller)
    coll = _check_collection(args["collection"])
    docs = (
        firestore.client()
        .collection(coll)
        .where(filter=_eq(args["field"], args["value"]))
        .limit(int(args.get("limit") or 1))
        .get()
    )
    return [{"id": d.id, "data": d.to_dict() or {}} for d in docs]


def _op_fs_update(args: dict, caller: Optional[dict]):
    coll = _check_collection(args["collection"])
    if coll == "activationCodes":
        # Burning a code is what activation.claim does — transactionally, and
        # together with the grant it pays for. There is no longer any reason
        # for a client to write one of these documents directly.
        raise HTTPException(403, "Activation codes are written by activation.claim only")
    _require_admin(caller)

    data = dict(args.get("data") or {})
    for field in args.get("server_timestamp_fields") or []:
        data[field] = firestore.SERVER_TIMESTAMP
    firestore.client().collection(coll).document(args["doc"]).update(data)
    return None


def _op_fs_set(args: dict, caller: Optional[dict]):
    """
    Write an admin's mobile-dashboard snapshot.

    ── The one operation still reachable on the shared secret alone ──────────
    Deliberately, and with its limits written down rather than assumed.

    This is pushed by the desktop's background scheduler, not by a request, so
    there is no signed-in user to authenticate as: the sync runs on a timer
    whether anyone is at the till or not, and an ID token expires in an hour.
    Requiring a caller here would simply stop the phone dashboard updating.

    What that costs is bounded and unchanged from before this rework: somebody
    holding the secret can overwrite a `mobile_dashboard/{uid}` document, which
    makes an owner's phone show wrong figures until the next sync. It reads
    nothing, reaches no other collection, and grants no role.

    When a caller IS present the rule tightens to "your own document only", so
    the manual Sync-now button is held to the stricter standard.

    To close it properly, mint a per-install token during activation.claim and
    require it here — see README.md.
    """
    coll = _check_collection(args["collection"])
    if coll != "mobile_dashboard":
        # Only the dashboard snapshot is written wholesale; account and code
        # documents are created by the control panel, never by a customer.
        raise HTTPException(403, f"Cannot create documents in '{coll}'")

    doc = str(args["doc"] or "")
    # Firebase uids are short opaque strings. Checking the shape stops a
    # malformed or path-like id from reaching Firestore at all.
    if not doc or len(doc) > 128 or "/" in doc:
        raise HTTPException(400, "Invalid dashboard document id")

    if caller and doc != _caller_uid(caller):
        raise HTTPException(403, "You can only write your own dashboard")

    firestore.client().collection(coll).document(doc).set(args.get("data") or {})
    return None


# ─── Online backup operations ─────────────────────────────────────────────────
# Read the block at the top of the file before changing any of these. Every one
# of them derives its prefix from the token; none of them accepts an account.

def _op_backup_upload_url(args: dict, caller: Optional[dict]):
    """
    Hand back a URL this shop may upload one backup to.

    The bytes never pass through this service. It signs a permission slip for a
    single object key that it chose itself, and the shop uploads straight to B2
    — which is what makes five hundred shops on a free-tier instance possible
    at all.
    """
    _require_admin(caller)
    account = _account_of(caller)

    try:
        size = int(args.get("size") or 0)
    except (TypeError, ValueError):
        raise HTTPException(400, "size must be a number")
    if size <= 0:
        raise HTTPException(400, "size must be the number of bytes about to be uploaded")
    if size > BACKUP_MAX_FILE_BYTES:
        raise HTTPException(413, "That backup is larger than this service accepts")

    # Prune BEFORE the quota check, so a shop at its limit with old backups to
    # drop is not refused for space it is about to free.
    existing = _list_backups(account)
    doomed = existing[max(BACKUP_KEEP - 1, 0):]
    for item in doomed:
        try:
            _s3().delete_object(Bucket=B2_BUCKET, Key=item["key"])
        except Exception as e:
            # A backup that will not delete is not a reason to refuse to make
            # the next one. It is pruned again tomorrow.
            logger.warning("could not prune %s: %s", item["key"], e)
    kept = existing[:max(BACKUP_KEEP - 1, 0)]

    used = sum(i["size"] for i in kept)
    if used + size > BACKUP_QUOTA_BYTES:
        raise HTTPException(
            413,
            "This shop has reached its online backup limit. Delete an older "
            "backup, or ask for more space.",
        )

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    key = f"{_account_prefix(account)}retailos-{stamp}.db.gz"

    url = _b2("prepare the upload", _s3().generate_presigned_url,
        "put_object",
        Params={"Bucket": B2_BUCKET, "Key": key, "ContentType": "application/gzip"},
        ExpiresIn=BACKUP_URL_TTL,
    )
    return {
        "url": url,
        "key": key,
        "method": "PUT",
        "headers": {"Content-Type": "application/gzip"},
        "expires_in": BACKUP_URL_TTL,
        "pruned": [i["key"] for i in doomed],
    }


def _op_backup_check(args: dict, caller: Optional[dict]):
    """
    Does online backup actually work from here, and if not, which setting is wrong?

    Exists because the first thing that happened on the first real deployment
    was a shop pressing the button and being told "the operation could not be
    completed". The cause was in a log on a server the shopkeeper has never
    heard of. This runs the same two calls a backup runs — reach the bucket,
    sign a URL — and reports what it finds.

    Safe to expose: it reports on OUR configuration, which the caller's own
    shop depends on, and it names no other shop and no data. It reports the
    endpoint and bucket because those are the values being diagnosed, and
    neither is a credential.
    """
    _require_admin(caller)
    account = _account_of(caller)

    out = {
        "account": account,
        "prefix": _account_prefix(account),
        "endpoint": B2_ENDPOINT or None,
        "region": B2_REGION or None,
        "bucket": B2_BUCKET or None,
        "key_id_set": bool(B2_KEY_ID),
        "app_key_set": bool(B2_APP_KEY),
        "keep": BACKUP_KEEP,
    }
    try:
        items = _list_backups(account)
        out["can_list"] = True
        out["backups"] = len(items)
    except HTTPException as e:
        out["can_list"] = False
        out["problem"] = e.detail
        return out

    try:
        _b2("prepare the upload", _s3().generate_presigned_url, "put_object",
            Params={"Bucket": B2_BUCKET, "Key": f"{_account_prefix(account)}.probe",
                    "ContentType": "application/gzip"},
            ExpiresIn=60)
        out["can_sign"] = True
    except HTTPException as e:
        out["can_sign"] = False
        out["problem"] = e.detail
        return out

    out["ok"] = True
    return out


def _op_backup_list(args: dict, caller: Optional[dict]):
    """Every backup this shop has, newest first. Never anybody else's."""
    _require_admin(caller)
    account = _account_of(caller)
    items = _list_backups(account)
    return {
        "backups": items,
        "keep": BACKUP_KEEP,
        "used": sum(i["size"] for i in items),
        "quota": BACKUP_QUOTA_BYTES,
    }


def _op_backup_download_url(args: dict, caller: Optional[dict]):
    """A URL to fetch one of this shop's own backups, for a restore."""
    _require_admin(caller)
    account = _account_of(caller)
    key = _own_key_or_403(account, args.get("key"))

    url = _b2("prepare the download", _s3().generate_presigned_url,
        "get_object",
        Params={"Bucket": B2_BUCKET, "Key": key},
        ExpiresIn=BACKUP_URL_TTL,
    )
    return {"url": url, "key": key, "expires_in": BACKUP_URL_TTL}


def _op_backup_delete(args: dict, caller: Optional[dict]):
    """Remove one of this shop's own backups."""
    _require_admin(caller)
    account = _account_of(caller)
    key = _own_key_or_403(account, args.get("key"))
    _b2("delete the backup", _s3().delete_object, Bucket=B2_BUCKET, Key=key)
    return {"deleted": key}


HANDLERS = {
    "user.list": _op_user_list,
    "user.get": _op_user_get,
    "user.get_by_email": _op_user_get_by_email,
    "user.create": _op_user_create,
    "user.update": _op_user_update,
    "user.delete": _op_user_delete,
    "user.set_claims": _op_user_set_claims,
    "activation.claim": _op_activation_claim,
    "account.claim_admin": _op_account_claim_admin,
    "fs.get": _op_fs_get,
    "fs.query": _op_fs_query,
    "fs.update": _op_fs_update,
    "fs.set": _op_fs_set,
    "backup.upload_url": _op_backup_upload_url,
    "backup.list": _op_backup_list,
    "backup.check": _op_backup_check,
    "backup.download_url": _op_backup_download_url,
    "backup.delete": _op_backup_delete,
}


# ─── Entry point ──────────────────────────────────────────────────────────────

def _secret_ok(presented: Optional[str]) -> bool:
    """Constant-time check against the current secret, and the previous one
    while a rotation is in flight."""
    if not RELAY_SECRET:
        return False
    presented = presented or ""
    if hmac.compare_digest(presented, RELAY_SECRET):
        return True
    if RELAY_SECRET_PREVIOUS and hmac.compare_digest(presented, RELAY_SECRET_PREVIOUS):
        logger.info("request authenticated with the PREVIOUS relay secret")
        return True
    return False


@app.post("/op")
def run_op(
    payload: OpIn,
    x_relay_secret: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    if not _secret_ok(x_relay_secret):
        raise HTTPException(401, "Unauthorised")

    handler = HANDLERS.get(payload.op)
    if handler is None:
        raise HTTPException(400, f"Unknown operation '{payload.op}'")

    _init()
    caller = _caller(authorization)

    try:
        result = handler(payload.args or {}, caller)
    except HTTPException:
        raise
    except KeyError as e:
        raise HTTPException(400, f"Missing argument: {e}")
    except Exception as e:
        # Logged in full here, summarised to the caller. The old code returned
        # str(e) verbatim, which handed Firebase's internal error text — and
        # on occasion document contents — to anyone holding the shared secret.
        logger.warning("op %s failed: %s", payload.op, e, exc_info=True)
        raise HTTPException(400, f"The operation '{payload.op}' could not be completed")

    return {"result": result}


@app.get("/health")
def health():
    """
    Unauthenticated on purpose — it is what the build script and the desktop app
    poll before trusting this service.

    `project` is here because its absence cost a day. The relay holds the key,
    so the relay decides which Firebase project every privileged operation
    reads. When the desktop app moved to a new project and this service was
    still holding the old key, the control panel wrote an activation code into
    one project and the backend asked this service to redeem it out of another.
    The code was not found, and the customer was told "Invalid activation code"
    about a code that was perfectly valid.

    Nothing was broken. The two ends were pointed at different places, and no
    health check said so. Now one does.
    """
    project = key_project()
    have_key = key_present()
    problem = key_problem()
    # Set FIREBASE_PROJECT_ID on the service and this becomes a verdict rather
    # than a fact somebody has to know how to read.
    project_ok = (not EXPECTED_PROJECT) or project == EXPECTED_PROJECT
    return {
        # "degraded" rather than a 500: the service IS answering, and what it
        # cannot do is something to fix in a dashboard. A relay serving the wrong
        # project counts as degraded — it is the failure that otherwise looks
        # like perfect health right up until a customer cannot activate.
        "status": "healthy" if (not problem and project_ok) else "degraded",
        "configured": bool(RELAY_SECRET),
        "key_present": have_key,
        # "" when the key is usable. Named as a problem rather than a boolean
        # so the answer is the sentence somebody needs, not a flag they then
        # have to look up.
        "key_problem": problem,
        "project": project,
        "project_expected": EXPECTED_PROJECT,
        "project_ok": project_ok,
        "version": app.version,
    }
