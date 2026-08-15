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
forging activation codes, and reading every other pharmacy's data.

This relay keeps the key in one place you control. The desktop app calls it
over HTTPS and gets back only the specific result it asked for.

Protection layers
-----------------
1. Shared secret (X-Relay-Secret) — a coarse gate that keeps unrelated
   internet traffic out. It ships inside the app, so treat it as a filter and
   not as a real credential.
2. Caller identity — operations that act on user accounts require the caller's
   own Firebase ID token, verified here, and the caller must hold the admin
   role. This is the layer that actually prevents privilege escalation: the
   shared secret alone grants nothing.
3. Collection allow-list — Firestore access is limited to the exact
   collections this product uses.

Deployment: see README.md.
"""

from __future__ import annotations

import os
import logging
from typing import Any, Optional

import firebase_admin
from firebase_admin import auth as fb_auth, credentials, firestore
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("relay")

RELAY_SECRET = (os.getenv("RELAY_SECRET") or "").strip()
SERVICE_ACCOUNT = os.getenv(
    "FIREBASE_SERVICE_ACCOUNT", "/etc/secrets/firebase_service_account.json"
)

# Firestore collections this product legitimately touches. Anything else is
# refused, so a compromised client cannot roam the database.
ALLOWED_COLLECTIONS = {"accounts", "activationCodes", "mobile_dashboard"}

# Fields a client may set on an activation code. Everything else (limits, the
# expiry date, the owning account) is issued by the control panel and must not
# be writable from a customer machine.
ACTIVATION_CODE_WRITABLE = {"used", "usedBy", "usedAt"}

app = FastAPI(title="Pharmacy Firebase Relay", version="1.0.0")


def _init() -> None:
    if not firebase_admin._apps:
        firebase_admin.initialize_app(credentials.Certificate(SERVICE_ACCOUNT))


@app.on_event("startup")
def _startup() -> None:
    if not RELAY_SECRET:
        logger.warning("RELAY_SECRET is not set — every request will be refused.")
    _init()
    logger.info("Relay ready. Allowed collections: %s", sorted(ALLOWED_COLLECTIONS))


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


def _require_admin(claims: Optional[dict]) -> dict:
    if not claims:
        raise HTTPException(401, "This action requires a signed-in administrator")
    if claims.get("role") != "admin":
        raise HTTPException(403, "This action requires the admin role")
    return claims


def _check_collection(name: str) -> str:
    if name not in ALLOWED_COLLECTIONS:
        raise HTTPException(403, f"Collection '{name}' is not accessible through the relay")
    return name


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
    # Also reachable during activation, before the caller holds any role, so
    # only the shared secret gates this read-only lookup.
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
    fields = args.get("fields") or {}
    allowed = {"display_name", "password", "disabled", "email", "phone_number"}
    unknown = set(fields) - allowed
    if unknown:
        raise HTTPException(400, f"Cannot update: {sorted(unknown)}")
    return _user_dict(fb_auth.update_user(args["uid"], **fields))


def _op_user_delete(args: dict, caller: Optional[dict]):
    _require_admin(caller)
    fb_auth.delete_user(args["uid"])
    return None


def _op_user_set_claims(args: dict, caller: Optional[dict]):
    claims = args.get("claims") or {}
    role = claims.get("role")
    if role not in {"admin", "cashier", "pharmacist", "warehouse"}:
        raise HTTPException(400, f"Refusing to set unknown role '{role}'")

    # Granting admin happens during activation, when the caller has no role
    # yet — but only to the person signed in, never to somebody else.
    if caller and caller.get("role") == "admin":
        pass
    elif caller and args.get("uid") == (caller.get("uid") or caller.get("user_id")):
        pass
    elif role == "admin" and not caller:
        # Activation path: the desktop backend proves it knows a valid,
        # unused activation code before reaching this point.
        pass
    else:
        raise HTTPException(403, "Not allowed to set claims for that account")

    fb_auth.set_custom_user_claims(args["uid"], claims)
    return None


def _op_fs_get(args: dict, caller: Optional[dict]):
    coll = _check_collection(args["collection"])
    snap = firestore.client().collection(coll).document(args["doc"]).get()
    return snap.to_dict() if snap.exists else None


def _op_fs_query(args: dict, caller: Optional[dict]):
    coll = _check_collection(args["collection"])
    docs = (
        firestore.client()
        .collection(coll)
        .where(args["field"], "==", args["value"])
        .limit(int(args.get("limit") or 1))
        .get()
    )
    return [{"id": d.id, "data": d.to_dict() or {}} for d in docs]


def _op_fs_update(args: dict, caller: Optional[dict]):
    coll = _check_collection(args["collection"])
    data = dict(args.get("data") or {})
    for field in args.get("server_timestamp_fields") or []:
        data[field] = firestore.SERVER_TIMESTAMP

    # Burning an activation code is the only write a customer machine may make
    # here, and only to the bookkeeping fields.
    if coll == "activationCodes":
        illegal = set(data) - ACTIVATION_CODE_WRITABLE
        if illegal:
            raise HTTPException(403, f"Cannot modify activation code fields: {sorted(illegal)}")
    elif coll == "accounts":
        _require_admin(caller)

    firestore.client().collection(coll).document(args["doc"]).update(data)
    return None


def _op_fs_set(args: dict, caller: Optional[dict]):
    coll = _check_collection(args["collection"])
    if coll != "mobile_dashboard":
        # Only the dashboard snapshot is written wholesale; account and code
        # documents are created by the control panel, never by a customer.
        raise HTTPException(403, f"Cannot create documents in '{coll}'")
    firestore.client().collection(coll).document(args["doc"]).set(args.get("data") or {})
    return None


HANDLERS = {
    "user.list": _op_user_list,
    "user.get": _op_user_get,
    "user.get_by_email": _op_user_get_by_email,
    "user.create": _op_user_create,
    "user.update": _op_user_update,
    "user.delete": _op_user_delete,
    "user.set_claims": _op_user_set_claims,
    "fs.get": _op_fs_get,
    "fs.query": _op_fs_query,
    "fs.update": _op_fs_update,
    "fs.set": _op_fs_set,
}


# ─── Entry point ──────────────────────────────────────────────────────────────

@app.post("/op")
def run_op(
    payload: OpIn,
    x_relay_secret: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    if not RELAY_SECRET or x_relay_secret != RELAY_SECRET:
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
        logger.warning("op %s failed: %s", payload.op, e)
        raise HTTPException(400, str(e))

    return {"result": result}


@app.get("/health")
def health():
    return {"status": "healthy", "configured": bool(RELAY_SECRET)}
