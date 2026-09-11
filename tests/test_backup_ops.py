"""
Isolation tests for the online-backup operations.

Five hundred shops that compete with each other share one bucket. The only
thing standing between shop A and shop B's cost prices is that the storage
prefix comes from a Firebase-signed claim rather than from the request. These
tests exist to make sure that stays true — not that the feature works, but that
it cannot be talked out of its boundary.

Run:  cd relay && python -m pytest tests -q
"""

import datetime
import importlib
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ── Stubs ─────────────────────────────────────────────────────────────────────
# The relay imports firebase_admin and (lazily) boto3. Neither is needed to test
# the decision-making, and requiring them would make these tests something
# nobody runs.

def _stub_firebase():
    if "firebase_admin" in sys.modules:
        return
    fa = types.ModuleType("firebase_admin")
    fa.initialize_app = lambda *a, **k: None
    fa._apps = {}
    auth_mod = types.ModuleType("firebase_admin.auth")
    auth_mod.verify_id_token = lambda t: {}
    auth_mod.get_user = lambda uid: types.SimpleNamespace(custom_claims={})
    creds = types.ModuleType("firebase_admin.credentials")
    creds.Certificate = lambda p: None
    fs_mod = types.ModuleType("firebase_admin.firestore")
    fs_mod.client = lambda: None
    fa.auth, fa.credentials, fa.firestore = auth_mod, creds, fs_mod
    sys.modules["firebase_admin"] = fa
    sys.modules["firebase_admin.auth"] = auth_mod
    sys.modules["firebase_admin.credentials"] = creds
    sys.modules["firebase_admin.firestore"] = fs_mod


_stub_firebase()
main = importlib.import_module("main")
from fastapi import HTTPException


class FakeS3:
    """Records what it was asked for, so a test can assert on the prefix."""

    def __init__(self, objects=None):
        self.objects = dict(objects or {})      # key → size
        self.list_prefixes = []
        self.signed = []
        self.deleted = []

    def list_objects_v2(self, **kw):
        self.list_prefixes.append(kw["Prefix"])
        contents = [
            {"Key": k, "Size": v,
             "LastModified": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)}
            for k, v in sorted(self.objects.items())
            if k.startswith(kw["Prefix"])
        ]
        return {"Contents": contents, "IsTruncated": False}

    def generate_presigned_url(self, op, Params=None, ExpiresIn=None):
        self.signed.append((op, Params["Key"]))
        return f"https://b2.example/{Params['Key']}?sig=x"

    def delete_object(self, Bucket=None, Key=None):
        self.deleted.append(Key)
        self.objects.pop(Key, None)


@pytest.fixture
def s3(monkeypatch):
    fake = FakeS3()
    monkeypatch.setattr(main, "B2_KEY_ID", "id")
    monkeypatch.setattr(main, "B2_APP_KEY", "key")
    monkeypatch.setattr(main, "B2_BUCKET", "retailos-backups")
    monkeypatch.setattr(main, "B2_ENDPOINT", "https://s3.us-west-004.backblazeb2.com")
    monkeypatch.setattr(main, "_s3_client", fake)
    return fake


ALICE = {"uid": "u-alice", "role": "admin", "account": "acct-alice"}
BOB   = {"uid": "u-bob",   "role": "admin", "account": "acct-bob"}
CASHIER = {"uid": "u-c", "role": "cashier", "account": "acct-alice"}


# ── The account comes from the token, and only from the token ────────────────

def test_account_is_read_from_the_claim():
    assert main._account_of(ALICE) == "acct-alice"


def test_admin_without_an_account_claim_is_refused():
    with pytest.raises(HTTPException) as e:
        main._account_of({"uid": "u", "role": "admin"})
    assert e.value.status_code == 403
    # The message has to tell a shopkeeper what to do, not name a claim.
    assert "activation" in e.value.detail.lower()


@pytest.mark.parametrize("bad", ["../other", "a/b", "acct alice", "", "x" * 129, "..", "./x"])
def test_an_account_id_that_is_not_a_safe_path_segment_is_refused(bad):
    with pytest.raises(HTTPException):
        main._account_of({"uid": "u", "role": "admin", "account": bad})


def test_passing_an_account_in_the_arguments_changes_nothing(s3):
    """The attack this whole design exists to prevent."""
    main._op_backup_list({"account": "acct-bob", "prefix": "backups/acct-bob/"}, ALICE)
    assert s3.list_prefixes == ["backups/acct-alice/"]


# ── One shop cannot reach another's objects ──────────────────────────────────

def test_download_url_refuses_another_shops_key(s3):
    with pytest.raises(HTTPException) as e:
        main._op_backup_download_url({"key": "backups/acct-bob/retailos-2026.db.gz"}, ALICE)
    assert e.value.status_code == 403
    assert s3.signed == []


def test_download_url_refuses_a_traversal_dressed_as_its_own(s3):
    with pytest.raises(HTTPException):
        main._op_backup_download_url(
            {"key": "backups/acct-alice/../acct-bob/retailos.db.gz"}, ALICE)
    assert s3.signed == []


def test_download_url_refuses_a_prefix_that_merely_starts_the_same(s3):
    """acct-alice must not reach acct-alice-2's folder."""
    with pytest.raises(HTTPException):
        main._op_backup_download_url({"key": "backups/acct-alice-2/x.db.gz"}, ALICE)


def test_download_url_refuses_the_bare_prefix(s3):
    with pytest.raises(HTTPException):
        main._op_backup_download_url({"key": "backups/acct-alice/"}, ALICE)


def test_download_url_signs_its_own_key(s3):
    out = main._op_backup_download_url({"key": "backups/acct-alice/retailos-1.db.gz"}, ALICE)
    assert s3.signed == [("get_object", "backups/acct-alice/retailos-1.db.gz")]
    assert out["url"].startswith("https://b2.example/")


def test_delete_refuses_another_shops_key(s3):
    with pytest.raises(HTTPException):
        main._op_backup_delete({"key": "backups/acct-bob/retailos-1.db.gz"}, ALICE)
    assert s3.deleted == []


# ── Role ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("op", [
    main._op_backup_upload_url, main._op_backup_list,
    main._op_backup_download_url, main._op_backup_delete,
])
def test_a_cashier_cannot_touch_backups(s3, op):
    with pytest.raises(HTTPException) as e:
        op({"key": "backups/acct-alice/x.db.gz", "size": 10}, CASHIER)
    assert e.value.status_code == 403


@pytest.mark.parametrize("op", [
    main._op_backup_upload_url, main._op_backup_list,
    main._op_backup_download_url, main._op_backup_delete,
])
def test_an_anonymous_caller_cannot_touch_backups(s3, op):
    with pytest.raises(HTTPException) as e:
        op({"key": "backups/acct-alice/x.db.gz", "size": 10}, None)
    assert e.value.status_code == 401


# ── Listing ──────────────────────────────────────────────────────────────────

def test_list_returns_only_this_shops_objects(s3):
    s3.objects = {
        "backups/acct-alice/retailos-1.db.gz": 100,
        "backups/acct-alice/retailos-2.db.gz": 200,
        "backups/acct-bob/retailos-1.db.gz": 999,
    }
    out = main._op_backup_list({}, ALICE)
    keys = [b["key"] for b in out["backups"]]
    assert keys == ["backups/acct-alice/retailos-2.db.gz",
                    "backups/acct-alice/retailos-1.db.gz"]
    assert out["used"] == 300


def test_two_shops_see_different_things(s3):
    s3.objects = {
        "backups/acct-alice/a.db.gz": 1,
        "backups/acct-bob/b.db.gz": 2,
    }
    assert [b["key"] for b in main._op_backup_list({}, ALICE)["backups"]] == ["backups/acct-alice/a.db.gz"]
    assert [b["key"] for b in main._op_backup_list({}, BOB)["backups"]] == ["backups/acct-bob/b.db.gz"]


# ── Upload ───────────────────────────────────────────────────────────────────

def test_upload_url_is_for_a_key_the_server_chose(s3):
    out = main._op_backup_upload_url({"size": 1000}, ALICE)
    assert out["key"].startswith("backups/acct-alice/retailos-")
    assert out["key"].endswith(".db.gz")
    assert s3.signed == [("put_object", out["key"])]


def test_upload_url_ignores_a_client_supplied_key(s3):
    out = main._op_backup_upload_url({"size": 10, "key": "backups/acct-bob/evil.db.gz"}, ALICE)
    assert "acct-bob" not in out["key"]


@pytest.mark.parametrize("size", [0, -1, None, "big"])
def test_upload_url_needs_a_real_size(s3, size):
    with pytest.raises(HTTPException):
        main._op_backup_upload_url({"size": size}, ALICE)


def test_upload_url_refuses_an_absurd_file(s3, monkeypatch):
    monkeypatch.setattr(main, "BACKUP_MAX_FILE_BYTES", 1000)
    with pytest.raises(HTTPException) as e:
        main._op_backup_upload_url({"size": 1001}, ALICE)
    assert e.value.status_code == 413


def test_upload_prunes_the_oldest_beyond_keep(s3, monkeypatch):
    monkeypatch.setattr(main, "BACKUP_KEEP", 3)
    s3.objects = {f"backups/acct-alice/retailos-{i}.db.gz": 10 for i in range(1, 6)}
    out = main._op_backup_upload_url({"size": 10}, ALICE)
    # Keeps the 2 newest, so that with the one about to arrive there are 3.
    assert sorted(out["pruned"]) == [
        "backups/acct-alice/retailos-1.db.gz",
        "backups/acct-alice/retailos-2.db.gz",
        "backups/acct-alice/retailos-3.db.gz",
    ]


def test_pruning_never_touches_another_shop(s3, monkeypatch):
    monkeypatch.setattr(main, "BACKUP_KEEP", 1)
    s3.objects = {
        "backups/acct-alice/retailos-1.db.gz": 10,
        "backups/acct-alice/retailos-2.db.gz": 10,
        "backups/acct-bob/retailos-1.db.gz": 10,
    }
    main._op_backup_upload_url({"size": 10}, ALICE)
    assert all(k.startswith("backups/acct-alice/") for k in s3.deleted)


def test_quota_is_enforced_after_pruning(s3, monkeypatch):
    monkeypatch.setattr(main, "BACKUP_KEEP", 10)
    monkeypatch.setattr(main, "BACKUP_QUOTA_BYTES", 100)
    s3.objects = {"backups/acct-alice/retailos-1.db.gz": 90}
    with pytest.raises(HTTPException) as e:
        main._op_backup_upload_url({"size": 50}, ALICE)
    assert e.value.status_code == 413


def test_a_shop_at_its_limit_with_prunable_backups_is_allowed(s3, monkeypatch):
    monkeypatch.setattr(main, "BACKUP_KEEP", 2)
    monkeypatch.setattr(main, "BACKUP_QUOTA_BYTES", 100)
    s3.objects = {f"backups/acct-alice/retailos-{i}.db.gz": 40 for i in range(1, 4)}
    out = main._op_backup_upload_url({"size": 40}, ALICE)   # 120 used, pruned to 40
    assert out["key"]


# ── Configuration ────────────────────────────────────────────────────────────

def test_an_unconfigured_server_says_which_setting_is_missing(monkeypatch):
    monkeypatch.setattr(main, "_s3_client", None)
    monkeypatch.setattr(main, "B2_BUCKET", "")
    monkeypatch.setattr(main, "B2_KEY_ID", "id")
    monkeypatch.setattr(main, "B2_APP_KEY", "key")
    monkeypatch.setattr(main, "B2_ENDPOINT", "https://x")
    with pytest.raises(HTTPException) as e:
        main._op_backup_list({}, ALICE)
    assert e.value.status_code == 503
    assert "B2_BUCKET" in e.value.detail


# ── The handler table ────────────────────────────────────────────────────────

def test_the_backup_ops_are_reachable():
    for name in ("backup.upload_url", "backup.list", "backup.download_url", "backup.delete"):
        assert name in main.HANDLERS


def test_no_backup_handler_reads_an_account_from_its_arguments():
    """
    A structural guard. If somebody later adds `args.get("account")` to one of
    these, this fails — before it reaches a bucket holding 500 shops.
    """
    import inspect
    for name, fn in main.HANDLERS.items():
        if not name.startswith("backup."):
            continue
        src = inspect.getsource(fn)
        assert "_account_of(caller)" in src, f"{name} must derive its account from the token"
        assert 'args.get("account")' not in src, f"{name} must not read an account from args"
        assert 'args["account"]' not in src, f"{name} must not read an account from args"
