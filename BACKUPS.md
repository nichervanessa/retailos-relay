# Online backups — setting up the bucket

Every shop that switches on **پاشەکەوتی ئۆنلاین** uploads its database here each
night. This is what you have to do once, before any of them can.

Nothing in this file is a shop's job. If you never do it, the backup screen
says online backup is not available and the other two backups carry on.

---

## 1. Make the bucket

Backblaze → **B2 Cloud Storage → Buckets → Create a Bucket**

| Setting | Value | Why |
|---|---|---|
| Bucket name | `retailos-backups` | any name; it goes in `B2_BUCKET` |
| Files in bucket are | **Private** | public would put 500 shops' books on the open web |
| Object lock | off | it would stop the nightly pruning |
| Encryption | on (SSE-B2) | free, and it costs nothing to have |

Then **Bucket Settings → Lifecycle Settings → Keep only the last version**.
The relay prunes per shop; this is the safety net underneath it.

## 2. Make an application key — for this bucket only

> **Do not use the master key.** Backblaze creates one automatically and shows
> it at the top of this page, and it does **not work with the S3 API at all** —
> their documentation says so outright. It comes back as "not a valid
> application key id", which reads like a typo and sends you re-copying a key
> that was never going to work.
>
> How to tell them apart: the master key's id is your **account id**, about 12
> characters. A real application key id is about **25** characters and starts
> with those same 12.

**App Keys → Add a New Application Key**

- Name: `retailos-relay`
- **Allow access to Bucket(s): `retailos-backups`** ← not "All"
- Type of Access: **Read and Write**
- Leave the file-name prefix empty (the relay writes under `backups/<account>/`)

You are shown `keyID` and `applicationKey` **once**. The application key is
never displayed again.

Scoping the key to one bucket is the part worth being careful about: this key
lives on a server, and a key that can reach the whole Backblaze account turns
one leaked env var into everything you have.

## 3. Give the relay the settings

Render → the `retailos-relay` service → **Environment**:

| Key | Value |
|---|---|
| `B2_ENDPOINT` | copy the *Endpoint* straight off the bucket page, e.g. `s3.eu-central-003.backblazeb2.com` — with or without `https://`, either is accepted |
| `B2_REGION` | **leave empty.** It is read out of the endpoint. Set it only to override that. |
| `B2_BUCKET` | `retailos-backups` |
| `B2_KEY_ID` | the keyID from step 2 |
| `B2_APP_KEY` | the applicationKey from step 2 |

Optional:

| Key | Default | |
|---|---|---|
| `BACKUP_KEEP` | `10` | backups kept per shop |
| `BACKUP_QUOTA_BYTES` | `5368709120` | 5 GiB ceiling per shop |

> **The mistake everybody makes.** Render has a KEY box and a VALUE box; the
> table above prints them as one line. Paste only the right-hand side into the
> VALUE box. `B2_ENDPOINT=https://s3...` in the value box is wrong —
> `https://s3...` on its own is right. The relay now catches this and names the
> setting, but only after a deploy you could have skipped.
>
> `B2_REGION` is read out of the endpoint, so leave it empty. If you do set it
> and it disagrees with the endpoint, B2 rejects every call with a signature
> error that says nothing about which of the two is wrong — so the relay checks
> them against each other and tells you instead.

Deploy. `GET /health` should still be green; the backup operations answer `503`
naming the missing or mistyped setting until all five are right.

---

## What this costs

A shop's database is usually 50–300 MB, about 45 MB gzipped. Ten kept per shop:

| | 500 shops |
|---|---|
| Stored | ~225 GB |
| B2 at ~$6/TB/month | **≈ $1.40/month** |
| Upload | free |
| Download on a restore | free (B2 gives 3× stored free) |

The ceiling matters more than the average: `BACKUP_QUOTA_BYTES` × 500 is the
worst case you have agreed to pay for. At the default that is 2.5 TB ≈ $15/month
if every shop filled it, which none will.

---

## How one shop is kept out of another's data

Worth knowing exactly, because it is the whole thing.

Each shop's files live under `backups/<account_id>/`. The relay builds that path
from the **`account` custom claim inside the caller's Firebase ID token** — a
token it verifies against Google on every request, and a claim only the relay
itself ever writes (during `activation.claim`). There is no operation that
accepts an account, a prefix or a bucket path, so there is no field in which a
shop could name someone else's. A key sent up for a download or a delete is
checked against that same prefix before it reaches B2.

The shared `RELAY_SECRET` is **not** part of this. It is baked into every
installer by design, so anyone with a copy of the app has it. It gets you to the
door; the token decides the room.

`relay/tests/test_backup_ops.py` is the proof — it asks for another shop's
backup in every way the API allows and requires each one to be refused.

---

## When a shop needs a restore

They do it themselves: **Backup → Restore → from the online backups**, pick a
date, type `RESTORE`, enter the Format PIN. Same gate as every other restore.

You can do it for them too — the files are plain, unencrypted `.db.gz`. That was
a deliberate choice so a support call can end with the shop trading again. It
also means you are holding readable copies of 500 shops' books: keep the B2 key
out of anything shared, and do not put a second copy of these files anywhere.
