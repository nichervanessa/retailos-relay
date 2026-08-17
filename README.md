# RetailOS Pro — Firebase privilege relay

Holds the Firebase service-account private key so the desktop installer never has to.

**This is its own service, for its own Firebase project.** It is not the pharmacy relay and
must not share a deployment with it: the two hold keys for different Firebase projects, and a
relay pointed at the wrong project reports every valid activation code as invalid. See
**Deploy on Render** below, and check `/health` after every deploy.

## Why

Before this service, `firebase_service_account.json` was copied into every customer's
installation. That file is the master key to the Firebase project. Anyone who extracted it
could create their own admin accounts, forge activation codes, and read every other
shop's synced dashboard. Because it shipped inside the app, it had to be assumed public.

The relay keeps the key on a server you control. The desktop app asks for the specific
operation it needs and receives only that result.

## What still works without it

Almost everything. Verifying a staff login needs only the project ID and Google's public
certificates, so **logins, the POS, inventory, reports and printing are unaffected** on an
install with no relay configured.

These three features need the relay (or a local key on a developer machine):

| Feature | Without a relay |
|---|---|
| Creating and editing staff accounts | Clear error asking you to configure the server |
| Online activation with a 16-character code | Clear error; legacy signed keys still activate offline |
| Mobile dashboard sync | Silently paused, logged once |

## Deploy on Render

Fifteen minutes, once. Everything below happens in the Render and Firebase dashboards —
nothing is committed, because none of it belongs in a git repository.

### 1. Get the key for the RIGHT project

Firebase Console → pick the project the app verifies against — **retail-pos-ee168** for
RetailOS Pro → gear icon → **Project settings** → **Service accounts** → **Generate new
private key**. A `.json` file downloads. Keep it out of this repository and off any shared
drive.

This step decides whether activation works at all. A key from any other project produces a
relay that answers every request politely and finds nothing.

### 2. Create the service

Push this repository to GitHub, then on Render: **New → Blueprint**, and pick
`nichervanessa/retailos-relay`. The blueprint in `render.yaml` names the service
`retailos-relay` and sets the health check.

If you already run the pharmacy relay, **create this as a separate service and leave that one
running.** Pharmacy installations already in the field have its address baked into their
build; taking it down stops them creating staff accounts and activating.

### 3. Upload the key

Service → **Environment** → **Secret Files** → **Add Secret File**:

| | |
|---|---|
| Filename | `firebase_service_account.json` |
| Contents | paste the whole JSON file from step 1 |

It mounts at `/etc/secrets/firebase_service_account.json`, where `FIREBASE_SERVICE_ACCOUNT`
already points.

### 4. Set two environment variables

| Key | Value |
|---|---|
| `RELAY_SECRET` | a long random string. Generate it and never reuse one that has been pasted into a chat, an email or a terminal you have shared: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `FIREBASE_PROJECT_ID` | `retail-pos-ee168` — the project you expect. The relay logs an error at startup and `/health` reports `project_ok: false` if the uploaded key disagrees. |

### 5. Verify before touching the app

```bash
curl https://retailos-relay.onrender.com/health
```

```json
{"status":"healthy","configured":true,"project":"retail-pos-ee168",
 "project_expected":"retail-pos-ee168","project_ok":true,"version":"2.1.0"}
```

`configured` false — `RELAY_SECRET` is not set. `project` empty — the Secret File is not
mounted, or is not the service-account JSON. `project_ok` false — the key belongs to another
project, and activation will fail with "Invalid activation code" until it is replaced.

### 6. Point the desktop app at it, and build

`npm run relay-config` bakes `RELAY_URL` into the build; the backend inherits `RELAY_SECRET`.
In PowerShell, from the app folder:

```powershell
$env:RELAY_URL="https://retailos-relay.onrender.com"
$env:RELAY_SECRET="<the same value you set on Render>"
npm run electron-publish
```

On a machine running the new build, the desktop `/health` should report
`"privileged_mode":"relay"`.

### The free plan sleeps

Render's free instance stops after about fifteen minutes of quiet and takes most of a minute
to wake. The desktop app retries once with a longer timeout for exactly this reason, so
background sync copes — but somebody sitting on the activation screen waits. If customers
activate during the working day, the paid plan (~$7/mo) is the difference between "it worked"
and "it timed out, try again".

## When activation says "Invalid activation code"

One message, four causes. In the order worth checking:

1. **The relay holds the wrong project's key.** `curl .../health` and read `project`. The
   control panel writes codes into its own project; the relay looks in the project its key
   belongs to. Different projects, and a perfectly valid code is simply not there. This is
   the cause that looks like every other cause, which is why `/health` now reports it.
2. **The code was never written**, or was written by a control panel signed in to a different
   project. Look for the exact 16 characters in the `activationCodes` collection in the
   Firebase console.
3. **Already used, revoked or expired** — each of those has its own message, so if you are
   reading "invalid", it is none of them.
4. **Not 16 alphanumeric characters** — refused without a lookup.

## How requests are authorised

1. **Shared secret** (`X-Relay-Secret`) — ships inside the app, so treat it as a coarse
   filter against random internet traffic rather than a real credential. Compared in
   constant time, and nothing here may rely on it alone.
2. **Caller identity** — every operation that touches an account requires the caller's own
   Firebase ID token, verified here.
3. **Entitlement** — what a caller may then do is read from data only the control panel can
   write. An admin may manage accounts within their own shop (`created_by` / `account`
   claims); nobody may reach across into another customer's.
4. **Collection allow-list** — Firestore access is restricted to `accounts`,
   `activationCodes` and `mobile_dashboard`, each with its own rule. Activation codes are no
   longer client-writable at all: `activation.claim` is the only thing that writes one.

### The rule that has to hold

> **No path may grant the admin role on the strength of the shared secret, or on the
> strength of the caller simply being signed in.**

The version of this service shipped before v2.0.0 broke that rule twice. `user.set_claims`
accepted any caller setting claims on their **own** uid — so a cashier could name themselves
admin, on any install in the customer base, and then list, create and delete accounts across
every shop sharing the project. It also accepted a request with **no caller at all** so
long as the role being granted was `admin`, on the strength of a comment saying the desktop
backend had checked an activation code first. The relay never verified that, and could not:
the check sat on the far side of a boundary the attacker controls.

Both paths existed to serve activation, which genuinely does need to grant admin to somebody
who is not an admin yet. That need is now met by two operations that establish entitlement
for themselves:

| Operation | Proof required | Who receives the role |
|---|---|---|
| `activation.claim` | an unused, unrevoked, unexpired `activationCodes` document — verified and burned in one Firestore transaction | the login named by the **code document** |
| `account.claim_admin` | the caller's verified ID token matching an `accounts` document by `adminUid`, or by **verified** email | the **caller**, and only the caller |

Neither lets a client name a role or a target. `user.set_claims` now requires an admin
caller and refuses accounts belonging to another shop.

### Known residual risk

Someone who extracts the shared secret can still reach the relay, but every operation behind
it now needs a signed-in admin — so what a bare secret buys is the chance to be refused. To
close it entirely, bind each installation to its own token: mint a random per-install token
during `activation.claim`, return it for the desktop app to store in `app_settings`, and
require it alongside the shared secret.

## Rotating the shared secret

**Do this once the v2.0.0 relay is deployed.** The old secret was in every installer
alongside a relay that would escalate on it.

The secret is baked into the build, so rotating it invalidates every copy already in the
field. `RELAY_SECRET_PREVIOUS` exists to make that a staged change rather than a cliff:

1. Generate a new secret: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
2. On Render, set `RELAY_SECRET` to the new value and `RELAY_SECRET_PREVIOUS` to the old
   one. Both are accepted; the log records which one each request used.
3. Build and release a desktop update carrying the new `RELAY_SECRET`.
4. Once customers have updated — the relay log stops mentioning the previous secret — clear
   `RELAY_SECRET_PREVIOUS` and redeploy.

Logins, sales, reports and printing are unaffected at every step. None of them touch the
relay.

## Rotating the service-account key

Since the key shipped in installers before the relay existed, treat it as compromised:

1. Firebase Console → Project settings → Service accounts → **Generate new private key**.
2. Upload the new file to Render as the secret file.
3. Delete the old key in the Google Cloud console (IAM → Service accounts → Keys).
4. Release a desktop build that uses the relay.

Old installations keep working for logins and sales throughout, because verification never
needed the key.

## After deploying v2.0.0: audit the admin role

The escalation paths above were reachable for as long as the previous relay was live, and
they leave no trace beyond the claim itself. Worth checking once:

```bash
python - <<'PY'
import firebase_admin
from firebase_admin import auth, credentials
firebase_admin.initialize_app(credentials.Certificate("firebase_service_account.json"))
for u in auth.list_users().users:
    c = u.custom_claims or {}
    if c.get("role") == "admin":
        print(f"{u.email:40} account={c.get('account','-'):24} created_by={c.get('created_by','-')}")
PY
```

An admin you do not recognise — or one with no `account` binding that you did not create
yourself — is worth investigating.

## Run locally

```bash
cd retailos-relay
pip install -r requirements.txt
export RELAY_SECRET=dev-secret
export FIREBASE_SERVICE_ACCOUNT=../backend/firebase_service_account.json
uvicorn main:app --port 9000
```

Then start the desktop backend with `RELAY_URL=http://127.0.0.1:9000` and
`RELAY_SECRET=dev-secret`.
