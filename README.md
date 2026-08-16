# Firebase privilege relay

Holds the Firebase service-account private key so the desktop installer never has to.

## Why

Before this service, `firebase_service_account.json` was copied into every customer's
installation. That file is the master key to the Firebase project. Anyone who extracted it
could create their own admin accounts, forge activation codes, and read every other
pharmacy's synced dashboard. Because it shipped inside the app, it had to be assumed public.

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

The blueprint in `../render.yaml` already defines this service.

1. **Push the repository** to GitHub, then in Render choose **New → Blueprint** and pick it.
2. **Upload the key.** In the `pharmacy-relay` service → *Environment* → *Secret Files*, add a
   file named `firebase_service_account.json` containing your service account JSON. It mounts
   at `/etc/secrets/firebase_service_account.json`.
3. **Set the shared secret.** Generate a long random string:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Set it as `RELAY_SECRET` on the relay service.
4. **Point the desktop app at it.** In `electron/main.js` the backend inherits `RELAY_URL` and
   `RELAY_SECRET` from the environment, so set both when building a release:

   ```
   RELAY_URL=https://pharmacy-relay.onrender.com
   RELAY_SECRET=<the same value>
   ```

5. **Verify.** `curl https://pharmacy-relay.onrender.com/health` should return
   `{"status":"healthy","configured":true}`, and the desktop `/health` should report
   `"privileged_mode":"relay"`.

Use a paid Render plan, or the free instance sleeps and the first activation of the day
times out.

## How requests are authorised

1. **Shared secret** (`X-Relay-Secret`) — ships inside the app, so treat it as a coarse
   filter against random internet traffic rather than a real credential. Compared in
   constant time, and nothing here may rely on it alone.
2. **Caller identity** — every operation that touches an account requires the caller's own
   Firebase ID token, verified here.
3. **Entitlement** — what a caller may then do is read from data only the control panel can
   write. An admin may manage accounts within their own pharmacy (`created_by` / `account`
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
every pharmacy sharing the project. It also accepted a request with **no caller at all** so
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
caller and refuses accounts belonging to another pharmacy.

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
cd relay
pip install -r requirements.txt
export RELAY_SECRET=dev-secret
export FIREBASE_SERVICE_ACCOUNT=../backend/firebase_service_account.json
uvicorn main:app --port 9000
```

Then start the desktop backend with `RELAY_URL=http://127.0.0.1:9000` and
`RELAY_SECRET=dev-secret`.
