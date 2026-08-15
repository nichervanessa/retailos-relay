# Pharmacy relay — deploy to Render

This folder is a **complete, standalone repository**. It holds the Firebase
privilege relay and nothing else.

**It contains no pharmacy source code.** No POS, no products, no sales, no
loans, no models, no reports, no Electron, no React. Three files:
`main.py` (290 lines), `requirements.txt`, `render.yaml`. Anyone reading the
whole repository learns that you create Firebase users and burn activation
codes — which the app tells them anyway — and nothing about how the pharmacy
system works.

Your real source code stays on your Desktop and is never uploaded anywhere.

---

## Step 1 — Put this folder in its own GitHub repo

Move this folder somewhere outside the pharmacy project first, so it can be
its own repository:

```
C:\Users\niche\Desktop\pharmacy-relay\
```

On GitHub: **New repository** → name it `pharmacy-relay` → set it to
**Private** → do *not* add a README or .gitignore (this folder has both) →
**Create repository**.

Then, in PowerShell:

```powershell
cd "C:\Users\niche\Desktop\pharmacy-relay"
git init
git add .
git commit -m "Firebase privilege relay"
git branch -M main
git remote add origin https://github.com/nichervanessa/pharmacy-relay.git
git push -u origin main
```

Before pushing, run `git status` once and confirm
`firebase_service_account.json` is **not** in the list. `.gitignore` already
excludes it, but check anyway — a key pushed to GitHub stays in the history
even after you delete the file, and must then be rotated.

Private is fine. Render reads private repositories on the free plan.

---

## Step 2 — Create the service on Render

1. Sign in at **render.com** with GitHub.
2. **New → Blueprint**.
3. Pick the `pharmacy-relay` repository. Render finds `render.yaml` and
   proposes one web service called `pharmacy-relay`.
4. It will ask for `RELAY_SECRET` because the blueprint marks it `sync: false`.
   Paste the secret from `SECRET.txt` (delivered alongside this folder — keep
   that file off GitHub; it is only a note to yourself).
5. **Apply**. The first build takes a few minutes.

The deploy will start and then fail its health check. That is expected — the
key is not there yet. Step 3 fixes it.

---

## Step 3 — Upload the Firebase key as a Secret File

This is the whole point of the relay: the key lives here, on a server you
control, instead of inside every customer's installer.

1. Render dashboard → the **pharmacy-relay** service → **Environment**.
2. Scroll to **Secret Files** → **Add Secret File**.
3. Filename — exactly this, spelling matters:

   ```
   firebase_service_account.json
   ```

4. Contents: open
   `C:\Users\niche\Desktop\Pharmcy Management system offline\backend\firebase_service_account.json`
   in Notepad, copy everything, paste it in.
5. **Save**. Render redeploys automatically.

It mounts at `/etc/secrets/firebase_service_account.json`, which is what
`render.yaml` already points `FIREBASE_SERVICE_ACCOUNT` at.

---

## Step 4 — Check it works

Copy your service URL from the top of the Render dashboard. It looks like
`https://pharmacy-relay.onrender.com`. Then:

```powershell
curl https://pharmacy-relay.onrender.com/health
```

You want exactly this:

```json
{"status":"healthy","configured":true}
```

`"configured":false` means `RELAY_SECRET` did not get set — go back to
Environment and add it. A 502 or a timeout on the first try usually means the
free instance is still waking up; try once more.

---

## Step 5 — Build the desktop app

In PowerShell, in the pharmacy project folder:

```powershell
cd "C:\Users\niche\Desktop\Pharmcy Management system offline"

$env:RELAY_URL="https://pharmacy-relay.onrender.com"
$env:RELAY_SECRET="<the same secret from SECRET.txt>"

npm run electron-publish
```

The refusal you hit is now satisfied and the build proceeds. You should see:

```
[relay] baked in: https://pharmacy-relay.onrender.com
```

These two variables last only for that PowerShell window. Open a new window
and you must set them again — which is deliberate, so a build can never
silently go out without a relay.

---

## About the free plan

A free Render instance sleeps after about 15 minutes with no traffic, and the
next request takes roughly 50 seconds to wake it. Activation is the request
that suffers: a customer types their code, waits, and may see
"Could not reach the activation server" before it wakes.

Two ways round it:

- **$7/month starter plan** — no sleeping. Simplest.
- **Stay free and warm it yourself** — hit `/health` every 10 minutes with a
  free uptime pinger (UptimeRobot and similar). Costs nothing. Do this at
  minimum, since activation is the first thing a new customer ever does.

---

## Rotating the secret later

If you ever need to change `RELAY_SECRET`: set the new value in the Render
dashboard, then rebuild and re-publish the desktop app with the same new
value. Installed copies keep selling, printing and logging in throughout —
only account creation and activation need the relay, and only until the
customer updates.
