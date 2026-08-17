# Getting this relay onto GitHub and Render

Three separate things, in this order. The last one is what fixes
**"Invalid activation code"**.

---

## 0. First: revoke the token and the secret you pasted

You pasted these into a chat:

```
GH_TOKEN      ghp_WT11oz…            ← revoke now
RELAY_SECRET  jBIgQjGm2iXro5mtnXIPR… ← replace when you deploy
```

Treat both as public.

**The GitHub token** — github.com → your avatar → **Settings** → **Developer settings** →
**Personal access tokens** → **Tokens (classic)** → find it → **Delete**. Then make a new one
with the **repo** scope and use that. A token with `repo` can read and write every repository
you own, so this is not a formality.

**The relay secret** — it is a coarse filter rather than a credential (every operation behind
it also needs a signed-in admin, by design), so nothing is compromised by it alone. Still:
generate a new one when you deploy, and set `RELAY_SECRET_PREVIOUS` to the old value for a few
days so installers already in the field keep working while you ship an update. The relay's
README has the staged procedure.

For anything you paste in future: environment variables set with `$env:` are the right
approach — just do not paste the values themselves anywhere. Put them in a file only you can
read, or set them once per machine in **System Properties → Environment Variables**.

---

## 1. The publish 404 — why `electron-publish` failed

The build succeeded. Only the upload failed, and only for one reason:

```
GET https://api.github.com/repos/nichervanessa/retailos-releases/releases → 404
```

`package.json` publishes to a repository called **retailos-releases**, and it does not exist.
`pharmacy-releases` does. GitHub answers 404 rather than 403 for a repository you cannot see,
which is why the error talks about your token — the token is fine.

**Rename the existing repository. Do not create a new one.**

1. github.com/nichervanessa/**pharmacy-releases** → **Settings**
2. Under **Repository name**, change it to `retailos-releases` → **Rename**

Renaming matters because every copy of the app already installed asks
`pharmacy-releases` for updates. GitHub keeps a redirect from the old name forever, so those
installs keep updating. A brand-new repository leaves them checking an address that has no
releases in it, and they never update again.

Then re-run the publish. The installer is already built at
`dist\RetailOS-Pro Setup 2.0.0.exe`, so this only re-uploads:

```powershell
$env:GH_TOKEN="<your NEW token>"
$env:RELAY_URL="https://retailos-relay.onrender.com"
$env:RELAY_SECRET="<the new secret>"
npm run electron-publish
```

It creates a **draft** release (`releaseType: draft` in package.json). Open it on GitHub and
press **Publish release**, or customers will not be offered the update.

---

## 2. Push this folder to `retailos-relay`

The folder is renamed and the remote is already pointed at the new repository. The GitHub repo
exists with one commit (its README), so pull that in first, then push:

```powershell
cd "$env:USERPROFILE\OneDrive\Desktop\Professional Retail POS\retailos-relay"

git remote -v                       # should say retailos-relay.git
git add -A
git commit -m "RetailOS relay: own project, own service"
git pull --no-rebase --no-edit origin main
git push -u origin main
```

If the pull reports a conflict in `README.md`, keep this folder's version:

```powershell
git checkout --ours README.md
git add README.md
git -c core.editor=true commit
git push -u origin main
```

You asked about the SSH address (`git@github.com:…`). HTTPS above needs no setup; SSH needs a
key pair generated and added to your GitHub account first. If you want SSH:

```powershell
git remote set-url origin git@github.com:nichervanessa/retailos-relay.git
```

**`SECRET.txt` is not pushed** — it is in `.gitignore`, and it holds the old secret. Replace
its contents when you generate the new one, or delete the file; it is a note to yourself, not
something the code reads.

The old `pharmacy-relay` folder now contains nothing but its `.git`. I cannot delete folders
on your machine — delete it in Explorer when you are satisfied the new one is pushed.

---

## 3. Deploy on Render — and why activation is failing right now

This is the actual cause of **کۆدی مۆڵەت — Invalid activation code**.

Your control panel writes activation codes into the Firebase project the app verifies
against: **retail-pos-ee168**. The relay you are pointing at
(`pharmacy-relay.onrender.com`) holds a service-account key for the *old pharmacy* project.
So the relay looks up your perfectly valid code in a project that has never heard of it,
finds nothing, and returns "Invalid activation code". Nothing logs an error, because from the
relay's point of view nothing went wrong.

Full click-by-click steps are in **README.md → Deploy on Render**. The short version:

1. Firebase Console → project **retail-pos-ee168** → Project settings → Service accounts →
   **Generate new private key**.
2. Render → **New → Blueprint** → pick `nichervanessa/retailos-relay`. Leave the pharmacy
   relay running — old pharmacy installs have its address baked in.
3. Service → Environment → **Secret Files** → filename `firebase_service_account.json`,
   contents = that JSON.
4. Environment variables: `RELAY_SECRET` = your new random string,
   `FIREBASE_PROJECT_ID` = `retail-pos-ee168`.
5. Check it before touching the app:

   ```bash
   curl https://retailos-relay.onrender.com/health
   ```

   `project` must read `retail-pos-ee168` and `project_ok` must be `true`. This check is new —
   the old relay had no way to tell you which project it was serving, which is exactly why
   this took so long to find.
6. Rebuild with `RELAY_URL=https://retailos-relay.onrender.com` and the new secret.

### Activating today, before Render is set up

The desktop app prefers a **local** service-account key over the relay when that key belongs
to the project it verifies against. So on your own shop PC you can activate immediately:

1. Get the `retail-pos-ee168` key JSON (step 1 above).
2. Save it as `firebase_service_account.json` inside the installed app's backend folder —
   `C:\Users\<you>\AppData\Local\Programs\RetailOS-Pro\resources\backend\`, or
   `backend\` in this project folder when running from source.
3. Restart the app. `http://127.0.0.1:8000/health` should report
   `"privileged_mode":"local"`, and the activation code will work.

**Only on machines you control.** That file is the master key to the Firebase project: anyone
who copies it can mint admin accounts and forge activation codes for every shop. Never put it
in an installer, a repository, or a customer's PC — the relay exists precisely so it does not
have to travel.
