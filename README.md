# Cert Tracker

A small self-hosted app for keeping track of TLS certificates, both internal CA and public:
what you have, where each one is installed, when it expires, and whether a renewal actually
made it onto every server. Reminders go to a shared mailbox, not to whoever happens to remember.

## What it does

- **Inventory without typing dates.** Add a certificate by uploading the file (.cer/.crt/.pem/.der/.p7b/.pfx),
  pasting PEM, or pointing it at a server (`host:port`). Expiry, names, issuer, serial and thumbprints
  are read from the certificate. Private keys are never stored. For things you can't get a file for,
  enter the expiry by hand.
- **Locations.** Each certificate lists everywhere it is installed:
  - *Endpoints* (`host:port`) are checked over the network every day.
  - *Manual locations* (SAML apps, appliances, client certs) are confirmed by a person.
- **Renewals tracked to the last server.** "Record a renewal" moves every location to the new certificate
  as *pending*. Endpoints flip to *installed* when the scanner sees the new cert. If a server still serves
  the old one, it's flagged. If a server starts serving a newer certificate nobody recorded, it's flagged
  too, with a one-click "record as the renewal".
- **Discovery, so the list doesn't depend on people.**
  - *Public:* watched domains are checked daily against Certificate Transparency logs (crt.sh). Every public
    certificate issued for your domains shows up for review, including ones bought on a credit card.
  - *Internal:* `scripts/Export-AdcsCertificates.ps1` exports issued certificates from the Microsoft CA,
    as a scheduled task posting to the API or as a CSV upload.
  - *Scans:* any unknown certificate seen on a scanned endpoint is added for review.
- **Email.** A daily digest goes to a distribution list when something crosses a threshold (60/30/14/7 days
  by default), is inside the last threshold or expired, a location has a problem, or discoveries are waiting.
  A weekly summary is sent even when all is well, so silence never means the tracker died. `/api/health`
  returns 503 if the daily run stops succeeding. Point your uptime monitor at it.
- **History.** Every change, renewal, scan result and note is logged with who did it.
- **Sign-in with Microsoft Entra ID**, and CSV export of everything.

## Try it locally (no sign-in)

```sh
docker build -t cert-tracker .
docker run --rm -p 8000:8000 -e AUTH_MODE=none -e DATABASE_URL=sqlite:////data/test.db cert-tracker
# open http://localhost:8000
```

`AUTH_MODE=none` is for trying it out only. Anyone who can reach the port can use it.

## Deploying

### 1. A host

Any Linux VM (or Windows with Docker) with Docker Compose. It needs to reach:

- the servers you want scanned, on their TLS ports (443, 636, 8443, …)
- your SMTP relay
- `login.microsoftonline.com` (sign-in) and `crt.sh` (CT checks), outbound HTTPS

The DMZ can come later. Endpoints the scanner can't reach just show "could not connect". For those, use
manual locations until a firewall rule is approved.

### 2. Register the app in Entra ID

1. **Entra admin center → App registrations → New registration.** Name it *Cert Tracker*, single tenant,
   redirect URI type **Web**: `https://<your BASE_URL>/auth/callback`.
2. **Certificates & secrets → New client secret.** Copy the value into `ENTRA_CLIENT_SECRET`.
   That secret expires, so add it to Cert Tracker as a manual certificate entry on day one.
3. Copy the **Directory (tenant) ID** and **Application (client) ID** from the overview page.
4. **Enterprise applications → Cert Tracker → Properties → Assignment required = Yes**, then under
   **Users and groups** add your team's group. Only assigned people can sign in.

### 3. Configure and start

```sh
git clone <this repo> cert-tracker && cd cert-tracker
cp .env.example .env      # fill it in; comments explain each setting
docker compose up -d --build
docker compose logs -f
```

Compose runs two containers from one image. **web** is the app on port 8000. **scheduler** runs the daily
job at `DAILY_RUN_TIME`, and catches up on start if it missed one.

### 4. Put TLS in front of it

Serve it as `https://certs.<yourdomain>` through your usual reverse proxy (IIS ARR, nginx, Caddy, the load
balancer), using a certificate from your internal CA. Set `TRUST_PROXY=true` and add that certificate to
Cert Tracker too.

### 5. First-day checklist

- Settings → **Send a test email**.
- Settings → add your public domains under **Public domains to watch**.
- On the CA, run `Export-AdcsCertificates.ps1 -OutFile issued.csv`, review it, upload it on Settings, then
  set up the scheduled task (below).
- Settings → **Run the daily checks now**, then work through **To review**: track what matters, ignore the rest.
- For each tracked certificate, add its locations and a few lines of "How to renew it".

## Internal CA sync (scheduled task)

On the CA, as an account that can read the CA database:

```powershell
# One-off check of what will be sent:
.\Export-AdcsCertificates.ps1 -OutFile C:\Temp\issued.csv

# Daily sync (put the API_TOKEN value in a file only that account can read):
.\Export-AdcsCertificates.ps1 -TrackerUrl https://certs.corp.example.ca -ApiTokenFile C:\CertTracker\token.txt
```

By default it leaves out auto-enrolment templates (Machine, User, DomainController, Workstation…). Adjust
`-ExcludeTemplate` / `-IncludeTemplate` to taste. Run the `-OutFile` version first and look at the CSV:
template names on your CA may differ, and **this script has not yet been run against a real CA**.

## Day to day

| Situation | What to do |
|---|---|
| New certificate | **Add** → upload it or read it from the server, then add its locations and renewal notes. |
| Renewing | Open it → **Record a renewal** (upload the new cert, or read it from a server you've installed it on). Install it everywhere; endpoints confirm themselves, manual locations need **Confirm installed**. |
| Email says "serving a newer certificate" | Someone renewed without recording it. Open it → **Record served cert as the renewal**. |
| Email says "serving an older certificate" | The renewal didn't get installed there. Go install it. |
| Something shows up in **To review** | Track it (and add locations), or ignore it if it isn't yours to manage. |
| Decommissioned | **Retire** it. Alerts stop and the history is kept. |

## Backups

Everything lives in one SQLite file in the `certdata` volume. A consistent copy:

```sh
docker compose exec web python -c "import sqlite3; sqlite3.connect('/data/certtracker.db').backup(sqlite3.connect('/data/backup.db'))"
docker compose cp web:/data/backup.db ./certtracker-backup.db
```

The **Export everything as CSV** link on the main page is a human-readable copy too.

## Known limits

- The scanner speaks TLS directly. Services that start in plain text and upgrade (SMTP STARTTLS on 25/587,
  LDAP StartTLS on 389, RDP on 3389, database protocols) can't be scanned yet. Track those as manual
  locations. LDAPS (636), HTTPS and most management interfaces work.
- One host, SQLite: fine for dozens or hundreds of certificates, not built for many thousands.
- Settings like thresholds and recipients live in `.env`, so they're changed by whoever administers the host.
- Schema changes in future versions will need a migration step. There's no migration tooling yet.

## Development

```sh
pip install -r requirements-dev.txt
pytest
AUTH_MODE=none DATABASE_URL=sqlite:///dev.db flask --app certtracker.wsgi run --debug
```
