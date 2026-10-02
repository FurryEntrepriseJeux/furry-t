# FurryPass account API

This Node.js service shares user accounts and per-profile language preferences between PCs. Conversation files stay on each PC and are never sent to this service.

## Requirements

- Node.js 18 or later
- An HTTPS reverse proxy such as IIS or Nginx for Internet access
- A persistent, private data directory on the server

The API uses only Node.js built-in modules; no `npm install` is required.

## Start the service

Set these environment variables in the hosting service configuration:

- `NODE_ENV=production`
- `HOST=127.0.0.1`
- `PORT=8787` (or the port assigned by the host)
- `FURRY_DATA_PATH` to a persistent writable JSON file outside the public web root
- `BOOTSTRAP_ADMIN_KEY` to a long, random, one-time setup secret

Start the service with `npm start`. The reverse proxy must provide HTTPS and set `X-Forwarded-Proto: https`. Keep the Node port private; do not expose plain HTTP to the Internet. `/api/health` can be used for a health check.

## Connect the Windows apps

Place a `server-url.txt` beside both `furry-new-chat.exe` and `furry-admin.exe`. The file must contain only the HTTPS origin, for example `https://accounts.example.com` (no `/api` suffix). Use the same URL on every PC.

On the administrator PC only, place the same one-time bootstrap secret in `admin-setup-key.txt` beside `furry-admin.exe`. Launch `furry-admin.exe`, create the first administrator, then delete `admin-setup-key.txt`. Never put the bootstrap key in the public app or on public PCs.

The first admin account is created only once. Admin-created users and public signups are shared by every connected PC. Passwords are stored as salted PBKDF2 hashes; login sessions expire after 12 hours. Login attempts are rate-limited.

## Existing local accounts

Local `users.xml` accounts are not automatically uploaded. Recreate the needed accounts from the admin app after connecting it to the API, and assign new passwords. Existing conversation history remains on its original PC.

## Local development

For local-only development, omit `NODE_ENV=production` and use `http://127.0.0.1:8787` in `server-url.txt`. This is only for the same PC and must not be used for Internet traffic.