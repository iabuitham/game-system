# Game Announcer 

This is a premium, event-ready version of the Game Announcer app (operator + announcement screens) with upgraded UI/UX:
- Tailwind CSS for modern responsive UI
- GSAP animations for smooth transitions
- Canvas-confetti for celebratory effects
- Audio feedback during prize reveal and operator actions

## Quick Start

Requirements:
- Node.js v18+ and npm

1. Install dependencies:
```bash
npm install
```

2. Seed the database (creates 9 games with device IDs and secrets):
```bash
npm run init-db
```
Look at the console output — it prints seeded device IDs and their secrets (OP-1..OP-9 and SC-1..SC-9).

3. Start the server:
```bash
npm start
```

4. Open the UIs:
- Operator: `http://localhost:3000/operator.html`
- Announcement screen: `http://localhost:3000/announcement.html`

## Features
- Real-time updates via Socket.IO.
- Idle media rotation on announcement screens (images/videos).
- Prize reveal animation with confetti and sound.
- Auto-login support via localStorage (useful with quick-login flow).

## Files
- `server.js` — backend server
- `db/init-db.js` — seeding script
- `public/` — front-end assets and media
- `package.json` — deps & scripts

## Notes
- Replace sample media in `public/media/` with your own high-resolution assets.
- For production, set `JWT_SECRET` and `ADMIN_SECRET` environment variables.
- Consider using HTTPS and a reverse proxy for public deployments.



---
## Deployment (Docker, production-ready)

This repo includes Docker and nginx setup so you can deploy the app with HTTPS using Let's Encrypt.
Files added for deployment:
- `Dockerfile` — Node app container.
- `docker-compose.yml` — runs `app` (Node) and `nginx` reverse-proxy and sets up volumes for certs.
- `nginx/conf.d/default.conf` — nginx config that proxies to the Node app and serves certbot ACME challenge webroot.
- `.env.example` — environment variables for production.

### Quick deploy (example for `example.com`)

1. Copy `.env.example` to `.env` and update values (especially `DOMAIN` and secrets):
   ```bash
   cp .env.example .env
   # edit .env and set DOMAIN, JWT_SECRET, ADMIN_SECRET, etc.
   ```

2. Build and start the containers:
   ```bash
   docker compose up -d --build
   ```

3. Obtain TLS certificates with certbot (one-time):
   ```bash
   docker compose run --rm certbot certonly --webroot --webroot-path=/var/www/certbot -d your.domain.com --email admin@your.domain.com --agree-tos --no-eff-email
   ```
   After certs are obtained, reload nginx:
   ```bash
   docker compose exec nginx nginx -s reload
   ```

4. Access your site at: `https://your.domain.com` (nginx will reverse-proxy to the Node app).

### Notes & production tips
- Set strong `JWT_SECRET` and `ADMIN_SECRET` in the `.env` file or Docker secrets.
- Use a managed volume for `/etc/letsencrypt` to preserve certs across restarts.
- For automatic renewals, create a scheduled job (host cron or container) to run certbot renew and reload nginx.
- Consider using Traefik for automatic certificate management if you scale to more services.
#
