# Secrets

Database passwords, API keys and signing secrets usually sit in `.env` files next to the compose file. If other
users (or a compromised low-privilege service) can read them, they get everything the app can reach.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-SECRET-PERMS | A `.env`-style file (`.env`, `.env.*`, `*.env`) in an app directory is readable by other users. |

App directories searched: `/srv`, `/opt`, `/app`, `/var/www`, `/root`, `/home` (4 levels), container working
directories and `--path` directories.

## Fix

```bash
chmod 600 /srv/app/.env && chown root:root /srv/app/.env
```

## Practices

- One secret per purpose, least privilege (the app's DB user is not the superuser).
- Never bake secrets into images (`docker history` shows them); pass them at runtime.
- Rotate everything the server could read after any compromise ([incident response](incident-response.md)).
- Keep a copy of production secrets in a password manager, not only on the server.
