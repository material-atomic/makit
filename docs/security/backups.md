# Backups

Backups are the last line of defence: against ransomware, a wrong `rm`, a broken migration, or an attacker who
deletes data on the way out. makit does not run backups; this page is the checklist.

- **3-2-1**: three copies, two kinds of storage, one **off the server** (and off the provider account if you can).
- **Immutable**: use object storage with object lock / versioning (S3, B2, R2) so a compromised server cannot delete
  old backups. The server's credentials should only be able to *write*.
- **Encrypted** before it leaves the server (restic, borg, or your database's tool + age/gpg).
- **Tested**: restore to a scratch server every quarter. An untested backup is a hope.
- **Scope**: databases (logical dumps), uploaded files/object storage, `.env` and configuration, TLS keys if not
  re-issuable.
- **Retention**: e.g. 7 daily, 4 weekly, 6 monthly.
