# Persistence

Malware that wants to survive a reboot or a cleanup registers itself somewhere that runs automatically.

## What makit checks

| Rule | Meaning |
| --- | --- |
| MK-DROPPER (start-up) | A cron job, systemd unit, rc.local or shell profile contains download-and-run commands. |
| MK-PERSIST-TEMP-EXEC | A start-up entry runs a program from `/tmp`, `/dev/shm` or a hidden directory. |
| MK-PERSIST-PRELOAD | `/etc/ld.so.preload` forces a library into every process — a classic rootkit technique; normally the file does not exist. |
| MK-PERSIST-RECENT | A cron job or systemd unit changed in the last 7 days — review it. |
| MK-PERSIST-SSH-KEYS | Authorized SSH keys; changed in the last 7 days = verify every key is yours. |

Places read: `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`, `/etc/crontabs` (Alpine), `/etc/systemd/system`,
user systemd units, `/etc/rc.local`, `/etc/init.d`, `/etc/profile(.d)`, shell rc files, `/etc/ld.so.preload`,
`authorized_keys`.

## Fix

Do not just delete the entry: first keep a copy as evidence and find how it got there. Then follow
[incident response](incident-response.md).
