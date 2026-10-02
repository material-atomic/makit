# Temporary directories

Droppers write their payload where anyone can write — `/tmp`, `/var/tmp`, `/dev/shm` — and run it from there. If those
places are mounted `noexec`, the binary cannot start.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-HOST-TMP-EXEC | `/dev/shm` (or `/tmp`, when it is a separate mount) allows executing files. |

Inside containers, the same idea is MK-DOCKER-TMP-EXEC — see [containers](containers.md) (`tmpfs: /tmp:noexec`).

## Fix

```bash
makit harden                 # /dev/shm → noexec,nosuid,nodev (fstab + remount)
makit harden --tmp-noexec    # also mount /tmp as tmpfs noexec,nosuid,nodev
```

`/tmp noexec` is opt-in because some installers build or run helpers in `/tmp` (node-gyp, a few vendor installers).
If one fails, run it with `TMPDIR=/var/tmp/build` (create it first) or temporarily `mount -o remount,exec /tmp`.

`noexec` does not stop `sh /tmp/x.sh` or `python /tmp/x.py` (the interpreter is elsewhere); it stops binaries like
`/tmp/vim`, which is what the common droppers use.
