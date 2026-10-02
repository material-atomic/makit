# Security updates

Known vulnerabilities in the OS (OpenSSL, glibc, sudo, the kernel) are fixed by the distribution within days. A
server that does not install them stays exploitable with public exploits.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-UPDATES-AUTO-OFF | Unattended security upgrades are not enabled. |
| MK-UPDATES-PENDING | Security updates are waiting to be installed. |
| MK-UPDATES-REBOOT | A kernel or libc update needs a reboot to take effect. |

## Fix

```bash
makit updates                 # unattended-upgrades for security updates
makit system-upgrade          # install what is pending now (--full for kernels)
```

Reboots stay manual: plan them (e.g. weekly), after `makit system-upgrade --full`, or use a livepatch service.
Applications in containers are not covered — see [dependencies](dependencies.md).
