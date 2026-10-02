# AppArmor

AppArmor confines programs to the files and capabilities their profile allows. Docker applies its `docker-default`
profile to every container when AppArmor is enabled — a free extra wall around containers.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-APPARMOR-OFF | AppArmor is not enabled in the kernel. |

## Fix

```bash
makit harden            # installs apparmor + apparmor-utils and enables the service
aa-status               # loaded profiles; containers show as docker-default
```

If the kernel boots with AppArmor disabled (`apparmor=0` or another LSM), enabling it needs a reboot after updating
the boot parameters — makit tells you when that is the case.
