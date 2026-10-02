# Vulnerable dependencies

The React2Shell attack (CVE-2025-55182) did not use an OS bug: it used the web framework. Application dependencies
are the most common way in, and OS updates do not touch them.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-VULN | An installed package version is affected by an advisory of the [catalog](../../security/README.md) (OSV format). Severity comes from the advisory. |

Today makit inventories **npm** packages (`node_modules`, pnpm stores) in app directories on the host and in each
container. More ecosystems will follow.

## Fix

1. Upgrade to the fixed version shown in the finding (or later in your release line).
2. Rebuild the image and redeploy — upgrading the lockfile alone does not change running containers.
3. If the vulnerability allowed code execution and the app was exposed while vulnerable: assume compromise, run
   `makit scan --all-containers --host`, and follow [incident response](incident-response.md) (rotate secrets).

## Stay ahead

- `makit rules update` pulls new advisories from the makit catalog; `makit schedule scan` runs the check daily.
- Subscribe to the security advisories of your framework (GitHub "Watch → Security alerts").
- Use your package manager's audit (`npm audit`, `pnpm audit`) in your build.
