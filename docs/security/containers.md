# Container hardening

A container is only as isolated as its configuration. These settings decide whether a compromised app is stuck in
its container or owns the host.

## What makit checks (every running container)

| Rule | Severity | Finding |
| --- | --- | --- |
| MK-DOCKER-PRIVILEGED | critical | `privileged: true` — the container can do anything the host kernel allows. |
| MK-DOCKER-SOCK | critical | `/var/run/docker.sock` is mounted — whoever controls the container controls Docker, i.e. root on the host. |
| MK-DOCKER-HOST-NS | high | Host network/PID namespace (`network_mode: host`, `pid: host`). |
| MK-DOCKER-CAPS | high | Dangerous capabilities added (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, SYS_MODULE, DAC_READ_SEARCH…). |
| MK-DOCKER-ROOT | medium | The main process runs as root (uid 0) inside the container. |
| MK-DOCKER-TMP-EXEC | medium | `/tmp` is writable **and** executable — where droppers put their binaries. |
| MK-DOCKER-NO-NEW-PRIVS | low | `no-new-privileges` is not set. |
| MK-DOCKER-RW-ROOT | info | The root filesystem is writable. |

## A hardened service

```yaml
services:
  web:
    image: ghcr.io/acme/web@sha256:…          # pin by digest
    user: "10001:10001"                       # not root (set USER in the Dockerfile too)
    read_only: true                           # immutable root filesystem
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m  # writable, but nothing in it can run
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]               # only if it binds < 1024
    security_opt: [no-new-privileges:true]
    ports: ["127.0.0.1:3000:3000"]            # see docker-ports.md
    mem_limit: 1g
    pids_limit: 512
```

`read_only` needs every write location to be a volume or tmpfs (uploads, caches, `.next/cache`…). Start with
`tmpfs /tmp noexec` + `user` + `cap_drop` + `no-new-privileges`: they rarely break anything and block most of what
dropped malware does.

## Never

- Mount the Docker socket into an app container (CI runners, dashboards: give them their own host).
- Use `privileged` for an application.
- Run images you have not pinned from registries you do not trust.
