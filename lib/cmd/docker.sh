# shellcheck shell=bash
cmd_docker() {
  [[ ${1:-} == --help ]] && { echo "makit docker — Docker Engine + Compose plugin from download.docker.com; caps json-file logs at 3 x 20 MB unless /etc/docker/daemon.json exists."; return; }
  require_root; require_supported_os
  step "Docker"
  if have docker; then
    ok "already installed: $(docker --version 2>/dev/null)"
  else
    # Derivatives (Mint, Pop!_OS…) use their Ubuntu/Debian base repo.
    local repo=ubuntu codename=${UBUNTU_CODENAME:-$OS_CODENAME}
    if [[ $OS_ID == debian || ( -z ${UBUNTU_CODENAME:-} && ${ID_LIKE:-} == *debian* && $OS_ID != ubuntu ) ]]; then repo=debian; codename=$OS_CODENAME; fi
    [[ -n $codename ]] || die "Cannot tell the distribution codename for the Docker repository."
    run install -m 0755 -d /etc/apt/keyrings
    run sh -c "curl -fsSL https://download.docker.com/linux/$repo/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg"
    run chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$repo $codename stable" \
      | write_file /etc/apt/sources.list.d/docker.list
    run apt-get update -qq
    apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ok "Docker installed"
  fi
  # Unbounded container logs fill the disk after a few months, and the symptom looks like a broken database.
  if [[ -f /etc/docker/daemon.json ]]; then
    if have jq && jq -e '."log-opts"."max-size"' /etc/docker/daemon.json >/dev/null 2>&1; then ok "container logs already capped"
    else warn "/etc/docker/daemon.json exists without log limits — left untouched; add \"log-opts\": {\"max-size\": \"20m\", \"max-file\": \"3\"}"; fi
  else
    write_file /etc/docker/daemon.json <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "20m", "max-file": "3" }
}
JSON
    run systemctl restart docker
    ok "container logs capped at 3 x 20 MB"
  fi
  run systemctl enable --now docker >/dev/null 2>&1 || true
}
