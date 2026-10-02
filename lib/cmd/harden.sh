# shellcheck shell=bash
# docs/security/kernel.md, mounts.md, ssh.md, fail2ban.md, apparmor.md, logging.md
HARDEN_SYSCTLS=(
  kernel.kptr_restrict=2 kernel.dmesg_restrict=1 kernel.yama.ptrace_scope=1
  fs.protected_symlinks=1 fs.protected_hardlinks=1 fs.protected_fifos=2 fs.protected_regular=2 fs.suid_dumpable=0
  net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2
  net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0
  net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.all.accept_source_route=0 net.ipv4.tcp_syncookies=1
)
HARDEN_STEPS=(sysctl shm ssh fail2ban apparmor auditd)

cmd_harden() {
  local tmp=0 skip=" " a
  for a in "$@"; do
    case "$a" in
      --help) echo "makit harden [--tmp-noexec] [--skip STEP,…] — kernel settings, /dev/shm noexec, SSH limits, fail2ban sshd jail,
AppArmor, auditd (records programs run from /tmp, /var/tmp, /dev/shm). Steps: ${HARDEN_STEPS[*]}.
  --tmp-noexec   also mount /tmp as tmpfs noexec,nosuid,nodev (opt-in: some installers run code from /tmp)
Docs: makit docs kernel | mounts | ssh | fail2ban | apparmor | logging"; return ;;
      --tmp-noexec) tmp=1 ;;
      --skip=*) skip+="${a#--skip=}" ; skip=" ${skip//,/ } " ;;
      *) die "Unknown option: $a" ;;
    esac
  done
  require_root; require_supported_os
  [[ $skip == *" sysctl "* ]] || { step "Kernel hardening"; sysctl_set "${HARDEN_SYSCTLS[@]}"; }
  [[ $skip == *" shm "* ]] || harden_shm
  [[ $tmp -eq 1 ]] && harden_tmp
  [[ $skip == *" ssh "* ]] || harden_ssh
  [[ $skip == *" fail2ban "* ]] || harden_fail2ban
  [[ $skip == *" apparmor "* ]] || harden_apparmor
  [[ $skip == *" auditd "* ]] || harden_auditd
  return 0
}

harden_shm() {
  step "/dev/shm: noexec,nosuid,nodev"
  if grep -qE '^[^#]*[[:space:]]/dev/shm[[:space:]].*noexec' /etc/fstab; then ok "already in /etc/fstab"
  else
    run sed -i.makit-bak '/^[^#]*[[:space:]]\/dev\/shm[[:space:]]/d' /etc/fstab
    run sh -c 'echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab'
  fi
  run mount -o remount,noexec,nosuid,nodev /dev/shm && ok "/dev/shm remounted"
}

harden_tmp() {
  step "/tmp: tmpfs noexec,nosuid,nodev"
  local unit=/usr/share/systemd/tmp.mount
  [[ -f $unit || -f /lib/systemd/system/tmp.mount ]] || { warn "systemd tmp.mount not available — skipped"; return 0; }
  write_file /etc/systemd/system/tmp.mount.d/makit.conf <<'CONF'
# Managed by makit (makit harden --tmp-noexec)
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=25%
CONF
  [[ -f /etc/systemd/system/tmp.mount || -f /lib/systemd/system/tmp.mount ]] || run cp "$unit" /etc/systemd/system/tmp.mount
  run systemctl daemon-reload
  warn "files currently in /tmp are hidden under the new mount until it is unmounted"
  run systemctl enable --now tmp.mount && ok "/tmp is tmpfs noexec (TMPDIR=/var/tmp/build for installers that need exec)"
}

harden_ssh() {
  step "SSH limits"
  have sshd || { info "no SSH server — skipped"; return 0; }
  local f=/etc/ssh/sshd_config.d/01-makit-harden.conf
  write_file "$f" <<'CONF'
# Managed by makit (makit harden). See docs/security/ssh.md
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
CONF
  [[ $MAKIT_DRY -eq 1 ]] && return 0
  if ! sshd -t; then rm -f "$f"; warn "sshd rejected the limits — reverted"; return 0; fi
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  ok "MaxAuthTries 4, LoginGraceTime 30, X11Forwarding no"
}

harden_fail2ban() {
  step "fail2ban: sshd jail"
  have sshd || { info "no SSH server — skipped"; return 0; }
  have fail2ban-client || apt_install fail2ban
  dpkg-query -W python3-systemd >/dev/null 2>&1 || apt_install python3-systemd
  write_file /etc/fail2ban/jail.d/makit.conf <<'CONF'
# Managed by makit (makit harden). See docs/security/fail2ban.md
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
CONF
  run systemctl enable fail2ban >/dev/null 2>&1 || true
  run systemctl restart fail2ban && ok "fail2ban running with the sshd jail"
}

harden_apparmor() {
  step "AppArmor"
  have aa-status || apt_install apparmor apparmor-utils
  run systemctl enable --now apparmor >/dev/null 2>&1 || true
  if [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]]; then ok "AppArmor enabled"
  else warn "AppArmor is not enabled in the kernel: add 'apparmor=1 security=apparmor' to the boot parameters and reboot"; fi
}

harden_auditd() {
  step "auditd: programs run from temporary directories, identity/SSH/cron changes"
  have auditctl || apt_install auditd
  local rules="# Managed by makit (makit harden). See docs/security/logging.md" p
  for p in /tmp /var/tmp /dev/shm; do [[ -e $p ]] && rules+=$'\n'"-w $p -p x -k makit_tmp_exec"; done
  for p in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k makit_identity"; done
  for p in /etc/ssh/sshd_config /etc/ssh/sshd_config.d /root/.ssh; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k makit_sshd"; done
  for p in /etc/crontab /etc/cron.d /var/spool/cron /etc/systemd/system; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k makit_cron"; done
  printf '%s\n' "$rules" | write_file /etc/audit/rules.d/makit.rules 0640
  run systemctl enable --now auditd >/dev/null 2>&1 || true
  if [[ $MAKIT_DRY -eq 0 ]]; then
    if augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/makit.rules >/dev/null 2>&1; then ok "audit rules loaded (ausearch -k makit_tmp_exec -i)"
    else warn "auditd rules saved but not loaded (no audit support in this kernel/container?)"; fi
  fi
}
