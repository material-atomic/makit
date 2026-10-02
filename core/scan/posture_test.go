package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/material-atomic/makit/core/sys"
)

func ids(is []issue) map[string]string {
	m := map[string]string{}
	for _, i := range is {
		m[i.id] = i.ev
	}
	return m
}

func TestSSHIssues(t *testing.T) {
	got := ids(sshIssues(parseKV("passwordauthentication yes\npermitrootlogin yes\nmaxauthtries 6\nlogingracetime 120\nx11forwarding yes\n")))
	for _, id := range []string{"MK-SSH-PASSWORD", "MK-SSH-ROOT-PASSWORD", "MK-SSH-WEAK-SETTINGS"} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s", id)
		}
	}
	if len(sshIssues(parseKV("passwordauthentication no\npermitrootlogin prohibit-password\nmaxauthtries 4\nlogingracetime 30\nx11forwarding no\n"))) != 0 {
		t.Error("hardened sshd reported")
	}
}

func TestContainerIssues(t *testing.T) {
	var c inspection
	c.HostConfig.Privileged = true
	c.HostConfig.NetworkMode = "host"
	c.HostConfig.CapAdd = []string{"CAP_SYS_ADMIN", "NET_BIND_SERVICE"}
	c.Mounts = append(c.Mounts, struct {
		Source      string
		Destination string
	}{"/var/run/docker.sock", "/var/run/docker.sock"})
	c.NetworkSettings.Ports = map[string][]struct {
		HostIp   string
		HostPort string
	}{"5432/tcp": {{"0.0.0.0", "5432"}}, "6379/tcp": {{"127.0.0.1", "6379"}}, "80/tcp": {{"0.0.0.0", "80"}}}
	got := ids(containerIssues(c, 0, true))
	for _, id := range []string{"MK-DOCKER-PRIVILEGED", "MK-DOCKER-SOCK", "MK-DOCKER-HOST-NS", "MK-DOCKER-CAPS", "MK-DOCKER-ROOT", "MK-DOCKER-TMP-EXEC", "MK-DOCKER-RW-ROOT", "MK-NET-PUBLIC-SERVICE"} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s", id)
		}
	}
	if !strings.Contains(got["MK-NET-PUBLIC-SERVICE"], "5432") || strings.Contains(got["MK-NET-PUBLIC-SERVICE"], "6379") {
		t.Errorf("public ports: %q", got["MK-NET-PUBLIC-SERVICE"])
	}
	if strings.Contains(got["MK-DOCKER-CAPS"], "NET_BIND_SERVICE") {
		t.Error("harmless capability reported")
	}

	var good inspection
	good.HostConfig.ReadonlyRootfs = true
	good.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	if is := containerIssues(good, 10001, false); len(is) != 0 {
		t.Errorf("hardened container reported: %+v", is)
	}
}

func TestTmpExecutable(t *testing.T) {
	noexec := "36 35 0:31 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=65536k\n"
	if tmpExecutable(noexec, false) {
		t.Error("noexec tmpfs reported executable")
	}
	if !tmpExecutable("36 35 0:31 / /tmp rw,relatime - tmpfs tmpfs rw\n", true) {
		t.Error("exec tmpfs reported safe")
	}
	if tmpExecutable("1 0 0:1 / / ro - overlay overlay ro\n", true) || !tmpExecutable("1 0 0:1 / / rw - overlay overlay rw\n", false) {
		t.Error("root filesystem rule")
	}
}

func TestHostHelpers(t *testing.T) {
	if got := execTmpMounts("tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n/dev/vda1 / ext4 rw 0 0\n"); len(got) != 1 || got[0] != "/dev/shm" {
		t.Errorf("tmp mounts %v", got)
	}
	if n := securityUpdates("Inst libssl3 [3.0.2] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])\nInst tzdata [2024a] (2024b Ubuntu:22.04/jammy-updates [all])\n"); n != 1 {
		t.Errorf("security updates %d", n)
	}
	if r := dockerUserRules("-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n"); len(r) != 0 {
		t.Errorf("default chain %v", r)
	}
	if r := dockerUserRules("-N DOCKER-USER\n-A DOCKER-USER -j ufw-user-forward\n-A DOCKER-USER -j RETURN\n"); len(r) != 1 {
		t.Errorf("makit chain %v", r)
	}

	root := t.TempDir()
	write(t, root, "proc/sys/kernel/kptr_restrict", "0\n")
	write(t, root, "proc/sys/fs/suid_dumpable", "2\n")
	write(t, root, "proc/sys/net/ipv4/tcp_syncookies", "1\n")
	if miss := missingSysctls(sys.Root(root)); len(miss) != 2 {
		t.Errorf("sysctls %v", miss)
	}

	dir := t.TempDir()
	tcp := "  sl  local_address rem_address   st\n" +
		"   0: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 111 1\n" +
		"   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 112 1\n"
	write(t, dir, "tcp", tcp)
	ls := listeners(filepath.Join(dir, "tcp"))
	if len(ls) != 2 || !ls[0].public || ls[0].port != 5432 || ls[1].public {
		t.Errorf("listeners %+v", ls)
	}

	sec := t.TempDir()
	write(t, sec, "srv/app/.env", "DB_PASSWORD=x")
	write(t, sec, "srv/app/.env.example", "DB_PASSWORD=")
	write(t, sec, "srv/other/.env", "X=1")
	if err := os.Chmod(filepath.Join(sec, "srv/other/.env"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := secretFiles(sys.Root(sec), []string{"/srv"}); len(got) != 1 || got[0].path != "/srv/app/.env" {
		t.Errorf("secret files %+v", got)
	}
}

// Every documented rule must point to an existing page and heading, so links printed on servers never break.
func TestDocsExist(t *testing.T) {
	c := loadRepoCatalog(t)
	docs := map[string]string{}
	for id, ch := range c.Checks {
		docs[id] = ch.Doc
	}
	for id, r := range c.Rules {
		docs[id] = r.Doc
	}
	heading := regexp.MustCompile(`(?m)^#+ (.+)$`)
	for id, d := range docs {
		if d == "" {
			t.Errorf("%s has no doc", id)
			continue
		}
		file, anchor, _ := strings.Cut(d, "#")
		b, err := os.ReadFile(filepath.Join("..", "..", file))
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if anchor == "" {
			continue
		}
		found := false
		for _, h := range heading.FindAllStringSubmatch(string(b), -1) {
			slug := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(h[1])), " ", "-")
			slug = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(slug, "")
			if slug == anchor {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no heading #%s in %s", id, anchor, file)
		}
	}
	if u := docURL("docs/security/ssh.md"); !strings.HasSuffix(u, "/docs/security/ssh.md") {
		t.Errorf("doc url %s", u)
	}
}
