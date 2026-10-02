// Package scan is `makit scan`: a read-only search for malware dropped on a host or inside containers.
// It never writes, deletes, moves, quarantines or uploads anything — it only reports.
package scan

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/material-atomic/makit/core/sys"
)

var Version = "dev"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// target is one filesystem to inspect: the host ("/") or a container's root seen from the host.
type target struct {
	name    string // host, container:<name>
	root    string // "/" or /proc/<pid>/root
	workdir string
	changed []string // container paths added/changed since the image (docker diff)
}

type scanner struct {
	cat     *Catalog
	rep     *Report
	maxSize int64
	extra   []string
	hashes  map[string]string // path → sha256 (cache)
	contOf  map[string]string // cgroup container id → name
}

func Main(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var containers, ruleDirs, paths multi
	fs.Var(&containers, "container", "scan this container (name or id); repeatable")
	allContainers := fs.Bool("all-containers", false, "scan every running container")
	host := fs.Bool("host", false, "also scan the host when --container/--all-containers is given (default: host only)")
	fs.Var(&ruleDirs, "rules", "extra security catalog directory (rules/*.yaml, vulns/*.json); repeatable, overrides same ids")
	fs.Var(&paths, "path", "extra directory to scan on every target; repeatable")
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	consent := fs.Bool("consent", false, "confirm consent non-interactively (for automation)")
	maxMB := fs.Int64("max-file-mb", 64, "skip hashing/reading files bigger than this")
	showRules := fs.Bool("list-rules", false, "print the catalog in use (sources, checks, rules, vulnerabilities) and exit")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `makit scan [options] — read-only malware check (host and/or containers). Reports only; changes nothing.

`)
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, "\nExit status: 0 nothing above LOW, 1 MEDIUM or worse found, 2 error, 3 consent not given.\n")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cat, err := LoadCatalog(append(CatalogDirs(), ruleDirs...))
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalog:", err)
		return 2
	}
	if *showRules {
		if *jsonOut {
			b, _ := json.MarshalIndent(cat, "", "  ")
			fmt.Println(string(b))
		} else {
			cat.Print(os.Stdout)
		}
		return 0
	}

	docker := sys.NewDocker("/var/run/docker.sock")
	var targets []target
	if len(containers) == 0 && !*allContainers {
		*host = true
	}
	if *host {
		targets = append(targets, target{name: "host", root: "/"})
	}
	if *allContainers || len(containers) > 0 {
		ts, err := containerTargets(docker, containers, *allContainers)
		if err != nil {
			fmt.Fprintln(os.Stderr, "containers:", err)
			return 2
		}
		targets = append(targets, ts...)
	}

	if !askConsent(targets, *consent) {
		fmt.Fprintln(os.Stderr, "Scan not started: consent not given.")
		return 3
	}

	hostname, _ := os.Hostname()
	op := os.Getenv("SUDO_USER")
	if op == "" {
		if u, err := user.Current(); err == nil {
			op = u.Username
		}
	}
	rep := &Report{Version: Version, Started: time.Now(), Host: hostname, Operator: op, Catalog: cat.Sources}
	for _, t := range targets {
		rep.Targets = append(rep.Targets, t.name)
	}
	if os.Geteuid() != 0 {
		rep.Notes = append(rep.Notes, "not running as root: other users' processes, sockets and files were not visible — run with sudo for a full scan")
	}
	s := &scanner{cat: cat, rep: rep, maxSize: *maxMB << 20, extra: paths, hashes: map[string]string{}, contOf: map[string]string{}}
	if cs, err := docker.Containers(); err == nil {
		for _, c := range cs {
			s.contOf[c.ID] = c.Name
		}
	}

	progress := func(msg string) {
		if !*jsonOut {
			fmt.Fprintf(os.Stderr, "  … %s\n", msg)
		}
	}
	progress("processes and network connections")
	s.processes(*host, targets)
	for _, t := range targets {
		progress("files on " + t.name)
		s.files(t)
		progress("persistence on " + t.name)
		s.persistence(t)
		progress("Next.js / React versions on " + t.name)
		s.packages(t)
	}
	rep.Finished = time.Now()
	rep.sort()

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		fi, _ := os.Stdout.Stat()
		rep.Print(os.Stdout, fi != nil && fi.Mode()&os.ModeCharDevice != 0)
	}
	if rep.worst() >= Medium {
		return 1
	}
	return 0
}

func askConsent(targets []target, given bool) bool {
	fmt.Fprintln(os.Stderr, `
makit scan — read-only malware check

It will READ:
  · every running process: its command line, executable (hashed) and open network connections
  · files in temporary and home directories (/tmp, /var/tmp, /dev/shm, /root, /home, /run), extra --path dirs
  · start-up locations: cron, systemd units, /etc/rc.local, /etc/ld.so.preload, shell profiles
  · installed Next.js / React packages (CVE-2025-55182)`)
	for _, t := range targets {
		if t.name != "host" {
			fmt.Fprintf(os.Stderr, "  · %s: its filesystem (from the host, via %s) and the files changed since its image\n", t.name, t.root)
		}
	}
	fmt.Fprint(os.Stderr, `
makit will NOT modify, delete, move, quarantine, execute or upload anything. Findings are only printed.

`)
	if given {
		fmt.Fprintln(os.Stderr, "Consent given with --consent.")
		return true
	}
	if fi, _ := os.Stdin.Stat(); fi == nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "No terminal to ask for consent: re-run interactively or pass --consent.")
		return false
	}
	fmt.Fprint(os.Stderr, "Type 'yes' to allow this scan: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line)) == "yes"
}

// CatalogDirs are the default catalog sources, in order: bundled with this makit, then the updated copy.
// MAKIT_SECURITY (colon-separated) replaces them.
func CatalogDirs() []string {
	if v := os.Getenv("MAKIT_SECURITY"); v != "" {
		return strings.Split(v, ":")
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil { // <prefix>/libexec/makit-core → <prefix>/security
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			dirs = append(dirs, filepath.Join(filepath.Dir(real), "..", "security"))
		}
	}
	return append(dirs, "/var/lib/makit/security")
}
