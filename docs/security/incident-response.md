# Incident response

You have a critical or high finding. In this order:

1. **Keep evidence before touching anything.**
   - Copy suspicious files: `cp -a /path/to/file /root/evidence/`.
   - For a running process, the executable can be recovered even if it was deleted:
     `cp /proc/<pid>/exe /root/evidence/<pid>.bin`, and note `cat /proc/<pid>/cmdline | tr '\0' ' '`,
     `ls -l /proc/<pid>/cwd`, `ss -tnp | grep <pid>`.
   - Save `makit scan --json --consent > /root/evidence/scan.json`.
   - Check the hash on VirusTotal (upload the hash, not necessarily the file).
2. **Contain.** Stop the container (`docker stop`) or isolate the server (provider firewall: deny all except your IP).
   Do not just `kill` the process and delete the file: persistence will bring it back.
3. **Find the entry point.** Web framework or dependency (`makit scan` → MK-VULN), leaked SSH key, exposed database,
   weak password. Patch it before rebuilding.
4. **Rebuild from clean images** and redeploy; for a host compromise, reinstall the server rather than cleaning it.
5. **Rotate every secret** the compromised machine or container could read: database passwords, JWT/session
   secrets, API keys, SSH keys, cloud tokens.
6. **Report** abuse to the attacker's hosting provider (IP owner from `whois`), and to your users if data was exposed
   (legal obligations vary by country).
7. **Learn**: add the indicators to your catalog (`--rules DIR`, or contribute them to makit's `security/`).

The React2Shell analysis shows the whole cycle on a real case:
https://github.com/ngvcanh/CVE-2025-55182-Attack-Analysis
