# NGINX2SHELL IMPACT ANALYSIS

CVE-2026-123007 and CVE-2026-123633 | Heap bugs in nginx's HTTP/2 code (worker crash, memory corruption, code execution as the worker user) | F5 CVSS 3.1: 8.1, CVSS 4.0: 9.2 | Fixed in nginx 1.31.9 and 1.30.7

Data cut-off: 19 November 2026, 04:30 UTC. Things are still moving, so check NVD, CISA KEV, EPSS and your distro or vendor advisory again before you act on anything here.

---

## EXECUTIVE SUMMARY

### The situation at a glance

- **What:** Two separate bugs in ngx_http_v2_module, the HTTP/2 module of nginx. F5 is the CNA for both records and says for both: "There is no control plane exposure; this is a data plane issue only." CVE-2026-123007 is a flow control window flaw. F5 says the window "can exceed the allowed threshold, potentially resulting in a heap buffer overflow typically followed by an NGINX worker segmentation fault" (CWE-191 and CWE-787). nginx.org calls it "Memory corruption in HTTP/2 flow control". CVE-2026-123633 is a use-after-free in the worker process (CWE-416), and nginx.org calls it "Use-after-free in HTTP/2". "Heap" is F5's word for CVE-2026-123007. Calling CVE-2026-123633 a heap bug is our reading, because a use-after-free is freed heap memory. The fixes are two nginx commits by Roman Arutyunyan: "HTTP/2: account for queued frames when validating WINDOW_UPDATE" for CVE-2026-123007, and "HTTP/2: reset reusable connection status on stream creation" for CVE-2026-123633.
  - Naming note: NGINX2Shell is the name this analysis uses for the two bugs. The name is already in public use (nginx2shell.com, a Hacker News story). Xint uses "nginx2root" for five nginx CVEs plus a separate Linux kernel bug, and Metnir uses "Drainbreak" for CVE-2026-123633. F5, nginx.org and the CVE records give the bugs no nickname.
  - Credit, CVE-2026-123007 (F5's wording from its K-article, WEAK, trimmed): "F5 acknowledges Rapid7 Senior Principal Researcher Stephen Fewer, Tomer Schwartz at Wiz Research, Xint.io, and Ikotas Labs, Inc. (@ikotas00) for bringing this issue to our attention and following the highest standards of coordinated disclosure."
  - Credit, CVE-2026-123633 (F5's wording from its K-article, WEAK): "F5 acknowledges Albert Ebb of Metnir (metnir.com), Nir Ohfeld at Wiz Research, and Xint.io for bringing this issue to our attention and following the highest standards of coordinated disclosure."
- **Risk level:** CRITICAL for internet-facing nginx on an affected version with HTTP/2 switched on and reachable over HTTP/2. That includes servers behind a CDN that speaks HTTP/2 to the origin, and products that turn HTTP/2 on by default (community ingress-nginx, Kong, Apache APISIX). HIGH for internal servers with HTTP/2 on. Servers with HTTP/2 off are not exposed to these two bugs, but should still upgrade, because the same release fixes 10 advisories, including bugs outside HTTP/2 (HTTP/3, resolver, mail proxy). F5 scores both bugs CVSS 3.1 8.1 (High) and CVSS 4.0 9.2 (Critical). nginx.org rates CVE-2026-123007 major and CVE-2026-123633 only medium. The CRITICAL tier is our reading. It rests on how exposed the HTTP/2 code is to untrusted input, not on proven exploitability.
- **Impact:** F5 says an attacker could "crash the NGINX worker process, corrupt its memory, or potentially execute code remotely" (CVE-2026-123007), and that CVE-2026-123633 may allow remote attackers "to cause a denial-of-service (DoS) on the NGINX system or may allow a code execution". The attacker needs only network access to a listener with HTTP/2 on: no login and no user action (AV:N, PR:N, UI:N). Attack complexity is High in both CVSS versions. Code execution is conditional. F5: "attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR." Our reading: a worker crash is the usual outcome of a failed attempt, and code execution is the harder outcome. Code that an attacker gets running would run as the nginx worker user (nginx, www-data or nobody, depending on the build), not as root. Xint says it reached root only by chaining CVE-2026-123007 with a separate Linux kernel flaw. We could not verify that (COULD NOT VERIFY). Wiz, Rapid7 and Metnir claim no root. All code execution results so far are lab results from the researchers.
- **Status:** Fixed upstream in nginx 1.31.9 (mainline) and 1.30.7 (stable), released on 18 November 2026. NGINX Plus 37.3.0.1 and 37.0.8.1 fix both bugs (inferred). There is no fixed release on older branches (inferred): nginx before 1.30 and NGINX Plus R33 to R36 have to move to a fixed release. Fixed builds exist in the nginx.org repositories, the Docker official image, Alpine edge, 3.24, 3.23 and 3.22, Amazon Linux 2023, Amazon Linux 2 (Nginx1 Extra) and 2027 Preview, AlmaLinux 9 and 10, Debian sid, Arch Linux, Homebrew, FreeBSD ports, Heroku, F5 NGINX Ingress Controller v5.8.0 and the open source image of NGINX Gateway Fabric v2.9.0. At the cut-off there was no fixed package from Debian stable and testing, Ubuntu, Red Hat, SUSE, Rocky Linux, AlmaLinux 8, Alpine 3.21 or the nginxinc/nginx-unprivileged image. freenginx, Angie, OpenResty, Tengine, Kong OSS and community ingress-nginx (retired, no fix expected) had shipped no fix either. No exploitation in the wild had been reported as of about 04:30 UTC on 19 November, 13.5 hours after disclosure, and neither CVE is in CISA's Known Exploited Vulnerabilities catalog (KEV). Rapid7 published a proof of concept for CVE-2026-123007, and its own notes limit it to a freshly started container. More public exploit code has appeared since: one repository claims a full code execution chain, Censys Research published proof-of-concept material, and HKCERT says a proof of concept is public. None of that code is verified. Wiz, Xint and Metnir still withhold their exploits, so no proof of concept from them is public for CVE-2026-123633.
- **Who's safe:** Servers on nginx 1.31.9 or 1.30.7, NGINX Plus 37.3.0.1 or 37.0.8.1, or a distro package that carries the fix, that have restarted since the upgrade. A reload is not enough: Xint says "A configuration reload alone does not replace the running executable." Servers with HTTP/2 off are not exposed to these two bugs. That means the HTTP/2 module is not compiled in (`nginx -V` shows `--with-http_v2_module` when it is), or no listener has HTTP/2 switched on. Stock default configurations ship with HTTP/2 off (inferred from the shipped files). nginx older than 1.9.5 has no HTTP/2 module, and nginx from 1.9.5 to 1.19.6 is outside CVE-2026-123633 (but not CVE-2026-123007). A server that only serves static files is outside CVE-2026-123633 (our reading of F5's wording) but not outside CVE-2026-123007: Wiz (secondary, a lab claim that is not in F5's text) says its test of that bug demonstrated code execution on nginx serving ordinary static files. F5's advisories list BIG-IP, BIG-IQ, F5OS, BIG-IP Next and CNF as not vulnerable (WEAK, read through a browser render).
- **Who's at risk:** Any server on an affected version, or on a distro package with no fix, that has the HTTP/2 module compiled in and HTTP/2 switched on for a listener that untrusted clients can reach. The packages compile the module in (inferred from build files): nginx.org packages, the Docker official image, Debian, Ubuntu, the RHEL family and Alpine. So one admin edit is enough (`http2 on;` or the legacy `http2` parameter on a `listen` line). Some products switch it on for you: community ingress-nginx, Kong and Apache APISIX default to HTTP/2 on. A CDN that speaks HTTP/2 to your origin leaves the origin's HTTP/2 code reachable (our reading), and Cloudflare does that by default on Free, Pro and Business plans, for origins that announce HTTP/2. Whether either bug can be triggered through such a proxy is unknown, because no source tested it. Worst off are the platforms with no fixed release: community ingress-nginx (retired), nginx before 1.30, NGINX Plus R33 to R36, the nginxinc/nginx-unprivileged image, OpenResty, Kong OSS and any distro package still waiting for a fix. Metnir says it reproduced the CVE-2026-123633 use-after-free in OpenResty and crashed the shipped binaries of Kong, Apache APISIX, NGINX Gateway Fabric and community ingress-nginx.

*Sources: nginx.org security advisories page, CHANGES file and fix commits, F5 advisories K000163926 and K000163928 (script pages read through a browser render, so WEAK) and F5 CVE records, NVD, CISA ADP entry and SSVC data, CISA KEV feed, FIRST EPSS API, Debian, Ubuntu, Red Hat, SUSE, Rocky Linux, AlmaLinux and Amazon Linux security pages, Alpine, Arch, Homebrew, FreeBSD, Heroku and Docker Hub package pages, F5 and nginx.org release pages, nginx, Kong, Apache APISIX and ingress-nginx package and config files, Cloudflare documentation, Wiz, Rapid7, Xint, Metnir, CIRCL, Previdian, Hacker News, HKCERT, CCB Belgium (WEAK), the oss-security list, Qualys (WEAK), Tenable, The Register, Censys Research, VulnCheck*

### What this means for your organization

The bugs sit in the nginx module that speaks HTTP/2, so they are reached only over HTTP/2. That makes the first question for every nginx server whether the module is compiled in and whether HTTP/2 is switched on for any listener. A build without ngx_http_v2_module has no HTTP/2 code, and Xint says absent means not affected. Updating the application behind nginx doesn't fix the bugs. A fixed nginx build and a restart do.

Stock configurations ship with HTTP/2 off, and the table under Where HTTP/2 is switched on has the detail:

- Stock defaults. The `http2` directive defaults to off. The nginx source tree, the nginx.org packages, the Docker official image, Debian, Ubuntu, RHEL (CentOS Stream files) and Alpine all ship a plain `listen 80;` server. This is inferred from the shipped files, and nothing was run. Source builds don't compile the HTTP/2 module unless asked with `--with-http_v2_module`. The packages do compile it in.
- What switches it on. An admin edit: `http2 on;` in a server block (nginx 1.25.1 and later) or the legacy `http2` parameter on a `listen` line. Either one enables it, so `http2 off;` does not override a leftover `listen` parameter (inferred from the source). On a plain listener the same switch accepts cleartext HTTP/2 (h2c) from clients that send the HTTP/2 preface first (inferred). No source says whether the bugs are reachable over h2c, so treat it as exposed.
- Products that turn it on. Community ingress-nginx has the ConfigMap key `use-http2` set to "true" by default. The project was retired and archived on 24 March 2026 with "no further releases, no bugfixes, and no updates to resolve any security vulnerabilities", so no fixed controller is expected. Kong's default listen strings carry `http2` on the 8443 and 8444 listeners. Apache APISIX has `enable_http2 = true` in its default table. F5 NGINX Ingress Controller is the opposite: its `http2` key defaults to "False". Metnir says NGINX Gateway Fabric also enables HTTP/2 by default, and we could not verify that (COULD NOT VERIFY). Whether OpenResty enables it is also COULD NOT VERIFY.

Many sites reach nginx through a CDN or load balancer. These bugs are reached through HTTP/2 itself, so what matters is which protocol the proxy speaks to your origin. Cloudflare's documentation says "At Cloudflare, HTTP/2 connection to the origin is enabled by default." It connects with HTTP/2 only to origins that announce it through ALPN and falls back to HTTP/1.1 otherwise. The setting is on by default for Free, Pro and Business plans and off by default for Enterprise. AWS says "By default, Application Load Balancers send requests to targets using HTTP/1.1." You can set a target group to HTTP/2 or gRPC. CloudFront "forwards requests to your custom origin using HTTP/1.1". At Akamai the connection from the edge to the origin is non-HTTP/2 by default, and an "HTTP/2 Edge to Origin" option exists. For Fastly we could not verify an explicit statement (COULD NOT VERIFY). Our reading: a CDN that speaks HTTP/2 to the origin leaves the origin's HTTP/2 code reachable through that CDN, so those origins sit in the CRITICAL tier. A CDN that speaks HTTP/1.1 to the origin removes that path, but not for an origin that can also be reached directly. Whether either bug can be triggered through a proxy that speaks HTTP/2 to the origin is unknown, because no source tested it. Wiz says CDNs and WAFs that terminate HTTP/2 "may mitigate parts of the exploit by not reflecting the exact payload back to the underlying NGINX server. This depends on implementation." Treat a proxy as a layer, not a fix, and lock the origin so it can't be reached around the proxy.

The two bugs have different preconditions:

- CVE-2026-123007 needs only HTTP/2 enabled. F5 states no proxy, static-file, server push, HPACK or stream-setting condition.
- CVE-2026-123633 needs HTTP/2 for client connections, proxying to a backend, and a worker running low on worker_connections (F5's text). Xint's table says "HTTP/2 with requests forwarded to an upstream (backend) server".
- So a static-only site with HTTP/2 on is exposed to CVE-2026-123007 but, on our reading of F5's wording, outside CVE-2026-123633.
- Server push was removed in nginx 1.25.1, so it cannot be a precondition on current releases. No source ties either bug to HPACK or stream settings.
- Not stated by any source: whether the bugs are reachable over cleartext HTTP/2, and whether 32-bit builds are affected. Wiz tested 64-bit systems.

The same release fixes 10 advisories, not two. The other eight include bugs outside HTTP/2 (HTTP/3, resolver, mail proxy), and the list is under Affected versions. Turning HTTP/2 off covers only the two HTTP/2 bugs. Servers with HTTP/2 off should still take 1.31.9 or 1.30.7 in the normal window.

One reading needs care: counts built on version numbers alone. Xint says that on 10 November Shodan returned 56.7 million hosts for product:nginx, that 11.94 million (21.1%) reported an identifiable version, and that among those 98.9% fell within the range affected by CVE-2026-123007 (1.9.5 through 1.31.8). Our arithmetic, not a source figure: that is about 11.8 million hosts. Xint adds: "These numbers are based on reported version strings and don't confirm that a server is vulnerable." HTTP/2 may be off, and a reported version may hide a backported fix. No source gives a count of nginx hosts with HTTP/2 on that we can use. Censys has a public tracker (running since 18 November) whose page says it counts services, and we quote none of its figures. Shadowserver, GreyNoise, Netlas and LeakIX gave us nothing usable (COULD NOT VERIFY). A remote version check can't see whether HTTP/2 is on or whether a distro backport is installed (our reading).

If an attacker gets one of these working against one of your servers, they can:

- Crash a worker process. A failed attempt can end that way, and the error log shows it as "worker process ... exited on signal 11".
- Corrupt memory in the worker and, under the conditions F5 names (ASLR disabled or bypassed), run code. The researchers showed this in labs: Xint with only an externally reachable TLS/HTTP/2 port, Wiz on official nginx 1.31.7 and 1.31.8 builds with an ASLR bypass, Rapid7 for CVE-2026-123007 against a Docker image of nginx 1.31.8 with HTTP/2 and TLS on, and Metnir for CVE-2026-123633 only ("id runs on the target as the unprivileged nginx user").
- Act as the worker user, not as root. The master process runs as root and the workers drop to the configured user (nginx docs and source). That user is "nginx" for the nginx.org packages, RHEL (CentOS Stream files) and Alpine, "www-data" for Debian and Ubuntu, nginx (uid 101) in the Docker official image, and "nobody" for a source build default (inferred from shipped config files).
- Reach whatever that user can reach: the site's files and configuration, application secrets, and the backends and internal services nginx proxies to.
- Reach root only with a second bug. Xint says it chained CVE-2026-123007 with a separate Linux kernel flaw and that, in its tests, the chain also escaped a Docker container running nginx and obtained root on the host. Xint says "The nginx vulnerabilities give an attacker code execution with worker privileges." CIRCL: "A vulnerable NGINX instance does not by itself imply host-root access." We could not verify the kernel claim (COULD NOT VERIFY), so it stays Xint's statement. As of 19 November, 04:30 UTC, we found no CVE ID and no fix for that kernel flaw, and Qualys (18 November; WEAK, because the text came through a fetch tool after curl was blocked) says the same: "That kernel flaw has no CVE and no patch yet, so patching nginx removes the remote entry point but not the step to root."

No indicators of compromise have been published, so there is nothing to match against yet. Xint: "An attack using CVE-2026-123007 may leave little evidence in nginx access logs."

Real-world context: both fixes reached the public nginx repository on 18 November 2026. F5's datePublic for both records is 15:00 UTC. Xint's post followed at 15:07, Wiz's at 15:13 and a Hacker News story at 15:19. The push to nginx master on GitHub came at 15:20 and the push to stable-1.30 at 15:22. The CVE records were published at 15:23, and the nginx.org download, CHANGES and advisories pages were last modified at 15:48 and 15:49. The author dates of the fix commits are 17 September (CVE-2026-123633) and 29 October (CVE-2026-123007), and the committer dates are 11 November. The push log shows no push to nginx master between 9 November at 13:29 UTC and 18 November at 15:20 UTC, so we found no silent window on GitHub (our reading). Two Hacker News comments say the fix was public a week earlier, and the push log does not support that. Whether the 11 November tarballs were downloadable before 18 November is not established. NGINX Plus customers had the CVE-2026-123633 fix from 14 October 2026, per the release notes.

No exploitation in the wild has been reported as of about 04:30 UTC on 19 November, 13.5 hours after disclosure. F5's spokesperson told The Register: "At this time, we have found no evidence of active exploitation of any of these vulnerabilities in the wild". Tenable's FAQ (00:18 UTC on 19 November) says "There are no reports of threat actors exploiting these CVEs as of November 18." Qualys says "As of November 18, 2026, we have not seen public confirmation of exploitation in the wild." (WEAK: the Qualys text came through a fetch tool after curl was blocked). The Hacker News says "Neither the vendor nor the Wiz and Rapid7 researchers have reported any attacks exploiting the flaw so far. CISA's Known Exploited Vulnerabilities catalog did not list it as of today." CERT-EU says "no exploitation in the wild has been reported yet", and CISA's SSVC entry says Exploitation none. CIRCL's sightings feed listed, at the 18 November check (not re-run on 19 November), 68 sightings for CVE-2026-123007 (66 "seen", 2 "published-proof-of-concept", 0 "exploited") and 47 for CVE-2026-123633 (46 "seen", 1 "published-proof-of-concept", 0 "exploited"). Previdian (WEAK) says "Previdian sensors have not observed exploitation attempts against either of these vulnerabilities." Our reading: confidence is moderate, because no primary telemetry was reachable (COULD NOT VERIFY: GreyNoise was blocked and Shadowserver had no report). The EPSS API returned no score for either CVE (checked again at 04:27 and 04:45 UTC on 19 November), and neither is in KEV (catalog 2026.11.18, 1786 entries, checked again at 04:27, 04:45 and 04:48 UTC). NCSC-NL, at 16:07 UTC and before the first proof-of-concept sighting, said it expects proof-of-concept code soon, after which it expects exploitation on a large scale. Wiz: "widespread attacks initially start against packaged products where many customers use the exact same build and configuration."

A public proof of concept exists for CVE-2026-123007. Rapid7 published one on GitHub (the repository was last pushed at 15:23 UTC on 18 November, and CIRCL's feed first saw it at 17:04 UTC). Rapid7's notes say it "is only suitable to demonstrate the given RCE exploitation strategy against a local freshly started Docker container". They add that it will likely fail against a server with several concurrent clients, a worker that has been running for some time, or a network proxy in the path. Xint says the opposite about its own unreleased exploit: it "works under concurrent normal traffic and across servers with different hardware specifications". Sources differ on how reliable exploitation is. CERT-FR confirms a public proof of concept for CVE-2026-123007, Sophos (WEAK) says the same, and HKCERT (19 November, 01:00 UTC) says "Proof of Concept exploit code is publicly available for CVE-2026-123007." More public exploit code has appeared since Rapid7's. Third party repositories claim exploit code for CVE-2026-123007, one with a full code execution chain, and Censys Research published proof-of-concept material (its README says its compact proof of concept "is not an RCE exploit", but the same README says Rapid7's full code execution chain was independently reproduced in its lab, and the repository holds a file naming code execution as confirmed for CVE-2026-123007). VulnCheck's exploit database lists a third party repository, dated 18 November. None of it is verified: we read descriptions and file lists only, and no repository is named or linked here. Wiz, Xint and Metnir still withhold their exploits, so no proof of concept from them is public for CVE-2026-123633. For Ikotas Labs we found no publication or proof of concept (COULD NOT VERIFY). One vulnerability database (Wiz) still showed "Has Public Exploit: No" at 04:27 UTC on 19 November although Rapid7's code is public, so aggregator flags lag.

A GitHub search for either CVE ID in quotes returned 18 repositories at 04:45 UTC on 19 November, and the same 18 at 04:48 UTC (15 match CVE-2026-123007 and 6 match CVE-2026-123633, with overlap). The figure counts search matches, not verified exploits, and 7 of the 18 were created after 20:10 UTC on 18 November. By their own descriptions, the repositories we read include third party exploit and proof-of-concept claims for CVE-2026-123007 (one claims a full code execution chain, and one records a reproduction with success logs), a lab repository published by Censys Research, Docker labs and read-only scanners. None of the third party code is verified, and we read descriptions and file lists only. The six claims we first reviewed on 18 November look unreliable. The ones about CVE-2026-123633 describe a crash or denial of service, with code execution only as a possibility. One describes the CVE-2026-123633 mechanism in a way that conflicts with nginx's own fix commit, and one mislabels a different nginx CVE. The count was still rising (17 at 04:28 UTC, 18 at 04:45 UTC). A Telegram post flagged as a proof of concept for both CVEs is unverified. We opened and ran none of them. Running unknown proof-of-concept code is a common way to get compromised, so leave them alone. We found no Metasploit module or pull request and no Nuclei template or pull request (searches at 19:36 and 20:02 UTC on 18 November, repeated at 04:28 to 04:45 UTC on 19 November with the same result; a template at another path would not show). Exploit-DB and Packet Storm could not be queried (COULD NOT VERIFY).

National CERTs have published advisories: NCSC-NL in the Netherlands (NCSC-2026-0506, rated H/H, high likelihood and high impact), CERT-EU (Security Advisory 2026-022, "Critical vulnerabilities in Nginx"), CERT-FR in France (CERTFR-2026-ALE-017), the Canadian Centre for Cyber Security (AV26-1174), CCB Belgium (a warning read only as a headline through a news aggregator, so WEAK) and HKCERT in Hong Kong (a bulletin that says a proof of concept for CVE-2026-123007 is public). A post on the oss-security mailing list also lists the ten bugs fixed in the release.

*Sources: nginx.org security advisories page and CHANGES file, nginx GitHub push log and fix commits, F5 CVE records and release notes, nginx documentation and source files, Debian, Ubuntu, RHEL (CentOS Stream), Docker and Alpine config files, Cloudflare, AWS and Akamai documentation, Fastly developer guide, ingress-nginx, Kong and Apache APISIX files, Kubernetes blog, Wiz, Rapid7, Xint, Metnir, CIRCL, Previdian (WEAK), Sophos (WEAK), The Hacker News, Hacker News, CISA SSVC data and KEV feed, FIRST EPSS API, GitHub repository search, NCSC-NL, CERT-EU, CERT-FR, Canadian Centre for Cyber Security, HKCERT and CCB Belgium (WEAK) advisories, the oss-security list, Qualys (WEAK), Tenable, The Register, Censys Research, VulnCheck, and AlmaLinux, SUSE and Amazon Linux security pages*

### Immediate actions required

HOUR 1: Find every nginx server with HTTP/2 on

1. List the servers, containers, ingress controllers, API gateways and appliances that run nginx or a product built on it (OpenResty, Kong, Apache APISIX, community ingress-nginx, F5 NGINX Ingress Controller, NGINX Gateway Fabric). Include the images you build yourself, so new instances don't start on an old build.
2. Get the version and the build options on each one: `nginx -v` and `nginx -V` (run as root if nginx is not on your path). Judge upstream builds by the nginx version. Judge distro packages by the distro advisory, because they backport fixes without changing the version number. On NGINX Plus, `nginx -v` shows the open source base, which can be below 1.31.9 on a fixed build (37.3.0.1 is based on 1.31.8), so check the Plus package version instead. Products that embed nginx carry their own numbers.
3. Mark the servers where HTTP/2 is switched on: the module compiled in and `http2 on;` or a `listen` line with `http2` in the config on disk. The Quick status check in the RISK DASHBOARD has the commands. Internet-facing servers come first. For a server behind a proxy or CDN, find out which protocol the proxy speaks to the origin: Cloudflare uses HTTP/2 where the origin offers it, and ALB and CloudFront use HTTP/1.1 by default. No source says whether either bug can be triggered through a proxy that speaks HTTP/2 to the origin.
4. Note which servers cannot take a fix today: distro packages with no fixed build, products and forks with no fix, and the images with no fixed tag. They get the HTTP/2 stopgap in DAY 1 below.

DAY 1: Patch and restart

1. Install nginx 1.31.9 or 1.30.7, NGINX Plus 37.3.0.1 or 37.0.8.1, or your distro's fixed package (see Where the fix comes from). Patch internet-facing servers with HTTP/2 on first, then every other server on an affected version, then servers with HTTP/2 off in the normal window, because the release fixes eight other bugs. If you run nginx before 1.30, or NGINX Plus R33 to R36, no fixed release exists on your branch (inferred): move to 1.30.7 or 1.31.9 and later, or a fixed 37.x release. For Docker, rebuild your image on the fixed tag and redeploy. The nginxinc/nginx-unprivileged image has no fixed tag yet. On Kubernetes, F5 NGINX Ingress Controller v5.8.0 and NGINX Gateway Fabric v2.9.0 carry fixed builds, and community ingress-nginx has no fix and none is coming. The commands for each platform are under IMMEDIATE ACTIONS in the PROTECTION ROADMAP.
2. If you suspect a server, save the logs, any core dumps and a list of running processes before you restart nginx, because a restart replaces the running worker processes.
3. Restart nginx on every patched server, a restart and not a reload. Xint: "A configuration reload alone does not replace the running executable." A reload also leaves connections that are already open, HTTP/2 ones included, on the old workers. `nginx -v` only reads the program on disk, so check that the main nginx process (owned by root) started after the update. A restart drops the connections in progress (Xint says it "forcibly disconnects every client"), so plan the window.
4. If patching has to wait, switch HTTP/2 off on the listeners that untrusted clients can reach. This is not an F5 or nginx.org instruction: F5's records say the workaround is "None". It is advice from Wiz, Xint, CIRCL, CERT-FR and Metnir. It blocks only these two bugs and not the other eight fixes in the release. Clients that support HTTP/1.1 carry on, but services that require HTTP/2 end to end, such as native gRPC, break, and HTTP/1.1 clients open more connections, so check that the workers have enough capacity (Metnir). Check every server block that shares the listening address and port, because a leftover `listen ... http2` parameter keeps HTTP/2 on even with `http2 off;` (inferred). For Cloudflare zones whose origin can't be patched yet, turning off "HTTP/2 to Origin" stops Cloudflare speaking HTTP/2 to the origin, which is on by default for Free, Pro and Business plans. That removes the path through Cloudflare, not the origin's own HTTP/2 listener (our reading). Fronting is a layer, not a fix. The commands for turning HTTP/2 off are under IMMEDIATE ACTIONS in the PROTECTION ROADMAP.

DAY 2: Look for compromise

No indicators of compromise have been published, and CIRCL says "a lack of suspicious access-log lines is therefore not sufficient to exclude exploitation", because HTTP/2 control frames do not normally show up as individual requests in the nginx access log.

1. Search the error log for worker crashes. nginx logs them as "worker process ... exited on signal 11". Xint: "A failed exploit attempt can crash an nginx worker, so look for abnormal exits and core dumps with the commands below." CERT-EU says worker-crash lines are "not a high-fidelity indicator of successful remote code execution but rather an indication of exploitation attempts". For the proxy bug (CVE-2026-123633), Metnir says repeated worker crashes after "worker_connections are not enough" warnings on an HTTP/2 proxy may point to it. The same warning also appears on busy servers that are simply short of connections. A crash alone proves nothing, and a clean log doesn't clear a server either.
2. Look for programs started by the nginx worker user (shells, download tools, interpreters), and for unusual outbound connections or DNS activity from the worker (Xint and CIRCL). Xint suggests an auditd rule that records program starts by the worker's user.
3. Look for long-lived HTTP/2 connections that send a lot of data with few logged requests. Wiz says detection rules covering them "may hint at an attack associated with this vulnerability" (CVE-2026-123007), and CIRCL names the same pattern. Wiz calls unexpected worker crashes and commands launched by nginx "general warning signs, not confirmed indicators of these vulnerabilities".
4. If anything looks off, treat the server as compromised and rotate every secret it holds or can reach. The worker user is not root (our reading, inferred), but it can read the site's files, configuration and application secrets.

### Business impact assessment

Financial risk:

- No confirmed compromise has been reported, so there is no incident cost to quote for these bugs.
- The fix itself is a package update and a restart. The costly cases are the ones with no released fix: community ingress-nginx (retired, no fix expected), nginx before the 1.30 branch and NGINX Plus R33 to R36 (a move to a fixed release), the nginxinc/nginx-unprivileged image, and the forks and products that had shipped no fix at the cut-off (freenginx, Angie, OpenResty, Tengine, Kong OSS). Distro-owned packages from Debian stable and testing, Ubuntu, Red Hat, SUSE, Rocky Linux and AlmaLinux 8 have no fix either, and Oracle Linux has no record for either CVE. Fedora, cPanel and Plesk are COULD NOT VERIFY (see Where the fix comes from). Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid now have fixed packages.
- Finding every server is the hidden cost. nginx sits inside container images, ingress controllers, API gateways and appliances, and a base image or a template can carry an old build into every new instance.

Operational risk:

- Every fix needs an nginx restart, and a restart drops the connections in progress. Plan the windows.
- Version scanners will be noisy. A remote version check can't see whether HTTP/2 is on or whether a distro backport is installed (our reading), so a flagged server may have HTTP/2 off or may already carry the distro's fix. Tenable still has no plugins for either CVE ("Coming Soon" on 18 November, empty plugin lists at 04:28, 04:45 and 04:48 UTC on 19 November), Qualys lists QIDs 736231 and 389654 as pending (WEAK), and Sophos (WEAK) says it is investigating.
- Turning HTTP/2 off is a stopgap. It breaks services that need HTTP/2 end to end, such as native gRPC, and it sends HTTP/1.1 clients into more connections. The fix is a patched build.
- Don't count on a WAF. We found no Cloudflare WAF changelog entry for either CVE, no AWS WAF managed-rule entry, no Emerging Threats Open rule and no Snort 3 community rule, and nothing from Akamai, Fastly, Imperva, Fortinet FortiGuard or F5 BIG-IP and Advanced WAF guidance. Wiz says CDNs and WAFs may mitigate parts of the exploit and that this depends on implementation, and Rapid7's notes say a proxy in the path will likely break its own public exploit. No source tested either claim against these bugs.

Legal risk:

- If a compromised server holds personal data, breach notification clocks start when you become aware of the breach. The deadlines by jurisdiction are in COMPLIANCE & LEGAL REQUIREMENTS.

*Sources: nginx.org security advisories page and CHANGES file, F5 CVE records and advisories (WEAK), Xint, Wiz, Rapid7, Metnir, CIRCL, CERT-EU and CERT-FR advisories, Cloudflare and AWS documentation, Cloudflare WAF and AWS WAF changelogs, Emerging Threats and Snort rule sets, Tenable plugin list, Sophos (WEAK), vendor release pages and trackers (see Where the fix comes from)*

---

## RISK DASHBOARD

### Severity metrics

| Metric | Rating | What it means |
| --- | --- | --- |
| **Overall risk** | CRITICAL for internet-facing nginx with HTTP/2 on, HIGH for internal servers with HTTP/2 on | F5 (the CNA) scores both CVEs CVSS 3.1 8.1 High and CVSS 4.0 9.2 Critical. nginx.org rates CVE-2026-123007 major and CVE-2026-123633 medium. Servers with HTTP/2 off are not exposed to these two bugs. Other sources are in the table below |
| **Attack complexity** | HIGH in both CVSS versions | F5's CVSS 3.1 vector is CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H and its CVSS 4.0 vector is CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N: network, high complexity, full impact. For CVE-2026-123633, F5's text also needs a worker running low on worker_connections |
| **Authentication needed** | NONE | PR:N in both vectors. The attacker needs only network access to a listener with HTTP/2 on |
| **User interaction** | NONE | UI:N. Nobody has to click anything |
| **Reach** | ONLY OVER HTTP/2 | The HTTP/2 module has to be compiled in and HTTP/2 has to be switched on for a listener the attacker can reach. CVE-2026-123633 also needs proxying to a backend. Whether a proxy that speaks HTTP/2 to the origin passes either trigger through is unknown |
| **Code execution** | CONDITIONAL, AS THE WORKER USER | F5: "attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR." CIRCL says ASLR is "not an effective standalone mitigation for these vulnerabilities". Not root, unless a second bug is chained (Xint's claim, COULD NOT VERIFY) |
| **Patch available** | YES for nginx 1.31.9 and 1.30.7 and several platforms, NO on older branches and for several distros | Both released on 18 November 2026. NGINX Plus 37.3.0.1 and 37.0.8.1 fix both bugs (inferred: later releases on a branch carry the earlier fix). Older branches have no fixed release (inferred). Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux had no fixed package at the cut-off, while Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had one (see Where the fix comes from) |
| **Active exploitation** | NOT REPORTED IN THE WILD | As of about 04:30 UTC on 19 November. The Hacker News, CERT-EU, F5 (to The Register), Tenable and Qualys (WEAK) report none, CIRCL says the lab results are "not by itself proof of widespread in-the-wild campaigns", CISA's SSVC entry says Exploitation none, and CIRCL's sightings feed listed 0 "exploited" for both CVEs at the 18 November check (not re-run). Previdian (WEAK) says its sensors saw no attempts. Not in CISA KEV (catalog 2026.11.18, checked at 19:59 and 20:10 UTC on 18 November and at 04:27, 04:45 and 04:48 UTC on 19 November). Our reading: confidence is moderate, because no primary telemetry was reachable |
| **Public proof of concept** | CVE-2026-123007, plus unverified third party code | Rapid7 published one for CVE-2026-123007, and its notes limit it to a freshly started container. More public exploit code has appeared since: one repository claims a full code execution chain, Censys Research published proof-of-concept material, and HKCERT says one is public. None of that code is verified. Wiz, Xint and Metnir withhold their exploits. Unverified third party repositories exist for both CVEs |
| **EPSS** | NO SCORE YET | The API returned no data for either CVE at 19:35, 19:48 and 19:59 UTC on 18 November and at 04:27 and 04:45 UTC on 19 November |
| **NVD record** | RECEIVED, NO NVD SCORE | Both records were published on 18 November 2026 at 16:18:04 UTC. NVD's change history shows later changes: reference links added at 20:18 and 21:17 UTC and, for CVE-2026-123633, one more change at 23:17 UTC. Status was still "Received" at 04:45 UTC on 19 November. NVD has not analysed them, shows F5's scores and has no CPE data |

Ratings by source:

| Source | Rating | Note |
| --- | --- | --- |
| F5 (CNA, both CVEs) | CVSS 3.1 8.1 High, CVSS 4.0 9.2 Critical | Same ratings under two CVSS versions (our reading). CWE-191 and CWE-787 for CVE-2026-123007, CWE-416 for CVE-2026-123633. F5 lists the workaround as "None" |
| nginx.org | CVE-2026-123007 major, CVE-2026-123633 medium | The scale is none, minor, medium, major, with no "critical". Vulnerable range 1.9.5 to 1.31.8 for CVE-2026-123007 and 1.19.7 to 1.31.8 for CVE-2026-123633 |
| CISA (ADP entry, "CISA Vulnrichment") | SSVC 2.0.3: Exploitation none, Automatable no, Technical Impact total | Both CVEs. Stamped 16:04:40 UTC (CVE-2026-123007) and 16:38:06 UTC (CVE-2026-123633) |
| NVD | Received, not analysed | No NVD score of its own. It shows F5's scores |
| Ubuntu | Priority High, CVSS 3 8.1 High, CVSS 4.0 9.2 Critical | Both CVEs. No fixed package yet |
| Debian | No urgency set | Both CVEs. Fixed in sid (nginx 1.30.6-4) only, no fixed package yet in the other releases |
| Red Hat | Both CVEs: threat severity "CRITICAL" (WEAK, read from the CVE pages' embedded data) | Exploit known false, CVSS v3 8.1 with status "DRAFT", on both pages. The CSAF VEX files (revision 3, 18 November, 21:27 UTC for CVE-2026-123007 and 21:29 UTC for CVE-2026-123633) list 45 products each as known affected, with no fix and a workaround entry. CVE-2026-123633 now has a Red Hat entry too: Affected, no erratum |
| Amazon Linux | Important, CVSS v3 base score 8.1 | Both CVEs fixed: ALAS2023-2026-3494 (Amazon Linux 2023), ALAS2NGINX1-2026-018 (Amazon Linux 2 Nginx1 Extra), and ALAS2027-2026-386 and ALAS2027-2026-385 (2027 Preview) |
| SUSE | "important" for both CVEs (SUSE's own rating, with F5's CVSS scores shown) | Records for both CVEs, state "Analysis" for every product. No fixed package and no SUSE-SU. Bugzilla 1290868 (CVE-2026-123007) and 1290872 (CVE-2026-123633) are both "NEW" |
| GitHub advisory database (unreviewed) | Critical, CVSS v4 9.2 | GHSA-m4q8-cf44-f42r for CVE-2026-123007 and GHSA-7xxj-p8w5-434q for CVE-2026-123633 |
| Snyk | Critical | Entry covers CVE-2026-123007 only. Listed as SNYK-UNMANAGED-NGINX-22598758, Exploit Maturity "Proof of Concept" |
| Wiz | Critical, CVSS 4.0 9.2 | F5's score, for both CVEs |
| Rapid7 | CVSSv4 9.2 (Critical), CWE-191 | CVE-2026-123007 |
| Metnir | CVSS 4.0 9.2 | CVE-2026-123633 |
| Xint | Critical, no CVSS given | |
| NCSC-NL | H/H (high likelihood, high impact) | Advisory NCSC-2026-0506 |
| CERT-EU | Titled "Critical vulnerabilities in Nginx" | Security Advisory 2026-022 |
| CERT-FR and Canadian Centre for Cyber Security | No rating in what we read | CERTFR-2026-ALE-017 and AV26-1174 cover the fixes |
| HKCERT and CCB Belgium | HKCERT rates it "Medium Risk". CCB Belgium's headline says "Multiple Critical NGINX Vulnerabilities" (WEAK) | HKCERT's bulletin of 19 November says a proof of concept for CVE-2026-123007 is public. CCB Belgium's warning was read only as a headline through a news aggregator (WEAK) |
| EPSS | No score yet | Checked at 19:35, 19:48 and 19:59 UTC on 18 November and at 04:27 and 04:45 UTC on 19 November |
| CISA KEV | Not listed | Catalog 2026.11.18, released 19:17 UTC, 1786 entries |

The 8.1 versus 9.2 split is not two assessors disagreeing. F5 scored both bugs once under CVSS 3.1 and once under CVSS 4.0, and the inputs are the same: attack complexity High, no privileges, no user action, full impact (our reading). The real gap is elsewhere. F5 and the researchers say Critical. nginx.org says major for CVE-2026-123007 and only medium for CVE-2026-123633, on a scale that has no "critical". CISA's assessment says Exploitation none and Automatable no. We state that tension once and weigh it below.

My read: treat it as critical for internet-facing nginx on an affected version with HTTP/2 switched on and reachable over HTTP/2, and as high for internal servers with HTTP/2 on. That includes servers behind a CDN that speaks HTTP/2 to the origin, and products that turn HTTP/2 on by default (community ingress-nginx, Kong, Apache APISIX). Servers with HTTP/2 off are not exposed to these two bugs, but should still upgrade, because the same release fixes 10 advisories, including bugs outside HTTP/2. F5 and the researchers rate it Critical, it needs no login and no user action, the fixes are public, Rapid7 has published a proof of concept for CVE-2026-123007 and more unverified exploit code has appeared since, four research teams showed code execution in labs, and NCSC-NL expects exploitation on a large scale once proof-of-concept code is out. Against that: F5 scores attack complexity High, nginx.org rates CVE-2026-123633 only medium, CISA's assessment says Exploitation none, code execution needs ASLR disabled or bypassed, nobody has reported exploitation, neither CVE is in KEV, and the public demonstration has narrow conditions. Rapid7's own notes say its code will likely fail against concurrent clients, a worker that has been running for some time, or a proxy in the path, while Xint says its unreleased exploit works under concurrent normal traffic. The critical tier is our reading. It rests on how exposed the HTTP/2 code is to untrusted input, not on proven exploitability. Internal servers stay at high, because anyone already inside the network is a possible attacker.

*Sources: nginx.org security advisories page, F5 CVE records and advisories (WEAK), NVD, CISA ADP entry and SSVC data, CISA KEV feed, FIRST EPSS API, Ubuntu, Debian, Amazon Linux and SUSE CVE pages, Red Hat CVE page and CSAF VEX file (WEAK), GitHub advisory database, Snyk, Wiz, Rapid7, Metnir, Xint, NCSC-NL, CERT-EU, CERT-FR and Canadian Centre for Cyber Security advisories, CIRCL, Previdian (WEAK), The Hacker News*

### Affected versions: quick lookup

- CVE-2026-123007: nginx Open Source 1.9.5 to 1.31.8, which is the range nginx.org lists as vulnerable. F5's table gives 1.9.5 to 1.30.6 and 1.31.0 to 1.31.8. The CVE record lists 1.9.5 with no upper bound, 1.30.0 up to but not including 1.30.7, and 1.31.0 up to but not including 1.31.9.
- CVE-2026-123633: nginx Open Source 1.19.7 to 1.31.8 (nginx.org), with the same structure in the CVE record and F5's table. nginx 1.19.7 was released on 16 February 2021.

| Release | Status on 19 November 2026 | Affected releases | Fixed in | Released |
| --- | --- | --- | --- | --- |
| nginx 1.31.9 (mainline) and 1.30.7 (stable) | Current, have both fixes | None for these two CVEs | 1.31.9 and 1.30.7 | 18 November 2026 |
| nginx 1.31.0 to 1.31.8 | Affected by both | All of them | 1.31.9 | 18 November 2026 |
| nginx 1.30.0 to 1.30.6 | Affected by both | All of them | 1.30.7 | 18 November 2026 |
| nginx 1.19.7 to before 1.30.0 (including 1.28.x) | Affected by both, no fixed release | All of them | None on these branches (inferred). Move to 1.30.7 or 1.31.9 and later | n/a |
| nginx 1.9.5 to 1.19.6 | Affected by CVE-2026-123007 only, no fixed release | All of them | None on these branches (inferred). Move to 1.30.7 or 1.31.9 and later | n/a |
| nginx before 1.9.5 | Not affected by these two CVEs | None. These releases have no HTTP/2 module | n/a | n/a |
| NGINX Plus 37.3.0.1 (CR) and 37.0.8.1 (LTS) | Current, have both fixes (inferred: later releases on a branch carry the earlier fix) | None | 37.3.0.1 and 37.0.8.1 | 18 November 2026 |
| NGINX Plus 37.0.0 to 37.0.7.1 and 37.1.0 to 37.2.0.1 | Affected by CVE-2026-123007. Affected by CVE-2026-123633 only up to 37.0.6.1 and 37.2.0 | 37.0.0 to 37.0.7.1 and 37.1.0 to 37.2.0.1 | CVE-2026-123007: 37.0.8.1 and 37.3.0.1. CVE-2026-123633: 37.0.7.1 and 37.2.0.1 | 37.0.8.1 and 37.3.0.1 on 18 November 2026. 37.0.7.1 and 37.2.0.1 on 14 October 2026 (per the release notes) |
| NGINX Plus R33 to R36 | Affected, no fixed release | R34 to R36 in F5's table, which lists the fix as "None". The CVE records also list R33, with no upper bound | None. Our reading: move to a fixed 37.x release | n/a |

Four things to know about this table. First, distro packages backport fixes without changing the nginx version. Xint says Ubuntu 24.04 ships 1.24.0, Ubuntu 22.04 ships 1.18.0 and Debian 12 ships 1.22.1, and that these distributions may backport security fixes to the existing version instead of replacing it with a new nginx release. Judge distro packages by the distro advisory, not by the nginx version string. At the cut-off Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux had no fixed package, while Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had one (see Where the fix comes from). Ubuntu lists releases with nginx older than 1.19.7 as needed for CVE-2026-123633, while nginx.org's range for it starts at 1.19.7, and we found no explanation (COULD NOT VERIFY). Second, products that embed nginx carry their own version numbers. OpenResty 1.31.8.1 is based on nginx 1.31.8, which is inside the affected range, and it has no fix. Kong's source tree pins OPENRESTY=1.27.1.2, which is nginx core 1.27.1 and inside the affected range (inferred), and we found no Kong statement. NGINX Plus 37.3.0.1 is based on nginx 1.31.8 (release notes) yet contains the CVE-2026-123007 fix, so the open source version of a Plus build says nothing about the fix. Third, Docker tags move. The official image tags (latest, mainline, stable and the numbered ones) were updated on 18 November, and the nginxinc/nginx-unprivileged image has no fixed tag. Fourth, no module, no bug. A build without ngx_http_v2_module has no HTTP/2 code, and `nginx -V` shows `--with-http_v2_module` when it is compiled in. Xint says absent means not affected.

The HTTP/2 module first shipped in nginx 1.9.5 on 22 September 2015, which is why CVE-2026-123007 reaches that far back. CVE-2026-123633 starts at nginx 1.19.7 (released 16 February 2021). Its fix commit says that having an HTTP/2 connection with streams registered as reusable "became possible after 76672e650", an earlier change by Maxim Dounin from 11 February 2021 titled "HTTP/2: reuse of connections with incomplete frames." We infer that change is in 1.19.7. The `http2` directive appeared in nginx 1.25.1 (13 June 2023), and the `http2` parameter of `listen` has been deprecated since then.

Sources disagree in four places, and we go with F5 and nginx.org each time:

- Metnir says its tests against older releases found related failures back to nginx 1.9.5. The official range for CVE-2026-123633 is 1.19.7 and later.
- The Hacker News headline calls the HTTP/2 flaw "10-Year-Old", and Wiz says "nearly six years" for CVE-2026-123633. Only CVE-2026-123007 goes back to 2015. CVE-2026-123633 starts in February 2021.
- The CVE records list NGINX Plus R33 as affected, and F5's table starts at R34. F5 says versions that have reached End of Technical Support are not evaluated.
- F5's weakness list and Rapid7 call CVE-2026-123007 an integer underflow, while nginx CHANGES and Xint call it an overflow. We use F5's wording ("flow control window can exceed the allowed threshold") and pick no side.

The fixes are small. The CVE-2026-123007 fix is nginx commit e27f5fa8 by Roman Arutyunyan, "HTTP/2: account for queued frames when validating WINDOW_UPDATE" (3 files under src/http/v2/, 6 insertions, 2 deletions). Its message says the flaw led to broken buffer size control when nginx sends response data, followed by memory corruption and a possible segmentation fault, and that the fix is "to account for the queued frames when validating a client WINDOW_UPDATE". The stable-1.30 copy is b89c4100. The CVE-2026-123633 fix is commit 2df48a50 by the same author, "HTTP/2: reset reusable connection status on stream creation" (1 file, src/http/v2/ngx_http_v2.c, 2 insertions). It marks the connection non-reusable when a stream is created. The stable-1.30 copy is 0c87dd1d. We say no more about the mechanism.

The same release fixes eight other bugs. The severity and range below are nginx.org's, and all are fixed in 1.31.9 and 1.30.7 unless noted:

- CVE-2026-123634, use-after-free during response processing in the resolver, medium, 0.6.18 to 1.31.8.
- CVE-2026-121810, use-after-free in HTTP/3, medium, 1.25.0 to 1.31.8 (the nginx.org link text reads "CVE-CVE-2026-121810").
- CVE-2026-118899, infinite loop while reading the client request body over TLS 1.3, major, 1.13.0 to 1.31.8.
- CVE-2026-113425, use-after-free in the mail proxy module, major, 0.5.33 to 1.31.8.
- CVE-2026-120993, NULL pointer dereference when using PROXY protocol version 2, minor, 1.31.4 to 1.31.8. It is fixed in 1.31.9, and nginx.org lists no 1.30.x fix for it.
- CVE-2026-125283, buffer overflow when using alias with try_files, minor, 0.9.6 to 1.31.8.
- CVE-2026-120967, SNI bypass when using client certificate validation in stream, medium, 1.25.5 to 1.31.8.
- CVE-2026-123640, insufficient validation in the stream ssl_preread module, minor, 1.15.2 to 1.31.8.

Xint lists five nginx bugs as code execution class: CVE-2026-123007, CVE-2026-123634, CVE-2026-123633, CVE-2026-121810 and CVE-2026-113425. It says disabling HTTP/2 "does not block the other three nginx vulnerabilities". We did not read the F5 records for those three. HTTP/3 (QUIC) is a separate switch (`--with-http_v3_module`, `listen ... quic`) and is not in scope for the two HTTP/2 CVEs.

Quick status check:

```bash
# Version of the nginx program on disk (prints to the error stream)
nginx -v
# Whether the HTTP/2 module is compiled in. No output means it is not (run as root if nginx is not on your path)
nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
# Whether HTTP/2 is switched on in the config on disk. Reads every included file (run as root)
nginx -T 2>&1 | grep -nE '^[[:space:]]*(listen[[:space:]][^#]*[[:space:]]http2([[:space:]]|;)|http2[[:space:]]+on[[:space:]]*;)'
# Which ports nginx listens on (run as root to see process names)
ss -tlnp | grep nginx
# Which user the worker processes run as. The master is owned by root
ps -eo user,pid,ppid,args | grep '[n]ginx: '
# From outside: which protocol a site negotiates (prints 2 for HTTP/2, 1.1 otherwise)
curl -sI --http2 -o /dev/null -w '%{http_version}\n' https://www.example.com/
# From outside: whether the server offers h2 in the TLS handshake ("ALPN protocol: h2" means yes)
openssl s_client -connect www.example.com:443 -servername www.example.com -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol:|No ALPN negotiated'
```

```bash
# Docker: version and HTTP/2 module inside a running container
docker exec <container> nginx -v
docker exec <container> nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
```

- On an upstream build, if `nginx -v` shows a version in the affected range in the table above, the build has the bugs. 1.31.9 and 1.30.7 have the fixes once the server has restarted. `nginx -v` reads only the program on disk, so a server that installed 1.31.9 but did not restart still runs the old code, and that is the one that counts.
- On a distro build, compare the package version with the fixed package in Where the fix comes from. The upstream numbers don't apply. On NGINX Plus, check the Plus package version, because `nginx -v` shows the open source base.
- If the `nginx -V` line prints nothing, the HTTP/2 module is not compiled in and there is no HTTP/2 code. If it prints `--with-http_v2_module`, the module is there, and the server is exposed only if HTTP/2 is also switched on.
- The `nginx -T` line prints each `listen` line with an `http2` parameter and each `http2 on;` line. A hit means a directive exists, not that the port is reachable, so follow with the curl and openssl checks. It reads the config on disk, and if the config changed without a reload, the running config may differ (Xint). The dump can include secrets from included files, so keep the grep (our reading). `nginx -t` and `nginx -T` try to open the files named in the config (certificate keys, logs, pid file), which are usually root-only. Xint runs them with sudo (documentation level; we did not run them). `nginx -V` and `nginx -v` need only permission to run the binary.
- The curl check prints 2 when the site negotiates HTTP/2 and 1.1 otherwise. The openssl check prints "ALPN protocol: h2" when the server offers h2 in the TLS handshake, and "No ALPN negotiated" means the server does not accept HTTP/2 (Xint). Both test TLS only, so a cleartext listener with `http2` shows up in the `nginx -T` line and nowhere else (our reading).
- Behind a CDN or reverse proxy, the curl and openssl checks reach only the proxy, so also run them against the nginx server directly (Xint).
- Containers carry their own nginx. Run the version and module checks inside each container with `docker exec`, and check which image tag it was built from. Pull dates are a poor guide, so check the version inside the image. The full assessment steps are in AM I AFFECTED? SELF-ASSESSMENT.

*Sources: nginx.org security advisories page, CHANGES file and fix commits, F5 CVE records and advisories (WEAK), F5 NGINX Plus release notes, nginx documentation (configure and command line switches) and source, Xint, Metnir, Wiz, Rapid7, The Hacker News, Docker Hub tag lists, OpenResty and Kong build files, Alpine package pages, Ubuntu CVE tracker*

### Where the fix comes from

Two rules decide whether you are fixed. First, a fix only counts once nginx has restarted on it, and a reload is not enough. Second, distro packages don't follow upstream numbers, so the table gives each vendor's status. "No fixed package at the cut-off" means the vendor's tracker lists the bug as needed, vulnerable or under analysis, or has no entry. COULD NOT VERIFY means no usable source was reachable. All times are UTC.

| Platform | Status on 19 November 2026, 04:30 UTC | Fixed package or version | Notes |
| --- | --- | --- | --- |
| Upstream (nginx Open Source) | Fixed | 1.31.9 (mainline) and 1.30.7 (stable), 18 November 2026 | The tarballs carry file times of 11 November (17:59 and 18:09), and public availability before 18 November is not established. nginx.org pages were last modified at 15:48:59 to 15:49:06, and the GitHub tags release-1.31.9 (15:54:06) and release-1.30.7 (15:56:40) followed. No fixed release on older branches (inferred) |
| nginx.org binary repositories | Fixed | 1.31.9-1 (mainline) and 1.30.7-1 (stable) for Debian (bookworm, trixie), Ubuntu (jammy, noble, resolute), RHEL 9 and 10, Alpine 3.24 (1.31.9-r1 and 1.30.7-r1) and Amazon Linux 2023 | The listing times (11 November, 20:04 to 21:12) are build times, not publication times |
| NGINX Plus | Fixed for 37.x. No fix for R34 to R36 | 37.3.0.1 (CR) and 37.0.8.1 (LTS) for both CVEs (inferred for CVE-2026-123633), both released 18 November. 37.2.0.1 and 37.0.7.1 fix CVE-2026-123633 only (14 October) | Our reading: R33 to R36 have no fixed release on their branch |
| Docker official image (nginx) | Fixed | Tags 1.31.9, 1.30.7, latest, mainline, stable and the numeric and alpine variants, pushed on 18 November between 17:15:03 and 17:21:46 | The alpine-perl and alpine-otel variants had no images at 19:41 and got them between 19:52 and 19:54. No stale tag at the 19:55 check on 18 November, and the 04:32 check on 19 November found 14 tags for 1.31.9, the newest pushed at 22:51 on 18 November. Pull dates are a poor guide, so check the version inside the image |
| Docker nginxinc/nginx-unprivileged | Not fixed | None. No 1.31.9 or 1.30.7 tag | The newest tags are dated 19 October 2026 |
| F5 NGINX Ingress Controller | Fixed in v5.8.0 | v5.8.0 (compatibility row "1.31.9 / R37.3.0.1") | The 2026-lts-r11 tag has NGINX_OSS_VERSION 1.31.0 and NGINX_PLUS_VERSION R37.0, inside the affected range, so a fixed LTS build is COULD NOT VERIFY |
| F5 NGINX Gateway Fabric | Fixed for the open source image in v2.9.0 | NGINX_VERSION 1.31.9 | The Plus image uses nginx 1.31.8 with Plus R37.3, and the patch level is not shown |
| Debian | Fixed in sid (unstable) only. No fixed package in bookworm, trixie and forky | sid: nginx 1.30.6-4, with the fixes for both CVEs backported from 1.30.7 | bookworm 1.22.1-9+deb12u9 and u10 (security), trixie 1.26.3-3+deb13u7 and u10 (security) and forky 1.30.6-3 are all "vulnerable". The changelog of 1.30.6-4 is signed on 18 November at 18:56 UTC, and the tracker caught up later. Migration of 1.30.6-4 to testing is pending. There is no DSA, and nginx is not in dsa-needed (checked at 04:29 and 04:35 UTC on 19 November). The tracker notes cite the upstream fix commits |
| Ubuntu | No fixed package at the cut-off | None | Both CVEs published 18 November (15:23), priority high. trusty is "not-affected" (nginx 1.4.6 has no HTTP/2). xenial, bionic, focal, jammy, noble, resolute and stonking are "needed". Upstream is "released (1.31.9,1.30.7)". No notice for either CVE among the newest 20 nginx notices, and none by CVE ID (rechecked at 04:29 UTC on 19 November; record last updated 18 November at 17:00 UTC) |
| Red Hat | No fixed package at the cut-off | None | RHEL 8 (module nginx:1.24), RHEL 9 (default, nginx:1.24 and nginx:1.26 streams), RHEL 10 and Hardened Images are known affected for both CVEs, with no erratum and no RHSA. CVE-2026-123633 now has a Red Hat record (Affected). The VEX files reached revision 3 at 21:27 UTC (CVE-2026-123007) and 21:29 UTC (CVE-2026-123633) on 18 November, list 45 products each, and carry a workaround entry but no fix |
| Rocky Linux | No fixed package at the cut-off | None | No record. The Apollo and errata APIs and the OSV data for Rocky Linux 8, 9 and 10 had no hit at 04:29 UTC on 19 November (API stamp 03:59 on 19 November) |
| AlmaLinux | Fixed in 9 and 10. No advisory for 8 | AlmaLinux 9: ALSA-2026:A025, nginx 2:1.20.1-32.el9_9.1.alma.3. AlmaLinux 10: ALSA-2026:A024, nginx 2:1.26.3-16.el10_3.1.alma.2 | Both cover both CVEs. The times are OSV record modified times (18 November, 23:00 for 9 and 22:45 for 10), because the published field carries only the date, so the release times are not known. AlmaLinux 8 has no advisory, and its newest nginx record is dated 13 November. Read from the OSV database, because the errata site is a script page |
| Oracle Linux | No record for either CVE | None | Both CVE pages return 404 (04:29 UTC on 19 November) |
| SUSE | No fixed package. Records now exist, state "Analysis" for every product | None. No SUSE-SU | SLE 15 SP1 to SP7, SLE 16.0 and 16.1, Leap 15.3 to 16.1 and SUSE Manager 4.x are listed. Bugzilla 1290868 (CVE-2026-123007) and 1290872 (CVE-2026-123633) are both "NEW". The pages show a creation time of 18 November, 21:03 (zone as shown, not stated) |
| Amazon Linux | Fixed on Amazon Linux 2023, Amazon Linux 2 (Nginx1 Extra) and 2027 Preview | Amazon Linux 2023: ALAS2023-2026-3494, nginx-1.30.7-1.amzn2023.0.1. Amazon Linux 2 (Nginx1 Extra): ALAS2NGINX1-2026-018, nginx-1.30.7-1.amzn2.0.1. Amazon Linux 2027 Preview: ALAS2027-2026-386 (nginx) and ALAS2027-2026-385 (nginx-awslc) | Both CVEs, severity Important. ALAS2023-2026-3494 was released on 18 November at 23:09 UTC and ALAS2NGINX1-2026-018 on 19 November at 01:20 UTC (feed times, GMT). The 2027 Preview rows are dated 18 November with no time shown. All three showed "Pending Fix" on 18 November |
| Alpine | Fixed in edge, 3.24, 3.23 and 3.22. Not fixed in 3.21 | edge and 3.24: nginx 1.30.7-r0 (builds at 17:06 and 17:11 on 18 November). 3.23 and 3.22: nginx 1.28.3-r8, a backport (listed builds at 01:10 and 01:08 on 19 November, time zone not stated) | The security database key "1.30.7-r0" lists both CVEs among nine fixed CVEs, and the 3.23 and 3.22 databases list them under "1.28.3-r8". Alpine 3.21 ships nginx 1.26.3-r3 with no entry. Alpine 3.23 and 3.22 had 1.28.3-r7 (built 23 July 2026) with no entry on 18 November |
| Arch Linux | Fixed | nginx 1.30.7-1 (build 16:42:05, repository 17:08:59) and nginx-mainline 1.31.9-1 (build 16:51:03, repository 16:56:25) | |
| Homebrew | Fixed | nginx 1.31.9 | Formula generated 18 November, no time |
| FreeBSD ports | Fixed in the ports tree | www/nginx 1.30.7,3 and www/nginx-devel 1.31.9 | Commit at about 16:32 (FreshPorts time zone not stated), "Security update to 1.30.7". No VuXML entry. The first fetch at 19:41 showed stale versions, and the 19:55 re-check shows the fix. Binary package availability was not checked |
| Gentoo | In the tree | www-servers/nginx 1.30.7 and 1.31.9 | Keywords and times not read, GLSA not checked |
| Fedora | COULD NOT VERIFY | Unknown | Bot challenge. Repology (stale) lists Fedora 43 to 45 at 1.30.6, which is weak evidence only. Red Hat Bugzilla has no bug for either CVE (0 matches by alias and by text search), and a web search found no Fedora update (19 November) |
| Bitnami | Unconfirmed | "[bitnami/nginx] Release 1.31.9-debian-12-r0" in the source repository (16:43) | The bitnami/nginx "latest" tag was updated at 18:48, and the image contents were not inspected. bitnamilegacy/nginx is frozen (2025) |
| Heroku | Fixed | nginx 1.30.7 on the PHP platform | Dev Center changelog item 3920, "Change effective on 18 November 2026" (no time). It names CVE-2026-123007, CVE-2026-123633 and CVE-2026-118899 |
| cPanel and Plesk | COULD NOT VERIFY | Unknown | No statement found from AWS, Azure, Google Cloud, Cloudflare or Vercel either (COULD NOT VERIFY) |
| Forks and products built on nginx | No fix shipped | None | freenginx (newest 1.31.5, 27 October 2026, no statement), Angie (newest 1.12.4, 16 October 2026, no statement), OpenResty (newest v1.31.8.1, 26 October 2026, nginx 1.31.8 base), Tengine (newest 3.2.0-rc5, 4 September 2026), Kong OSS (newest 3.9.4, 12 October 2026) and community ingress-nginx (retired, no fix expected) |

The biggest gaps are Debian stable, Ubuntu, Red Hat, SUSE and Rocky Linux, which many servers run, community ingress-nginx, which is retired, and the older branches that have no fixed release. Until a distro ships a fixed package, the HTTP/2 stopgap in the PROTECTION ROADMAP is what those servers can do. For anything marked unconfirmed, check the vendor's own advisory before you rely on a package.

Two things to know about F5's products. First, F5's advisories (WEAK, read through a browser render) list "NGINX (all other products)" as "Not vulnerable" and have no separate rows for Ingress Controller, Gateway Fabric or Instance Manager. Metnir says it crashed the shipped Gateway Fabric binaries (and those of Kong, Apache APISIX and community ingress-nginx) with the CVE-2026-123633 bug, and reproduced it in OpenResty. F5 shipped new Ingress Controller and Gateway Fabric releases on 18 November, and the notes we saw do not mention these CVEs. Second, the timestamps for the F5 images and releases of 18 November (Ingress Controller v5.8.0 images at 13:10, the 2026-lts-r11 tag at 13:28, the Gateway Fabric v2.9.0 release at 13:29 and the Ingress Controller GitHub release at 14:29) come from before F5's 15:00 datePublic, and public availability of those images is not established.

Other F5 products, from the advisories (WEAK): "NGINX One Console" and "F5 Distributed Cloud (all services)" are marked "**", which means F5 is still researching. BIG-IP, BIG-IQ, F5 Insight, F5OS, BIG-IP Next and CNF are "Not vulnerable". For F5 App Protect, Instance Manager and F5 notice K000164058 we could not verify anything (COULD NOT VERIFY).

*Sources: vendor and distro pages and trackers as of 19 November 2026, 04:30 UTC (nginx.org download, CHANGES and package repositories, F5 advisories and NGINX Plus release notes, F5 NGINX Ingress Controller and Gateway Fabric repositories and Docker Hub tag lists, Debian security tracker, Ubuntu CVE tracker, Red Hat CVE page and CSAF VEX files, Rocky Linux errata, AlmaLinux errata page, Oracle Linux and SUSE CVE pages, Amazon Linux Security Center, Alpine security database and package pages, Arch package pages, Homebrew formula, FreshPorts, Gentoo package page, Repology, Bitnami containers repository, Heroku Dev Center changelog, release feeds of freenginx, Angie, OpenResty, Tengine and Kong, ingress-nginx repository)*

### Where HTTP/2 is switched on

Only servers with HTTP/2 on are exposed, so what turns HTTP/2 on tells you which servers to patch first. The bugs are in nginx's HTTP/2 module, not in these products, and the fix is the same everywhere: a fixed nginx build and a restart. "Inferred" means we read config, build or source files and drew a conclusion that no vendor states outright. Nothing was run.

| Where | What we found | On by default? |
| --- | --- | --- |
| Upstream: nginx source build | "This module is not built by default, it should be enabled with the --with-http_v2_module configuration parameter." The stock conf/nginx.conf has `listen 80;` and a commented TLS block with no http2, and the `http2` directive's documented default is off. HTTP/2 is switched on with `http2 on;` per server (1.25.1 and later) or the legacy `listen ... http2` parameter. Either one enables it (inferred), so `http2 off;` does not override a leftover `listen` parameter. On a plain listener the same switch accepts cleartext HTTP/2 (h2c) (inferred) | No |
| Packages: nginx.org (Debian, RPM, Alpine) and the Docker official image | The module is compiled in (inferred from build files). default.conf is `listen 80;` only, and the Docker entrypoint scripts have no http2 | No (inferred) |
| Distro: Debian and Ubuntu | The module is compiled in (Debian 1.30.6-3 and 1.26.3-3+deb13u10 rules and Ubuntu launchpad rules, whose version was not read. Debian bookworm was not read). The default sites are `listen 80 default_server;` with a commented 443 line | No (inferred) |
| Distro: RHEL family (CentOS Stream files, the upstream of RHEL packaging, not RHEL itself) | c10s has `listen 80;` with `http2 on;` only in commented lines. c9s has a commented `listen 443 ssl http2;` | No (inferred) |
| Distro: Alpine | default.conf is `listen 80 default_server;` | No (inferred) |
| Distro: Fedora | COULD NOT VERIFY (bot challenge) | Not verified |
| Product: community ingress-nginx | The ConfigMap key `use-http2` defaults to "true" ("Enables or disables HTTP/2 support in secure connections"), and the template adds `http2 on;` to each server block when it is true. The project was retired and archived on 24 March 2026: "there will be no further releases, no bugfixes, and no updates to resolve any security vulnerabilities" | Yes |
| Product: Kong | kong.conf.default has `proxy_listen = 0.0.0.0:8000 reuseport backlog=16384, 0.0.0.0:8443 http2 ssl reuseport backlog=16384` and `admin_listen = 127.0.0.1:8001 reuseport backlog=16384, 127.0.0.1:8444 http2 ssl reuseport backlog=16384`. `status_listen` has no http2 | Yes, on the 8443 and 8444 listeners |
| Product: Apache APISIX | The default table in apisix/cli/config.lua has `enable_http2 = true,`, and the nginx template adds `http2 on;` when it is true | Yes |
| Product: F5 NGINX Ingress Controller | The ConfigMap key `http2` defaults to "False". The `nginx.org/http2` annotation or the VirtualServer `http2` field can turn it on per resource | No |
| Product: NGINX Gateway Fabric | Metnir says it enables HTTP/2 by default. We did not verify that | Not verified (COULD NOT VERIFY) |
| Product: OpenResty | The docker-openresty alpine image (RESTY_VERSION 1.31.8.1) builds with both `--with-http_v2_module` and `--with-http_v3_module`. Whether a source build or OpenResty's own config enables HTTP/2 by default is COULD NOT VERIFY. An OpenResty GitHub issue (1165, opened 18 November, 16:33 UTC) says "OpenResty 1.31.8.1 is based on nginx 1.31.8, which is vulnerable to CVE-2026-123633 and CVE-2026-123007. Please update Openresty ASAP. Mitigations: disable http2." The saved page shows no maintainer reply | Not verified |
| Product: Tengine, Angie and freenginx | Tengine has the HTTP/2 module off by default (HTTP_V2=NO), its nginx core is 1.31.5 (inside the affected range, inferred) and it made no statement. Angie does not build the module by default per its docs, its security page does not mention either CVE, and whether its HTTP/2 code shares the flaws is not established. freenginx made no statement, and whether it is affected is COULD NOT VERIFY | Tengine and Angie: not built by default |
| Proxy or CDN: Cloudflare | "At Cloudflare, HTTP/2 connection to the origin is enabled by default." It connects with HTTP/2 only to origins that announce it through ALPN and falls back to HTTP/1.1 otherwise. Free, Pro and Business plans: "Enabled by default". Enterprise: "Disabled by default (1 stream per connection)". The switch is Speed > Settings > Protocol Optimization > HTTP/2 to Origin | Yes on Free, Pro and Business, to origins that offer HTTP/2 |
| Proxy or CDN: AWS ALB | "By default, Application Load Balancers send requests to targets using HTTP/1.1." A target group's protocol version can be set to HTTP/2 or gRPC | No, HTTP/1.1 to targets |
| Proxy or CDN: CloudFront | "CloudFront forwards requests to your custom origin using HTTP/1.1" | No, HTTP/1.1 to custom origins |
| Proxy or CDN: Akamai | When HTTP/2 is on, the connection from the edge to the origin is non-HTTP/2 by default. An "HTTP/2 Edge to Origin" option exists (introduced 29 July 2025). The 7 May 2026 catalog says it is now in General Availability for Property Manager and more, and we did not read that line to the end | No by default |
| Proxy or CDN: Fastly | We could not verify an explicit HTTP/2-to-origin statement (COULD NOT VERIFY). Its docs say it supports any backend that is an HTTP/1.1 compliant web server | Not verified |
| Hosting stacks: cPanel and Plesk | COULD NOT VERIFY (nothing found) | Not verified |

- This is read from package and build files and vendor documentation. It is not a survey of real servers.
- Scale, as a rough guide only: W3Techs (18 November 2026) says "Nginx is used by 29.7% of all the websites whose web server we know." HTTP/2 is used by 35.6% of all websites, which is a separate population, so do not multiply the two. Netcraft's September 2026 survey counts 1,470,435,351 sites, with nginx on 225,366,509 of them (15.3%), and Wiz's "more than 225 million websites" matches. Netcraft's August 2026 narrative shows a large swing in nginx's count, so that figure is volatile. No source we can use counts nginx hosts with HTTP/2 on (see Global impact statistics for the Censys tracker).
- Whether either bug can be triggered through a proxy that speaks HTTP/2 to the origin is unknown. No source tested it.

*Sources: nginx documentation (configure, ngx_http_v2_module and ngx_http_core_module) and source files, nginx, Debian, Ubuntu, CentOS Stream, Alpine and Docker packaging and config files, ingress-nginx, Kong and Apache APISIX files, F5 NGINX Ingress Controller documentation, docker-openresty Dockerfile and OpenResty GitHub issue, Tengine, Angie and freenginx files and pages, Cloudflare, AWS, Akamai and Fastly documentation, Metnir, Wiz, W3Techs, Netcraft*

---
## ATTACK TIMELINE

### How fast this moved

| When (UTC) | What happened |
| --- | --- |
| 22 September 2015 | nginx 1.9.5 ships the HTTP/2 module. It is the first version affected by CVE-2026-123007 |
| 11 February 2021, 18:52 | Commit 76672e650, "HTTP/2: reuse of connections with incomplete frames." (Maxim Dounin). The CVE-2026-123633 fix commit names it as the change that made the bug possible |
| 16 February 2021 | nginx 1.19.7 is released. It is the first version affected by CVE-2026-123633 (inferred that the 11 February commit is in 1.19.7) |
| 13 June 2023 | nginx 1.25.1 adds the `http2` directive and removes server push |
| 12 September 2026 | Metnir says it reported CVE-2026-123633 to F5 (date only). The author date of the CVE-2026-123633 fix commit is 17 September, 12:10 |
| 14 October 2026 | NGINX Plus 37.0.7.1 (LTS) and 37.2.0.1 (CR) are released. Their release notes list the CVE-2026-123633 fix. The CVE IDs were only reserved on 9 November, so the CVE number was added to those notes later (our reading) |
| 16 October 2026 | Xint reports to F5 through HackerOne. The report is validated on 20 October and delivered to F5's nginx development team on 27 October |
| 21 October 2026 | Wiz reports CVE-2026-123633. F5 says another team had reported it first |
| 24 October 2026 | F5 confirms the use-after-free to Metnir and agrees a release date |
| 29 October 2026, 17:37 | Author date of the CVE-2026-123007 fix commit |
| 9 November 2026, 18:42 | Both CVE IDs are reserved (18:42:53). The nginx team asks Xint to validate the patch |
| 10 November 2026 | F5 sends Wiz a patch for review. Xint finishes its validation |
| 11 November 2026 | Rapid7 first contacts F5. The fix commits carry committer dates of 12:13 (CVE-2026-123633) and 12:16 (CVE-2026-123007) on master, and 18:08 for the stable-1.30 copy of the CVE-2026-123633 fix. nginx.org tarball file times are 17:59 (1.31.9) and 18:09 (1.30.7), and nginx.org binary package builds are dated 20:04 to 21:12. These are directory-listing and build times, not publication times |
| 12 November 2026 | Rapid7 sends its details to F5, and F5 confirms receipt |
| 16 November 2026 | Wiz reports CVE-2026-123007. F5 confirms to Rapid7 that it validated the report, assigned the CVE and set disclosure for 18 November |
| 17 November 2026 | F5 confirms to Wiz that CVE-2026-123007 is in the planned 18 November release |
| 18 November 2026, 13:10 to 14:29 | F5 NGINX Ingress Controller v5.8.0 images appear on Docker Hub (13:10), then the 2026-lts-r11 tag (13:28), the NGINX Gateway Fabric v2.9.0 release (13:29) and the Ingress Controller v5.8.0 GitHub release (14:29). These timestamps are from before F5's publication time, and public availability of the images isn't established |
| 18 November 2026, 14:00 | Rapid7's post carries this date in its metadata, one hour before F5's publication time. When the post went live isn't established |
| 18 November 2026, 15:00 | F5's publication time (datePublic) for both CVE records |
| 18 November 2026, 15:07 to 15:19 | Xint's post (15:07), Wiz's post (15:13) and a Hacker News story that links the Wiz post (15:19) |
| 18 November 2026, 15:20 to 15:23 | Pushes to nginx master (15:20, "nginx-1.31.9-RELEASE") and stable-1.30 (15:22). Both CVE records are published (CVE-2026-123633 at 15:23:27, CVE-2026-123007 at 15:23:29). Rapid7's proof-of-concept repository was last pushed at 15:23 |
| 18 November 2026, 15:48 to 15:56 | The nginx.org download, CHANGES and advisories pages are last modified (15:48 to 15:49). GitHub tags release-1.31.9 (15:54) and release-1.30.7 (15:56) |
| 18 November 2026, 16:04 to 16:38 | CISA's ADP entry for CVE-2026-123007 with its SSVC assessment (16:04). NCSC-NL advisory (16:07). NVD receives both records (16:18). CISA's ADP entry for CVE-2026-123633 (16:38) |
| 18 November 2026, 16:32 to 17:22 | Fixed builds reach platforms: FreeBSD ports (about 16:32, FreshPorts time), Arch (builds at 16:42 and 16:51), the Bitnami source repository (16:43), Alpine 3.24 and edge (builds at 17:06 and 17:11) and the Docker official image tags (17:15 to 17:22) |
| 18 November 2026, 17:04 | The first proof-of-concept sighting appears in CIRCL's sightings feed |
| 18 November 2026, 17:27 to 17:30 | CCB Belgium's warning is listed by a news aggregator (17:27, WEAK, because the page itself returned Access Denied), and CERT-EU publishes Security Advisory 2026-022 (17:30, shown as 18:30 CET) |
| 18 November 2026, 18:31 to 19:54 | The Hacker News publishes its article (18:31). The bitnami/nginx "latest" tag is updated (18:48). CISA KEV catalog 2026.11.18 is released with neither CVE listed (19:17). The Docker official alpine-perl and alpine-otel variants get their images (19:52 to 19:54) |
| 18 November 2026, 18:56 to 19:02 | The Debian changelog for nginx 1.30.6-4 in sid is signed (18:56), with the fixes for both CVEs backported from 1.30.7, and the tracker showed it later. The Canadian Cyber Centre updates AV26-1174 (19:02) |
| 18 November 2026, 20:13 to 20:35 | The CVE Program adds reference links to both CVE records (20:13 and 20:14, none tagged as an exploit) and NVD copies them (20:18). A post to the oss-security mailing list, "CVE-2026-123633, CVE-2026-123007: nginx RCE via HTTP/2", follows (20:35) |
| 18 November 2026, 21:03 | SUSE's pages for both CVEs are created, with every product in state "Analysis" (the page does not state a time zone) |
| 18 November 2026, 21:17 to 21:29 | NVD adds one more reference link to each record (21:17), and Red Hat's VEX files reach revision 3 (21:27 for CVE-2026-123007, 21:29 for CVE-2026-123633). CVE-2026-123633 now has a Red Hat record: Affected, no erratum |
| 18 November 2026, 21:57 to 22:25 | Censys Research creates a lab repository with proof-of-concept material (21:57), and a third party repository that claims a full code execution chain for CVE-2026-123007 gets its commit (22:25). Names withheld, nothing verified |
| 18 November 2026, 22:17 to 23:17 | The CVE-2026-123633 record is updated (22:17), and NVD logs a further change to it (23:17). Both CVEs stay "Received" in NVD |
| 18 November 2026, 22:45 to 23:09 | AlmaLinux 10 (ALSA-2026:A024, record modified 22:45) and AlmaLinux 9 (ALSA-2026:A025, 23:00) get fixes, and Amazon Linux 2023 releases ALAS2023-2026-3494 (23:09). The Amazon Linux 2027 Preview advisories ALAS2027-2026-386 and ALAS2027-2026-385 are dated 18 November, with no time shown |
| 18 November 2026, 23:29 | Qualys's post (dated 18 November) is listed by a news aggregator. It names QIDs 736231 and 389654 as pending (WEAK: the text came through a fetch tool after curl was blocked) |
| 19 November 2026, 00:18 | Tenable's FAQ says there are no reports of threat actors exploiting these CVEs as of 18 November |
| 19 November 2026, 01:00 | HKCERT's bulletin (09:00 +0800) says proof-of-concept exploit code is publicly available for CVE-2026-123007 |
| 19 November 2026, 01:08 to 01:10 | Alpine 3.22 and 3.23 list nginx 1.28.3-r8, a backport that fixes both CVEs (build times as printed by Alpine, time zone not stated) |
| 19 November 2026, 01:20 | Amazon Linux 2 (Nginx1 Extra) releases ALAS2NGINX1-2026-018 |
| 19 November 2026, 02:20 to 04:10 | More repositories appear: a lab repository that claims a small proof of concept (02:20), a Docker lab (03:56) and an open pull request that adds a detector for both CVEs to an open source vulnerability tool (04:10). Names withheld, nothing verified |
| 19 November 2026, 04:06 | Censys refreshes the snapshot of its public exposure tracker. Its figures are not quoted here |
| 19 November 2026, 04:30 | Data cut-off for this analysis. The new checks ran from 04:27 to 04:48 UTC, and facts fetched after 04:30 carry their own times |

Critical insight: for the open source code, the fixes were not public long before the release. The commit dates say 11 November, but GitHub's activity log shows no push to nginx master between 9 November 13:29 and 18 November 15:20 UTC, so the fixes reached GitHub on 18 November, 20 minutes after F5's publication time (our reading). Two Hacker News comments say the fix was public a week earlier, and the push log doesn't support that. Whether the 11 November tarballs could be downloaded before 18 November isn't established. The head start that did exist went to NGINX Plus customers: F5's release notes list the CVE-2026-123633 fix in builds from 14 October, 35 days before disclosure (our arithmetic). The CVE IDs were only reserved on 9 November, so the CVE number was added to those notes later (our reading). After disclosure everything moved in hours. Xint's post came 7 minutes after F5's 15:00 UTC publication time and Wiz's 13 minutes after. Rapid7's proof-of-concept repository was last pushed at 15:23. CIRCL's feed first saw a proof of concept at 17:04, 2 hours 4 minutes after disclosure, and about four hours after disclosure one unverified third party repository claimed to reproduce code execution on a stock container image. By 04:30 UTC on 19 November more third party exploit repositories, a Censys Research lab repository and an HKCERT statement that a proof of concept is public had followed, none of it verified. NCSC-NL wrote at 16:07, before that first sighting, that it expected proof-of-concept code soon and large-scale exploitation after it. Platforms moved fast too: FreeBSD ports, Arch, Alpine 3.24 and edge and the Docker official image had a fixed build within about two and a half hours of disclosure, and Homebrew the same day. At 20:00 UTC, five hours in, Debian, Ubuntu, Red Hat, Rocky Linux and Amazon Linux had no fixed package. By 04:30 UTC on 19 November, Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had shipped fixes, while Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux still had none. For an internet-facing server with HTTP/2 on, "we'll patch it next window" isn't a plan.

*Sources: nginx.org security advisories, CHANGES and download pages, the nginx source repository and its commit history and activity log, F5 advisories and CVE records, F5 NGINX Plus release notes, Xint, Wiz, Rapid7 and Metnir write-ups, Hacker News, NVD, CISA's entries in the CVE records, NCSC-NL, CIRCL sightings feed, CISA KEV catalog, Docker Hub and the Docker official images repository, Alpine, Arch, FreeBSD ports (FreshPorts), Bitnami, The Hacker News*

### Who's attacking

No exploitation in the wild has been reported as of about 04:30 UTC on 19 November 2026 (disclosure was at 15:00 UTC on 18 November), so there is nobody to attribute. No threat actor is known to be using either bug. Here is what each source said by then:

| Source | What they said or showed | Confidence |
| --- | --- | --- |
| CISA | Not in KEV (catalog 2026.11.18, released 19:17 UTC, 1786 entries, checked at 19:59 and 20:10 UTC on 18 November and at 04:27, 04:45 and 04:48 UTC on 19 November). Its ADP entries (CISA Vulnrichment, SSVC 2.0.3) give both CVEs: Exploitation none, Automatable no, Technical Impact total. They are stamped 16:04 UTC (CVE-2026-123007) and 16:38 UTC (CVE-2026-123633) | Negative. Unchanged at the rechecks |
| CIRCL | Its sightings feed showed, at the 18 November check (not re-run on 19 November), CVE-2026-123007 with 68 sightings (66 "seen", 2 "published-proof-of-concept", 0 "exploited") and CVE-2026-123633 with 47 (46 "seen", 1 "published-proof-of-concept", 0 "exploited"). Its notice says exploitation shown in a research setting is "not by itself proof of widespread in-the-wild campaigns" | Tracker counts, not attack data |
| Previdian | Says "Previdian sensors have not observed exploitation attempts against either of these vulnerabilities." Says Wiz has not published exploit code and Rapid7 has published a proof of concept for CVE-2026-123007 | WEAK. Its own sensors, no data shown |
| NCSC-NL | NCSC-2026-0506 (16:07 UTC) is rated H/H (high likelihood, high impact) and covers all ten bugs fixed in the release. It expects proof-of-concept code soon and large-scale exploitation after that | Forecast, written before the first proof-of-concept sighting |
| CERT-EU | Security Advisory 2026-022, "Critical vulnerabilities in Nginx" (18 November, 17:30 UTC, shown as 18:30 CET), says "no exploitation in the wild has been reported yet". It says worker-crash log lines are "not a high-fidelity indicator of successful remote code execution but rather an indication of exploitation attempts" | Advisory only, no attack data |
| CERT-FR and Canadian Cyber Centre | CERT-FR alert CERTFR-2026-ALE-017 confirms a public proof of concept for CVE-2026-123007 and recommends disabling HTTP/2 until fixes are applied. The Canadian Cyber Centre's AV26-1174 (updated 18 November, 19:02 UTC) covers the fixes | Advisories only, no attack data |
| HKCERT | Bulletin dated 19 November, 09:00 (+0800), which is 01:00 UTC: "Proof of Concept exploit code is publicly available for CVE-2026-123007." It also lists CVE-2026-123640 | Advisory only, no attack data |
| CCB Belgium | "Warning: Multiple Critical NGINX Vulnerabilities, Patch Immediately!", listed by a news aggregator at 17:27 UTC on 18 November. The page itself returned Access Denied | WEAK. Headline and time only, no attack data |
| oss-security | A mailing list post, "CVE-2026-123633, CVE-2026-123007: nginx RCE via HTTP/2" (18 November, 20:35 UTC), that lists the ten bugs fixed in the release, points to nginx.org's advisories page and quotes parts of Wiz's advisory | Notice only, no attack data |
| F5, Tenable and Qualys | F5's spokesperson told The Register: "At this time, we have found no evidence of active exploitation of any of these vulnerabilities in the wild". Tenable's FAQ (00:18 UTC on 19 November): "There are no reports of threat actors exploiting these CVEs as of November 18." Qualys: "As of November 18, 2026, we have not seen public confirmation of exploitation in the wild." | Statements, no attack data. The Qualys text came through a fetch tool after curl was blocked, so WEAK |
| Rapid7 | Published a proof of concept for CVE-2026-123007 only (repository last pushed 15:23 UTC). Its notes say it suits only a freshly started local container and will likely fail against several concurrent clients, a worker that has run for some time, or a network proxy in the path. No Metasploit module | Lab result, not an attack |
| Wiz | Built exploits for both bugs and confirmed code execution with an ASLR bypass on official nginx 1.31.7 and 1.31.8 builds. Says "we will not be releasing these exploits at this time". Says widespread attacks tend to start against packaged products where many customers run the same build and configuration | Lab result, not an attack |
| Xint | Shows unauthenticated code execution as the worker user in its lab, and says its unreleased exploit "works under concurrent normal traffic and across servers with different hardware specifications". Says it chained a separate Linux kernel flaw to reach root and withholds the details of that flaw. We could not verify the root claim (COULD NOT VERIFY), and Wiz, Rapid7 and Metnir claim no root | Lab result, not an attack. The root claim is Xint's alone |
| Metnir | Shows a command running "as the unprivileged nginx user" for CVE-2026-123633 only. Withholds its exploit while patched builds reach distributions and downstream products | Lab result, not an attack |
| GitHub | A search for either CVE ID in quotes returns 18 repositories (04:45 UTC on 19 November, unchanged at 04:48; CVE-2026-123007: 15, CVE-2026-123633: 6, with overlap). The figure counts search matches, not verified exploits, and 7 of the 18 were created after 20:10 UTC on 18 November. By their own descriptions, the repositories we read include third party exploit and proof-of-concept claims for CVE-2026-123007 (one claims a full code execution chain and one records a reproduction with success logs), a lab repository published by Censys Research, Docker labs and read-only scanners. The count was still rising (17 at 04:28 UTC, 18 at 04:45 UTC) | Not verified. Treat as untrusted |
| Security vendors | Tenable still has no plugins for either CVE ("Coming Soon" on 18 November, empty plugin lists at 04:28, 04:45 and 04:48 UTC on 19 November). Qualys lists QIDs 736231 (NGINX Open Source) and 389654 (F5 NGINX Plus), both naming F5 notice K000164058, as pending, with release shown as "TBD By EOD" (WEAK: the text came through a fetch tool after curl was blocked). An open pull request, created at 04:10 UTC on 19 November, adds a detector for both CVEs to an open source vulnerability tool, and community scanners exist, none vetted. Rapid7's vulnerability database has pages for both and shows no check. Snyk rates CVE-2026-123007 critical with Exploit Maturity "Proof of Concept". Sophos (WEAK) says it is investigating and has announced no protection. There is no rule in Emerging Threats Open (the ruleset file dates from 17 November, before disclosure) or the Snort 3 community rules (0 matches in 4,040 rule lines), no Sigma, Elastic or CIRCL Rulezet rule, no Nuclei template (one path checked), no Metasploit module, and no entry in the Cloudflare WAF changelog or the AWS WAF managed rules changelog. Akamai, Fastly, Imperva, Fortinet and F5 BIG-IP guidance: nothing found | Detection content, no attack data |
| Press | The Hacker News (18:31 UTC): "Neither the vendor nor the Wiz and Rapid7 researchers have reported any attacks exploiting the flaw so far. CISA's Known Exploited Vulnerabilities catalog did not list it as of today." CyberScoop also covers the disclosure | Secondary sources |

Proof-of-concept status per CVE, with no repository names:

| CVE | Public proof of concept | Notes |
| --- | --- | --- |
| CVE-2026-123007 | Yes. Rapid7 published one. CERT-FR confirms it, Sophos (WEAK) says the same, and CIRCL's feed first saw it at 17:04 UTC on 18 November. HKCERT says "Proof of Concept exploit code is publicly available" (19 November, 01:00 UTC). Censys Research published proof-of-concept material, and unverified third party repositories claim exploit code, one with a full code execution chain | Rapid7's code is aimed at a freshly started container, with the limits above. Censys Research's README says its compact proof of concept "is not an RCE exploit", but it also says Rapid7's full code execution chain was independently reproduced in its lab, and the repository holds a file naming code execution as confirmed. The third party claims are not verified. Wiz and Xint withhold theirs. For Ikotas Labs no publication or proof of concept was found (COULD NOT VERIFY) |
| CVE-2026-123633 | No proof of concept from Wiz, Xint or Metnir is public. HKCERT's statement names CVE-2026-123007 only | Wiz, Xint and Metnir withhold their exploits. Censys Research's repository says it holds lab reproductions of the five nginx bugs in Xint's set, which include this CVE. The third party claims that mention this CVE describe a crash or denial of service, with code execution only as a possibility, and are unverified |

Where the sources disagree: Rapid7's notes say its proof of concept will likely fail against a busy server, a long-running worker or a proxy in the path, while Xint says its own unreleased exploit works under concurrent normal traffic. No source gives results that settle how reliable exploitation is. One press report says working exploits exist for all the flaws it covers, but among the four research teams only Rapid7 has published code, and none of the third party code that has appeared since is verified. A vulnerability database (Wiz) still showed "Has Public Exploit: No" at 04:27 UTC on 19 November although Rapid7's code is public, so aggregator flags lag, while VulnCheck's exploit database lists a third party repository for CVE-2026-123007 (dated 18 November). Of the six unverified third party claims we first reviewed, one describes the CVE-2026-123633 mechanism in a way that conflicts with nginx's own fix commit and one mislabels a different nginx CVE, so treat all six as unreliable. One of them claims, about four hours after disclosure, to reproduce code execution on a stock container image, and another describes a non-destructive check mode next to an exploit mode. Our reading: a non-destructive check mode makes mass scanning easier to build. A Telegram post flagged as a proof of concept for both CVEs is unverified.

Absence of reports is weak evidence, and some sources couldn't be read or checked at all. GreyNoise was blocked and Shadowserver had no report, so there is no telemetry from either (COULD NOT VERIFY). We found nothing in the SANS ISC, Help Net Security, Dark Reading and Security Affairs feeds, and no CISA alert mentions nginx or F5. Our reading: confidence that nothing is being exploited is moderate, because no primary telemetry was reachable. There is no IP list or attack pattern to give you, and no indicators of compromise have been published. Skip the repositories too: none was opened or run for this analysis, nobody has verified any of the third party code, and running unknown proof-of-concept code is a common way to get compromised. To find out whether you're exposed, use the checks in AM I AFFECTED? SELF-ASSESSMENT.

*Sources: CISA KEV catalog and the SSVC entries in the CVE records, CIRCL, Previdian, NCSC-NL, CERT-EU, CERT-FR, Canadian Cyber Centre, Rapid7, Wiz, Xint, Metnir, GitHub repository search, Tenable, Snyk, Sophos, Emerging Threats Open and Snort community rules, Cloudflare and AWS WAF changelogs, The Hacker News, CyberScoop, The Register, HKCERT, CCB Belgium (WEAK), the oss-security list, Qualys (WEAK), Censys Research, VulnCheck (checked on 18 November 2026, up to 20:10 UTC, and again on 19 November 2026, 04:27 to 04:48 UTC)*

### Global impact statistics

- **No usable count exists** of internet-facing nginx servers with HTTP/2 switched on, and this analysis gives none. Censys runs a public tracker (since 18 November, snapshot refreshed at 04:06 UTC on 19 November) that sorts what it scans into groups such as "In range, HTTP/2 on", "Distro build, HTTP/2 on", patched and mitigated. Its page says its figures count services, and we quote none of them. Shadowserver's Vulnerable HTTP report page has no entry for these CVEs, and GreyNoise, Netlas and LeakIX gave us nothing (COULD NOT VERIFY). A count of nginx versions couldn't size the exposure anyway, because stock configurations ship with HTTP/2 off (inferred from the shipped files), so exposure depends on each server's settings.
- **56.7 million** hosts answered a Shodan search for product:nginx, **11.94 million (21.1%)** of them reported an identifiable version, and **98.9%** of those fell within the range affected by CVE-2026-123007, 1.9.5 through 1.31.8 (Xint, 10 November 2026). Xint says these numbers "are based on reported version strings and don't confirm that a server is vulnerable". HTTP/2 may be off, and a reported version may hide a backported fix. Our arithmetic, not a source figure: 98.9% of 11.94 million is about 11.8 million hosts.
- **29.7%** of the websites whose web server is known use nginx, and **35.6%** of all websites use HTTP/2 (W3Techs, 18 November 2026). Both count websites, not servers. The HTTP/2 figure covers every web server, so it doesn't say how many nginx sites have HTTP/2 on, and the two shares can't be multiplied.
- **225,366,509** sites run nginx, which is **15.3%** of the **1,470,435,351** sites in Netcraft's September 2026 survey. Wiz's "more than 225 million websites" matches that figure. Netcraft's August 2026 write-up shows a large swing in nginx's count, so the number is volatile. It counts nginx with or without HTTP/2, so it sizes the software, not the exposure. CyberScoop's "roughly a third of all websites" is its own estimate.
- **No score yet** from EPSS for either CVE. The API returned no data at 19:35, 19:48 and 19:59 UTC on 18 November and at 04:27 and 04:45 UTC on 19 November.
- **Not listed** in CISA KEV (catalog 2026.11.18), and no source checked reports exploitation in the wild.
- **18** GitHub repositories match a search for either CVE ID in quotes (04:45 UTC on 19 November; 7 were created after 20:10 UTC on 18 November). The figure counts search matches, so it is a proxy for attention, not exposure. None of the third party code is verified.

*Sources: Xint (Shodan figures, 10 November 2026), W3Techs, Netcraft, Wiz, CyberScoop, FIRST EPSS API, CISA KEV catalog, GitHub repository search, Censys tracker (named only), Shadowserver*

---

## AM I AFFECTED? SELF-ASSESSMENT

The checks below are manual and read-only. Run the host commands as root where a comment says so, or they may miss files and processes you can't read.

### Quick 3-minute assessment

**STEP 1: Which hosts run nginx? (1 minute)**

```bash
# nginx processes running now, with their owner. The one owned by root is the main process (run as root)
ps -eo user,pid,ppid,args | grep '[n]ginx: '
# Every TCP listener and the program behind it. Look for nginx on ports 80, 443 and any other port (run as root to see process names)
ss -tlnp | grep nginx
```

A container keeps the nginx it was built with, so check each one from the inside:

```bash
# nginx version inside a running container (replace <container> with its name or ID)
docker exec <container> nginx -v
```

On Kubernetes, list the workloads whose image names point at nginx or at a product built on it:

```bash
# Deployments, daemon sets and stateful sets with nginx, Kong, APISIX or OpenResty in the image name (needs read access to the cluster)
kubectl get deployments,daemonsets,statefulsets -A -o wide | grep -iE 'nginx|kong|apisix|openresty'
```

Inventories miss some places, so look there too: forgotten virtual machines and cloud images, test and staging servers that face the internet, container images built on an nginx base, Kubernetes ingress controllers and gateways (community ingress-nginx, F5 NGINX Ingress Controller, NGINX Gateway Fabric), API gateways and other products with nginx inside (Kong, Apache APISIX, OpenResty, Tengine), and appliances and vendor products that bundle a web server (ask the vendor). As of the cut-off we found no statement from cPanel, Plesk, AWS, Azure, Google Cloud, Cloudflare or Vercel, so if you rely on any of them, ask the vendor in writing whether the product contains nginx with HTTP/2 on and has the fix. Heroku says its PHP platform moved to nginx 1.30.7 on 18 November. A vulnerability scanner can give you a starting list, but Tenable's plugins for both CVEs were still "Coming Soon" at the cut-off, and a remote version check can't see whether HTTP/2 is on or whether a distro backport is installed (our reading), so use a scanner to find hosts, not to clear them.

*Sources: nginx.org documentation, F5, Kong, Apache APISIX, OpenResty and Tengine repositories, Heroku Dev Center changelog, Tenable plugin list, vendor and cloud provider security pages (checked on 18 and 19 November 2026)*

---

**STEP 2: Is this version affected, and does it carry the fix? (30 seconds)**

Start with the version-number traps, because they fool scanners and people alike. The fix is in nginx 1.31.9 (mainline) and 1.30.7 (stable), released on 18 November 2026. The two bugs have different starting points, so check each CVE:

| Build | CVE-2026-123007 affected | CVE-2026-123633 affected | Fixed in |
| --- | --- | --- | --- |
| nginx Open Source | 1.9.5 to 1.31.8 | 1.19.7 to 1.31.8 | 1.31.9 and 1.30.7 (both CVEs) |
| NGINX Plus | 37.0.0 to 37.0.7.1 and 37.1.0 to 37.2.0.1, and R34 to R36 (the CVE records also list R33) | 37.0.0 to 37.0.6.1 and 37.1.0 to 37.2.0, and R34 to R36 | CVE-2026-123007: 37.3.0.1 (CR) and 37.0.8.1 (LTS), 18 November. CVE-2026-123633: 37.2.0.1 (CR) and 37.0.7.1 (LTS), 14 October. R34 to R36: none |

```bash
# Version of the nginx program on disk (prints to the error stream)
nginx -v
# Debian and Ubuntu: installed package version, and the version your repositories offer
dpkg -s nginx | grep '^Version'
apt-cache policy nginx
# RHEL family and Amazon Linux: installed package version
rpm -q nginx
# Alpine: installed package version
apk info -v | grep nginx
# Homebrew: installed version
brew list --versions nginx
# Container: version inside a running container (replace <container> with its name or ID)
docker exec <container> nginx -v
# NGINX Plus on Debian and Ubuntu: installed package version
apt-cache policy nginx-plus
# NGINX Plus on the RHEL family: installed package version
rpm -q nginx-plus
```

**Interpretation:**

- Open source builds from nginx.org, source builds, the Docker official image and distros that follow upstream numbers: the nginx version decides. 1.31.9 or 1.30.7 or later is fixed. A server on 1.9.5 to 1.19.6 is affected by CVE-2026-123007 only, and from 1.19.7 to 1.31.8 by both. The HTTP/2 module first shipped in 1.9.5, so an older build has none.
- No fixed release exists on older branches (inferred from nginx.org's "Not vulnerable: 1.31.9+, 1.30.7+" and F5's note that end-of-support versions aren't evaluated). Distro builds can carry a backport on an older branch: Alpine 3.23 and 3.22 ship nginx 1.28.3-r8, a patched 1.28.3 that is not an upstream release. Anyone on a release before 1.30 has to move to 1.30.7 or 1.31.9 and later.
- NGINX Plus: judge the Plus package, not the open source base. 37.3.0.1 is based on nginx 1.31.8 yet contains the CVE-2026-123007 fix, so `nginx -v` can show a number below 1.31.9 on a fixed build. 37.3.0.1 and 37.0.8.1 fix both bugs (inferred: later releases on the same branch carry the earlier fix). F5's table lists R34 to R36 as affected by both with the fix as "None", and the CVE records also list R33. Our reading: Plus customers on R33 to R36 have no fixed release on their branch and must move to a fixed 37.x release.
- Trap 1, distro packages: they backport fixes without changing the nginx version. Xint says Ubuntu 24.04 ships 1.24.0, Ubuntu 22.04 ships 1.18.0 and Debian 12 ships 1.22.1, and that these distributions may backport security fixes to the existing version instead of replacing it with a new nginx release. Judge a distro package by the distro advisory, not by the version string. At the cut-off there was no fixed package from Debian stable and testing, Ubuntu, Red Hat, SUSE, Rocky Linux, AlmaLinux 8 or Alpine 3.21, while Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had fixed packages. Ubuntu also lists releases with nginx older than 1.19.7 as "needed" for CVE-2026-123633, while nginx.org's range for it starts at 1.19.7. We found no explanation (COULD NOT VERIFY).
- Trap 2, products that embed nginx carry their own numbers. OpenResty 1.31.8.1 is based on nginx 1.31.8 (inside the affected range, no fix shipped). Kong's source tree pins OpenResty 1.27.1.2, which carries nginx core 1.27.1 (inside the affected range, inferred), and we found no Kong statement. Tengine carries nginx core 1.31.5 (inside the affected range, inferred) and has made no statement. Angie and freenginx have made no statement, and whether their HTTP/2 code shares the flaws isn't established. Community ingress-nginx is retired and has no fix coming. F5 NGINX Ingress Controller v5.8.0 and NGINX Gateway Fabric v2.9.0 carry fixed builds, but the Ingress Controller 2026-lts-r11 tag has nginx 1.31.0 (inside the affected range), so a fixed LTS build is COULD NOT VERIFY.
- Trap 3, Docker tags move. The official image tags (latest, mainline, stable and the numbered ones) were updated on 18 November, so pull dates are a poor guide: check the version inside the image. The nginxinc/nginx-unprivileged image has no fixed tag.
- F5's own advisories list "NGINX (all other products)" as "Not vulnerable" (WEAK, browser render) and have no rows for Ingress Controller or Gateway Fabric, while Metnir says it crashed shipped binaries of Gateway Fabric, Kong, Apache APISIX and community ingress-nginx with the CVE-2026-123633 bug, and reproduced it in OpenResty. Ask the vendor of any product that embeds nginx.
- Where the sources disagree on versions: Metnir says its tests against older releases found related failures back to nginx 1.9.5, but the official range for CVE-2026-123633 starts at 1.19.7, so we go with F5 and nginx.org. The Hacker News headline calls the HTTP/2 flaw "10-Year-Old" and Wiz says "nearly six years" for CVE-2026-123633. Only CVE-2026-123007 goes back to 2015. CVE-2026-123633 starts in February 2021.
- What each platform has published is in the RISK DASHBOARD.

Fixed: go to STEP 5: Is the fixed build actually running? Vulnerable or unsure: go to STEP 3: Is HTTP/2 switched on?

*Sources: nginx.org security advisories and CHANGES, F5 CVE records and advisories (WEAK where read through a browser render), F5 NGINX Plus release notes, Xint, Metnir, Wiz, The Hacker News, Debian, Ubuntu, Red Hat, Amazon Linux, Alpine and Docker Hub package pages, OpenResty, Kong and Tengine repositories (checked on 18 and 19 November 2026)*

---

**STEP 3: Is HTTP/2 switched on? (30 seconds)**

These bugs are reached through HTTP/2, so a server is exposed only when all three of these hold: it runs an affected build, the HTTP/2 module is compiled in, and HTTP/2 is switched on for a listener that untrusted clients can reach. No login and no user action are needed. Disabling HTTP/2 blocks both bugs (Xint's table says "Yes" for both, and Wiz, CIRCL and CERT-FR give the same advice).

```bash
# Whether the HTTP/2 module is compiled in. No output means it is not (run as root if nginx is not on your path)
nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
# Whether HTTP/2 is switched on in the config on disk. Reads every included file (run as root)
nginx -T 2>&1 | grep -nE '^[[:space:]]*(listen[[:space:]][^#]*[[:space:]]http2([[:space:]]|;)|http2[[:space:]]+on[[:space:]]*;)'
```

Containers keep their config inside the container, so run the same two checks there:

```bash
# Container: is the HTTP/2 module compiled in? (replace <container> with its name or ID)
docker exec <container> nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
# Container: is HTTP/2 switched on in its config? (replace <container> with its name or ID)
docker exec <container> nginx -T 2>&1 | grep -nE '^[[:space:]]*(listen[[:space:]][^#]*[[:space:]]http2([[:space:]]|;)|http2[[:space:]]+on[[:space:]]*;)'
```

**Interpretation:**

- Both parts must be true: the module is compiled in (the first command prints `--with-http_v2_module`) and a listener has HTTP/2 on (the second command prints a line). A build without the module has no HTTP/2 code, and Xint says absent means not affected. Source builds don't compile the module unless asked: "This module is not built by default, it should be enabled with the --with-http_v2_module configuration parameter." The nginx.org packages for Debian, RPM and Alpine, the Docker official image, Debian, Ubuntu, the RHEL family (we read CentOS Stream's package files, not RHEL itself) and Alpine all compile it in (inferred from build files, nothing was run). Fedora is COULD NOT VERIFY. On a packaged server the config decides.
- Two syntaxes switch HTTP/2 on: `http2 on;` in a server block (nginx 1.25.1 and later) and the older `listen ... http2` parameter, as in `listen 443 ssl http2;` (deprecated since 1.25.1, and the only form from 1.9.5 to 1.25.0). Either one enables it (inferred from the source), so `http2 off;` doesn't override a leftover `listen ... http2` parameter. Xint says the same in practice: remove any legacy http2 parameter and check all server blocks that share the listening address and port. The second command matches both syntaxes.
- On a plain listener the same switch accepts cleartext HTTP/2 (h2c) from clients that send the HTTP/2 preface first (inferred, no HTTP/1.1 Upgrade path found in the source). No source says whether the bugs are reachable over h2c, and the public demonstrations we read all used TLS with HTTP/2. No source says whether 32-bit builds are affected, and Wiz's test was on 64-bit systems.
- CVE-2026-123007 needs only HTTP/2 on. F5 states no proxy, static-file, server push, HPACK or stream-setting condition. Wiz (secondary, a lab claim that isn't in F5's text) says its test "demonstrated code execution on NGINX serving ordinary static files, without a backend application or third-party modules", over HTTPS on 64-bit systems. So a static-only site with HTTP/2 on is exposed to this bug. Server push was removed in nginx 1.25.1, and no source ties either bug to HPACK or stream settings.
- CVE-2026-123633 needs three things at once: HTTP/2 for client connections, proxying client requests to a backend, and a worker running low on worker_connections (F5's text). Xint's table says "HTTP/2 with requests forwarded to an upstream (backend) server". A server that only serves static files is outside this bug (our reading of F5's wording). If the same server forwards requests to an upstream, treat it as in scope for both bugs.
- Stock installs have HTTP/2 off (inferred from the shipped files, and the documented default of the `http2` directive is off). The nginx source tree, the nginx.org packages, the Docker official image, Debian, Ubuntu, RHEL (CentOS Stream files) and Alpine all ship a plain `listen 80;` server. The RHEL files carry `http2 on;` or `listen 443 ssl http2;` only in commented lines. HTTP/2 on a fresh install therefore means an admin or a product switched it on.
- Products that switch HTTP/2 on by default: community ingress-nginx (the ConfigMap key `use-http2` defaults to "true", and the template adds `http2 on;` to each server block), Kong (the default `proxy_listen` and `admin_listen` strings carry `http2` on ports 8443 and 8444, and `status_listen` has none) and Apache APISIX (`enable_http2 = true` in its default table). Metnir says Kong, Apache APISIX, NGINX Gateway Fabric and community ingress-nginx "enable HTTP/2 by default". We did not verify the Gateway Fabric default (COULD NOT VERIFY). F5 NGINX Ingress Controller is the opposite: its ConfigMap key `http2` defaults to "False", and the `nginx.org/http2` annotation or the VirtualServer `http2` field can turn it on per resource.
- Other nginx-based products: OpenResty's Docker alpine image compiles in both the HTTP/2 and HTTP/3 modules, and whether OpenResty's own config enables HTTP/2 by default is COULD NOT VERIFY. Tengine has its HTTP/2 module off by default. Angie's documentation says its HTTP/2 module isn't built by default.
- HTTP/3 (QUIC) is a separate switch (`--with-http_v3_module`, `listen ... quic`) and is not in scope for these two CVEs. The HTTP/3 use-after-free CVE-2026-121810 is fixed in the same release, and turning HTTP/2 off doesn't block it.
- A hit from the second command means a directive exists, not that the port is reachable, so follow with the checks in STEP 4. `nginx -T` reads the config on disk, so if the config changed without a reload, the running config may differ (Xint). The dump can include secrets from included files, so keep the grep (our reading). `nginx -t` and `nginx -T` try to open the files named in the config (certificate keys, logs, the pid file), which are usually readable by root only, and Xint runs them with sudo. `nginx -V` and `nginx -v` need only permission to run the binary.

*Sources: nginx.org documentation (ngx_http_v2_module, ngx_http_core_module, configure, switches) and source, Debian, Ubuntu, CentOS Stream, Alpine, Docker and nginx.org packaging files, ingress-nginx, Kong, Apache APISIX, F5 NGINX Ingress Controller, OpenResty, Tengine and Angie files and documentation, F5 CVE records, Xint, Wiz, Metnir, CIRCL, CERT-FR (checked on 18 November 2026)*

---

**STEP 4: Does a CDN or load balancer in front speak HTTP/2 to your origin? (30 seconds)**

The bugs are reached through HTTP/2 itself, so what matters is which protocol the proxy speaks to your origin. When a CDN or reverse proxy sits in front of nginx, the two checks below reach only the proxy (Xint), so run them against the nginx server directly as well.

```bash
# From outside: which protocol a site negotiates (prints 2 for HTTP/2, 1.1 otherwise)
curl -sI --http2 -o /dev/null -w '%{http_version}\n' https://www.example.com/
# From outside: whether the server offers h2 in the TLS handshake ("ALPN protocol: h2" means yes)
openssl s_client -connect www.example.com:443 -servername www.example.com -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol:|No ALPN negotiated'
```

Against the nginx server itself, a server with HTTP/2 off prints 1.1 for the first check and "No ALPN negotiated" for the second (Xint: that line means the server does not accept HTTP/2). What each proxy speaks to the origin:

- Cloudflare says "At Cloudflare, HTTP/2 connection to the origin is enabled by default." It connects with HTTP/2 only to origins that announce it through ALPN, and falls back to HTTP/1.1 otherwise. Free, Pro and Business plans: "Enabled by default". Enterprise: "Disabled by default (1 stream per connection)". The switch is Speed > Settings > Protocol Optimization > HTTP/2 to Origin.
- AWS says "By default, Application Load Balancers send requests to targets using HTTP/1.1." The target group's protocol version can be set to HTTP/2 or gRPC, so check that nobody changed it. CloudFront "forwards requests to your custom origin using HTTP/1.1".
- Akamai: when HTTP/2 is on, the connection from the edge to the origin is non-HTTP/2 by default. An "HTTP/2 Edge to Origin" option exists (introduced 29 July 2025).
- Fastly: we found no explicit HTTP/2-to-origin statement (COULD NOT VERIFY). Its documentation says it supports any backend that is an HTTP/1.1 compliant web server.
- Our reading: a CDN that speaks HTTP/2 to the origin leaves the origin's HTTP/2 code reachable through that CDN, so those origins sit in the CRITICAL tier. A CDN that speaks HTTP/1.1 to the origin removes that path, but not for an origin that can also be reached directly.
- Whether either bug can be triggered through a proxy that speaks HTTP/2 to the origin is unknown, because no source tested it. Wiz says only that CDNs and WAFs that terminate HTTP/2 "may mitigate parts of the exploit by not reflecting the exact payload back to the underlying NGINX server. This depends on implementation." Rapid7's notes say a network proxy in the path will likely break its own public exploit. Those are the researchers' statements, not tests of any CDN. We found no CDN or WAF vendor rule or statement for either CVE.
- Treat a proxy as a layer, not a fix. Lock the origin so it can't be reached around the proxy.

| What you found | Priority |
| --- | --- |
| Internet-facing nginx on an affected build with HTTP/2 on, including an origin behind a CDN that speaks HTTP/2 to it and a product that switches HTTP/2 on by default (community ingress-nginx, Kong, Apache APISIX). For CVE-2026-123633 the server also proxies to a backend | CRITICAL (our reading: this rests on exposure, not on proven exploitation). Patch and restart first, today |
| Internet-facing with HTTP/2 on and no fixed build to move to (inferred for the older branches): community ingress-nginx, NGINX Plus R33 to R36, nginx before 1.30, the nginxinc/nginx-unprivileged image | CRITICAL. Switch HTTP/2 off now, then move to a build that has the fix |
| The same affected build with HTTP/2 on, on an internal-only server | HIGH. Patch this week. An internal server is exposed to everyone who can reach that network, partners and VPN users included |
| HTTP/2 off: the module isn't compiled in, or no listener has HTTP/2 on in either syntax | Not exposed to these two bugs. Take 1.31.9 or 1.30.7 in the normal window anyway, because the same release fixes 10 advisories, including bugs outside HTTP/2 (HTTP/3, resolver, mail proxy) |

Containers and ingress controllers count as internet-facing when their ports are reachable from untrusted networks.

*Sources: Cloudflare, AWS and Akamai documentation, Fastly developer guide, Wiz, Xint, Rapid7 proof-of-concept notes, nginx.org security advisories (checked on 18 November 2026)*

---

**STEP 5: Is the fixed build actually running? (30 seconds)**

```bash
# Version of the nginx program on disk (it does not show what is running)
nginx -v
# When the nginx processes started. The one owned by root is the main process (run as root)
ps -eo user,pid,ppid,lstart,args | grep '[n]ginx'
# Old workers that are still shutting down after a reload (run as root)
ps -eo user,pid,ppid,lstart,args | grep '[n]ginx: worker process is shutting down'
# NGINX Plus on Debian and Ubuntu: the Plus package version
apt-cache policy nginx-plus
# NGINX Plus on the RHEL family: the Plus package version
rpm -q nginx-plus
# Container: the version inside the running container (replace <container> with its name or ID)
docker exec <container> nginx -v
```

A package update puts new files on disk and leaves the running server on the old code until nginx is restarted. `nginx -v` reads the program on disk, so on its own it proves nothing about the process. The main nginx process starts the workers, so its start time has to be later than the update. A reload isn't enough. Xint: "A configuration reload alone does not replace the running executable." Previdian says a reload leaves the old main process running, so the binary doesn't change, and CIRCL says "Restart to replace old workers and binaries." A reload also leaves connections that are already open, HTTP/2 ones included, on the old workers (Xint). A restart drops the connections in progress (Xint: it "forcibly disconnects every client"). The live binary upgrade is documented in the "Upgrading Executable on the Fly" section of nginx.org's control page, and this analysis gives no commands for it. If the main process started before the update, restart the service (the commands are in For technical teams).

NGINX Plus is the exception for `nginx -v`: it shows the open source base, which can be below 1.31.9 on a fixed Plus build (37.3.0.1 is based on 1.31.8), so check the Plus package version with the two Plus commands above. A container works the same way as a package: rebuild your image on a fixed tag (nginx:1.30.7, or nginx:1.31.9 for mainline), recreate the containers from it, and run the version check inside the new container. The nginxinc/nginx-unprivileged image has no fixed tag yet. On Kubernetes, F5 NGINX Ingress Controller v5.8.0 and NGINX Gateway Fabric v2.9.0 carry fixed builds, and Metnir's advice is "Recreate containers from the patched image." Community ingress-nginx has no fix and none is coming.

*Sources: nginx.org control documentation, Xint, CIRCL, Previdian, Metnir, F5 NGINX Plus release notes and F5 release pages, Docker Hub, Kubernetes ingress-nginx retirement notice (checked on 18 and 19 November 2026)*

---

### Full vulnerability checklist

**You are VULNERABLE if ALL of these are true:**

- [ ] The server runs nginx Open Source in an affected range (1.9.5 to 1.31.8 for CVE-2026-123007, 1.19.7 to 1.31.8 for CVE-2026-123633), or an NGINX Plus build in F5's affected ranges, or a distro or product build with no fix, whatever its version string says. A fixed package that was never restarted into the running server counts too
- [ ] The HTTP/2 module is compiled in (`nginx -V` shows `--with-http_v2_module`)
- [ ] HTTP/2 is switched on for a listener, with `http2 on;` or a `listen ... http2` parameter
- [ ] An untrusted party can reach that listener: the internet, a partner network, a VPN, or a CDN that speaks HTTP/2 to the origin. No login and no user action are needed
- [ ] For CVE-2026-123633 only: the server also proxies client requests to a backend, and a worker can run low on worker_connections

**Your risk is higher if ANY of these also apply:**

- [ ] The server is internet-facing and answers direct connections, so a proxy or CDN in front of it can be skipped
- [ ] A proxy in front speaks HTTP/2 to your origin (Cloudflare's HTTP/2 to the origin is on by default for Free, Pro and Business plans, and Akamai has an "HTTP/2 Edge to Origin" option). No source tested whether either bug can be triggered that way, so treat the origin as exposed
- [ ] You run a product that switches HTTP/2 on by default: community ingress-nginx, Kong or Apache APISIX
- [ ] You run a build with no fixed release to move to (inferred for the older branches): community ingress-nginx, NGINX Plus R33 to R36, nginx before 1.30, or the nginxinc/nginx-unprivileged image
- [ ] The host runs on a platform with no fixed package at the cut-off (Debian stable and testing, Ubuntu, Red Hat, SUSE, Rocky Linux, AlmaLinux 8, Alpine 3.21), or on a product with no fix shipped (Kong, OpenResty, Tengine), or on a product whose vendor we found no statement from (cPanel, Plesk, AWS, Azure, Google Cloud, Cloudflare, Vercel, and Angie and freenginx, where it isn't established that they share the flaws)
- [ ] The error log shows "worker_connections are not enough" warnings, which is the condition CVE-2026-123633 needs (the warning also appears on busy servers that are simply short of connections)
- [ ] The server can read credentials, keys or customer data. A successful attacker runs code as the worker user, such as nginx, www-data or nobody depending on the build (inferred from shipped config files). That isn't root: the main process runs as root and the workers drop to the configured user. Xint says it reached root only by chaining a separate Linux kernel flaw, which we couldn't verify

Nothing on the second list is a reason to skip the update. The two HTTP/2 fixes are small (3 files with 6 insertions and 2 deletions for CVE-2026-123007, one file with 2 insertions for CVE-2026-123633), and the release also fixes eight other advisories.

*Sources: nginx.org security advisories and CHANGES, the nginx fix commits, F5 CVE records and advisories, Xint, Wiz, Metnir, Debian, Ubuntu, Red Hat, Amazon Linux and Alpine pages, Cloudflare and Akamai documentation, vendor and cloud provider security pages (checked on 18 and 19 November 2026)*

---

### You are SAFE if:

- [ ] Every nginx you run is on 1.31.9 or 1.30.7 or later, or on NGINX Plus 37.3.0.1 or 37.0.8.1 or later, or on a distro build at or above the distro's fixed build (judged by the distro advisory, not by the nginx version string). At the cut-off Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had shipped one, and Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux had not
- [ ] Every patched server was restarted, and its main nginx process started after the update (a package on disk doesn't count, and neither does a reload)
- [ ] Containers were rebuilt on a fixed tag such as nginx:1.30.7 and redeployed (a rebuilt image that isn't running doesn't count)
- [ ] Ingress controllers, gateways and appliances with nginx inside have each confirmed in writing that they run a fixed build or have HTTP/2 off. Community ingress-nginx can't pass this check, because no fix is coming
- [ ] For servers you can't patch yet: the HTTP/2 module isn't compiled in, or no listener has HTTP/2 on in either syntax (`http2 on;` or a `listen ... http2` parameter), in every server block that shares the listening address and port and in every included file. You also checked containers, ingress controllers and appliances before saying so, and the change took effect (nginx was restarted, or it was reloaded and no old worker is still shutting down). That removes the exposure to these two bugs, but not the other eight fixes in the release, so still patch in the normal window
- [ ] The only nginx you run is older than 1.9.5, which has no HTTP/2 module (not affected by these two CVEs)

**IMPORTANT:** Turning HTTP/2 off, locking the origin and putting a proxy in front do not fix the bug. Only a patched build does, and only after the server restarts. Switching HTTP/2 off removes the exposure to these two bugs, but it isn't an F5 or nginx.org workaround: F5's records say the workaround is "None", and the advice comes from Wiz, Xint, CIRCL, CERT-FR and Metnir. It has a cost. Clients that support HTTP/1.1 carry on, but services that require HTTP/2 end to end, such as native gRPC, break, and HTTP/1.1 clients may open more connections (Xint, Metnir, CIRCL). No source tested whether a proxy or WAF blocks either bug.

A clean scanner report still proves little. A remote version check can't see whether HTTP/2 is on or whether a distro backport is installed (our reading), and at the cut-off Tenable's plugins for both CVEs were still "Coming Soon". NVD shows both records as Received, with no score of its own and no product data (it shows F5's scores), and the GitHub advisories are unreviewed. Check each server with the commands above.

*Sources: nginx.org security advisories, F5 CVE records, Wiz, Xint, CIRCL, CERT-FR, Metnir, Tenable, NVD, GitHub Advisory Database, Debian, Ubuntu, Red Hat and Amazon Linux security pages (checked on 18 and 19 November 2026)*

---

## PROTECTION ROADMAP

### For non-technical executives

#### HOUR 1: Emergency assessment

**Immediate actions checklist:**

- [ ] Get IT, the engineering leads and your hosting and software providers on one call
- [ ] Ask: "Which of our websites, web shops, customer portals and APIs run on nginx, and which of them can be reached from the internet?" Include anything a hosting company, agency or vendor runs for you, and products with nginx inside, such as API gateways, ingress controllers and load balancers
- [ ] Ask for three facts per server: its version, whether HTTP/2 is switched on (IT runs the Quick 3-minute assessment), and what sits in front of it. A server with HTTP/2 off isn't exposed to these two bugs. A patched package does nothing until the server restarts
- [ ] Ask every host, panel, appliance and software vendor that runs nginx for you, in writing, whether the product has HTTP/2 on and the fix. As of 18 November we found no statement from cPanel, Plesk, AWS, Azure, Google Cloud, Cloudflare or Vercel (AWS, Azure, Google Cloud and Cloudflare were rechecked on 19 November with the same result), and as of 19 November no fixed package from Debian stable and testing, Ubuntu, Red Hat, SUSE or Rocky Linux, so don't wait for them to write to you
- [ ] Flag any internet-facing server that has no fixed build to move to (inferred for the older branches): community ingress-nginx (retired), NGINX Plus R33 to R36, nginx before 1.30, and the nginxinc/nginx-unprivileged container image
- [ ] Approve emergency maintenance, including restarts during business hours and taking a service offline if it comes to that
- [ ] Tell legal, compliance and your cyber insurer that you're responding

**Decision points:**

- Everything fixed and restarted, or HTTP/2 off: document it and move to WEEK 1: Verification and assessment.
- Internet-facing servers with HTTP/2 on where a fixed build exists (the nginx.org packages, the Docker official image, F5's updated Ingress Controller and Gateway Fabric, NGINX Plus 37.3.0.1 or 37.0.8.1, and the platforms marked fixed in the RISK DASHBOARD): approve patching and a restart today. Servers that face the internet directly, and origins behind a CDN that speaks HTTP/2 to them, go first.
- Servers with HTTP/2 on and no fixed build yet (distro packages, community ingress-nginx, NGINX Plus R33 to R36, the unprivileged Docker image, Kong, OpenResty): approve the interim measure in For technical teams, which is to switch HTTP/2 off until a fix arrives, and ask the vendor in writing for a date. The advice comes from Wiz, Xint, CIRCL, CERT-FR and Metnir, not from F5 or nginx.org. Expect some loss of speed, and expect anything that needs HTTP/2 end to end, such as native gRPC, to break.
- Servers with HTTP/2 off: not exposed to these two bugs. Schedule 1.31.9 or 1.30.7 in the normal window, because the release also fixes eight other advisories.

---

#### DAY 1: Emergency response

**Executive decision checklist:**

- [ ] Approve maintenance windows. Every patched server has to restart nginx (a reload isn't enough), and container setups have to be rebuilt and redeployed, so plan for short interruptions. A restart disconnects every client
- [ ] Decide what to do about servers that can't take a fix today. That means distro packages with no fixed package yet, community ingress-nginx, NGINX Plus R33 to R36, the nginxinc/nginx-unprivileged image, and products with no fix shipped:
    - [ ] **Option A:** Move the service to a build or platform that already has the fix, such as the nginx.org packages, the Docker official image on 1.30.7 or 1.31.9, or NGINX Plus 37.3.0.1 or 37.0.8.1 (safest). For community ingress-nginx, move to a maintained controller
    - [ ] **Option B:** Take internet-facing services offline, or close them to the public internet, until the fix arrives
    - [ ] **Option C:** Switch HTTP/2 off until the fix arrives. Wiz, Xint, CIRCL, CERT-FR and Metnir advise it, and F5's records say the workaround is "None". Clients fall back to HTTP/1.1, which costs some speed, and services that need HTTP/2 end to end break. The server stays unpatched, so it is a stopgap, and it doesn't block the other eight fixes in the release
    - [ ] **Option D:** Extra layers only: ask your CDN or proxy provider to send HTTP/1.1 to your servers (Cloudflare's HTTP/2 to the origin is on by default for Free, Pro and Business plans), and lock the servers so only the proxy can reach them (leaves the most risk behind: no source tested whether a proxy blocks either bug, and the origin's own HTTP/2 listener stays on)
- [ ] Communication plan:
    - [ ] Brief the board if you're publicly traded
    - [ ] Prepare a customer notice in case a service has to go offline
    - [ ] Tell your cyber insurer
    - [ ] Ask legal for a compliance read
- [ ] Resources:
    - [ ] Approve overtime or outside help if the team is stretched
    - [ ] Call in your incident response retainer if you have one

---

#### WEEK 1: Verification and assessment

**Follow-up checklist:**

- [ ] Confirm, with evidence, that every internet-facing nginx with HTTP/2 on runs a fixed build and has restarted. Evidence means output from the server (the version, or the package version for NGINX Plus, and the start time of the main process), not a package list or a ticket
- [ ] Review error logs since each server was last restarted, and at least back to 11 November 2026, the date on the fix commits (ADVANCED FORENSICS sets the full window). No source we checked reports attacks in the wild, but clean logs prove little: no indicators of compromise have been published, and an attack on CVE-2026-123007 may leave little evidence in the nginx access logs (Xint). A failed attempt can end as a crashed worker, which the error log shows as "worker process ... exited on signal 11"
- [ ] Re-check vendor and platform advisories. At the 19 November cut-off there was no fixed package from Debian stable and testing, Ubuntu, Red Hat (RHEL 8, 9, 10 and Hardened Images), SUSE, Rocky Linux, AlmaLinux 8 or Alpine 3.21, Oracle Linux had no record for either CVE, a fix was unconfirmed for Fedora, cPanel and Plesk, and Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had shipped fixes. The nginxinc/nginx-unprivileged image, Kong, OpenResty, Tengine, Angie and freenginx had shipped nothing, and community ingress-nginx will never ship a fix
- [ ] Ask your scanner vendor how it judges HTTP/2 and distro builds. A remote version check can't see whether HTTP/2 is on or whether a backport is installed (our reading), so a clean scan proves little and a dirty one can be a false alarm
- [ ] Rotate secrets on any server that showed suspicious activity: credentials, keys and tokens that the nginx worker user can read. A successful attacker runs code as that user
- [ ] Hold a post-incident review with the technical teams
- [ ] Compliance:
    - [ ] Check notification duties if you found any sign of compromise
    - [ ] Keep timestamped records of everything you did
    - [ ] Preserve evidence
    - [ ] Get legal advice before you conclude "no breach"

---

#### MONTH 1: Strategic planning

**Lasting improvements:**

- [ ] Keep a live inventory of every nginx server, including containers, ingress controllers, API gateways and appliances, with its version, who supplies it, whether HTTP/2 is on and what sits in front of it
- [ ] Move off community ingress-nginx for good. The project is retired and archived (24 March 2026), and its notice says there will be "no further releases, no bugfixes, and no updates to resolve any security vulnerabilities"
- [ ] Move NGINX Plus R33 to R36 and nginx before 1.30, which have no fixed release (inferred), onto a branch that has the fix, and decide who owns keeping every nginx on a current branch. F5 says versions that have reached End of Technical Support are not evaluated
- [ ] Decide on purpose where HTTP/2 is worth the risk, and keep it off where it isn't. Stock installs ship with HTTP/2 off (inferred from the shipped files), so every server that has it on got there through someone's choice or a product default. Write down which ones and why
- [ ] Subscribe to the security advisories, not only the release announcements: nginx.org's advisories page links F5's K-articles for the details, and the nginx-announce archive had no 2026 pages when we looked (COULD NOT VERIFY). Add F5's advisories, your distro's security feed and your hosting and product vendors' bulletins
- [ ] Agree a patch and restart policy: how fast a web server fix reaches production, who may approve an emergency restart, and when the maintenance windows are. A reload doesn't replace the running program, so the policy has to say restart
- [ ] Put internet-facing services behind a proxy and lock origin servers so only the proxy can reach them, and decide on purpose which protocol the proxy speaks to the origin. Treat this as a layer, not a fix
- [ ] Add detection for worker crashes and for programs started by the nginx worker user (DETECTION & FORENSICS says how)
- [ ] Check what your scanner sees: does it know distro builds and whether HTTP/2 is on, or only version numbers?
- [ ] Review hosting contracts for patch timelines and notification duties
- [ ] Run a tabletop exercise based on this incident

*Sources: nginx.org security advisories and CHANGES, F5 advisories and NGINX Plus release notes, Kubernetes ingress-nginx retirement notice, Xint, Wiz, CIRCL, Metnir, Debian, Ubuntu, Red Hat, Amazon Linux and Alpine security pages, Cloudflare and AWS documentation, vendor and cloud provider pages (checked on 18 and 19 November 2026)*

### For technical teams

#### IMMEDIATE ACTIONS (Hour 1-2)

**Phase 1: Assessment and inventory**

**Checklist:**

- [ ] Find every nginx you run: servers, virtual machines, cloud instances, container images and running containers, Kubernetes ingress controllers and gateways, products built on nginx (OpenResty, Kong, Apache APISIX, Tengine, Angie, freenginx), hosting stacks and appliances that embed it, and the images and launch templates that new servers start from
- [ ] Record the nginx version, the package build and who supplies it (nginx.org, a distro, F5 NGINX Plus, a vendor, or you, from source). For NGINX Plus, record the Plus package version too, because `nginx -v` shows the open source base
- [ ] Record whether the HTTP/2 module is compiled in. A build without it has no HTTP/2 code, so these two bugs are not there
- [ ] Record whether HTTP/2 is switched on, in every server block and on every listener, cleartext ones included: `http2 on;` or a `listen ... http2` parameter
- [ ] Record whether the server proxies requests to a backend. CVE-2026-123633 needs that on top of HTTP/2 (our reading of F5's wording: a server that only serves static files is outside that bug)
- [ ] Record whether a proxy or CDN sits in front, which protocol it speaks to the origin, and whether the origin can still be reached around it
- [ ] Put internet-facing servers with HTTP/2 on first (our CRITICAL tier), then internal servers with HTTP/2 on (our HIGH tier), then servers with HTTP/2 off. Those last are not exposed to these two bugs, but the same release fixes eight other advisories

**Commands for assessment:**

These checks only read. They are at documentation level: we did not run them against a live server. Commands marked "run as root" need it.

```bash
# Version of the nginx program on disk (prints to the error stream)
nginx -v
# Whether the HTTP/2 module is compiled in. No output means it is not (run as root if nginx is not on your path)
nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
# Whether HTTP/2 is switched on in the config on disk. Reads every included file (run as root)
nginx -T 2>&1 | grep -nE '^[[:space:]]*(listen[[:space:]][^#]*[[:space:]]http2([[:space:]]|;)|http2[[:space:]]+on[[:space:]]*;)'
# Which ports nginx listens on (run as root to see process names)
ss -tlnp | grep nginx
# Which user the worker processes run as. The master is owned by root
ps -eo user,pid,ppid,args | grep '[n]ginx: '
# From outside: which protocol a site negotiates (prints 2 for HTTP/2, 1.1 otherwise)
curl -sI --http2 -o /dev/null -w '%{http_version}\n' https://www.example.com/
# From outside: whether the server offers h2 in the TLS handshake ("ALPN protocol: h2" means yes)
openssl s_client -connect www.example.com:443 -servername www.example.com -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol:|No ALPN negotiated'
```

```bash
# Debian and Ubuntu: installed nginx packages and their versions
dpkg -l | grep nginx
# RHEL family and Amazon Linux: installed nginx packages
rpm -q nginx nginx-plus
# Alpine: installed nginx packages
apk info -v | grep nginx
# Homebrew: installed nginx version
brew list --versions nginx
```

```bash
# Docker: version and HTTP/2 module inside a running container
docker exec <container> nginx -v
docker exec <container> nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
```

```bash
# Kubernetes: every pod with the images it runs, filtered to nginx-based names. The filter misses images that embed nginx under another name
kubectl get pods -A -o 'custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,IMAGE:.spec.containers[*].image' | grep -iE 'nginx|kong|apisix|openresty'
```

Replace `<container>` with the container's name or ID, and www.example.com with your site.

How to read the output:

- No output from the `--with-http_v2_module` check means the HTTP/2 module is not compiled in. There is no HTTP/2 code, so these two bugs are not there (Xint). Source builds leave the module out unless asked. The nginx.org packages, the Docker official image and the Debian, Ubuntu, RHEL (CentOS Stream files) and Alpine packages compile it in (inferred from build files; nothing was run). Fedora: COULD NOT VERIFY.
- HTTP/2 is on when a server has `http2 on;` (nginx 1.25.1 and later) or the legacy `listen ... http2` parameter. Either one enables it (inferred from the source), so `http2 off;` does not override a leftover `listen` parameter. Check every server block that shares the listening address and port. On a plain listener the same switch accepts cleartext HTTP/2 (h2c) from clients that send the HTTP/2 preface first (inferred; we found no HTTP/1.1 Upgrade path in the source).
- A hit in the `nginx -T` grep means a directive exists, not that the port is reachable. Follow it with the `curl` and `openssl` checks. `nginx -T` reads the config on disk: if the config changed without a reload, the running config may differ (Xint). The dump can include secrets from included files, so keep the grep.
- Run `nginx -t` and `nginx -T` as root. They try to open the files named in the config (certificate keys, logs, the pid file), which are usually root-only, and Xint runs them with sudo. `nginx -v` and `nginx -V` need only permission to run the binary.
- `curl` prints 2 when the site negotiates HTTP/2 and 1.1 otherwise. The `openssl` line prints "ALPN protocol: h2" when the server offers HTTP/2 in the TLS handshake, and "No ALPN negotiated" when it does not accept HTTP/2 (Xint). Both outside checks see only the TLS side: a cleartext listener shows only in the `nginx -T` output.
- If a CDN or reverse proxy sits in front of nginx, the two outside checks reach only the proxy. Run them against the nginx server directly as well (Xint).
- A server with an affected version and HTTP/2 on is exposed to CVE-2026-123007. CVE-2026-123633 also needs proxying to a backend and a worker that runs low on worker_connections, so a busy HTTP/2 proxy is the case to worry about (our reading).
- Affected versions: nginx Open Source 1.9.5 to 1.31.8 for CVE-2026-123007 and 1.19.7 to 1.31.8 for CVE-2026-123633. The fixes are in 1.31.9 and 1.30.7. No fixed release exists on older branches (inferred from nginx.org's "Not vulnerable: 1.31.9+, 1.30.7+" and F5's note that end-of-support versions are not evaluated), so every release before 1.30 has to move to 1.30.7 or 1.31.9 and later. Versions older than 1.9.5 have no HTTP/2 module. They still run other known bugs: nginx.org's range for the resolver bug fixed in this release starts at 0.6.18.
- A distro build can carry a fix under an older number (Xint: Ubuntu 24.04 ships 1.24.0, Ubuntu 22.04 ships 1.18.0 and Debian 12 ships 1.22.1, and these distributions may backport security fixes to the existing version instead of replacing it with a new nginx release). Judge distro packages by the distro advisory, not by the nginx version string. At the cut-off Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had shipped a fix, and Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux had not. Option B below lists each.
- NGINX Plus: `nginx -v` shows the open source base. NGINX Plus 37.3.0.1 is based on 1.31.8 and still has the CVE-2026-123007 fix, so check the Plus package version.
- In Kubernetes the controller pod is the server. Community ingress-nginx switches HTTP/2 on by default (the ConfigMap key `use-http2` defaults to "true"), so a ConfigMap without that key means HTTP/2 is on. Kong and Apache APISIX switch it on by default too. F5 NGINX Ingress Controller defaults to off.
- The worker user depends on the build (inferred from shipped config files): `nginx` on the nginx.org packages, RHEL (CentOS Stream files) and Alpine, `www-data` on Debian and Ubuntu, `nginx` with uid 101 in the Docker official image, and `nobody` on a source build with the default settings. The main (master) process runs as root and the workers drop to the configured user.

For bigger estates, run the checks through your configuration management, remote execution or EDR tooling and collect the output into one table keyed by host: version, module, HTTP/2 listeners and the start time of the main process. A package list says what is installed, and these bugs are fixed only in the process that is running.

Don't test your hosts with proof-of-concept or checker code from public repositories. As of 04:45 UTC on 19 November 2026, a search for either CVE ID in quotes returns 18 GitHub repositories. We opened and ran none of them. Several claim an exploit or a proof of concept for CVE-2026-123007, one with a full code execution chain, and others call themselves read-only checkers. None of the third party code is verified, and running unknown code is a common way to get compromised.

**Document your findings:**

```
Host / image / gateway / appliance:
Platform and release (/etc/os-release):
Role and exposure [internet-facing / internal only / behind a proxy with the origin locked down]:
nginx version (nginx -v) and, for NGINX Plus, the Plus package version:
Package versions (dpkg -l, rpm -q nginx):
HTTP/2 module compiled in [yes / no]:
HTTP/2 switched on, with the file and server block (http2 on; or listen ... http2) [yes / no]:
Cleartext listener with HTTP/2 [yes / no]:
Proxies requests to a backend [yes / no]:
Worker user:
Proxy in front, and the protocol it speaks to the origin [none / HTTP/1.1 / HTTP/2 / unknown]:
Origin reachable around the proxy [yes / no]:
Fixed build for this platform [yes / no / vendor has no fix yet]:
Interim measure [HTTP/2 off / listen parameter removed / product setting / proxy setting / none], date and who:
Restarted after the upgrade [yes / no, time]:
Status [fixed / exposed / not exposed (module absent or HTTP/2 off) / no fix yet]:
```

---

**Phase 2: Emergency patching**

**Pre-patch checklist:**

- [ ] Snapshot or back up the server or image, configuration included
- [ ] Note current versions (`nginx -v`, plus `dpkg -l` or `rpm -q nginx`) for rollback
- [ ] Write down any interim measure you applied (an `http2 off;` line, a removed `listen` parameter, a product setting, a proxy setting) so you can undo it on purpose later
- [ ] Tell stakeholders about the maintenance window. A restart drops the connections in progress (Xint: it "forcibly disconnects every client"), so plan the order: internet-facing servers with HTTP/2 on first
- [ ] Have a rollback plan ready, with a time limit. A rollback puts the vulnerable build back
- [ ] For a server you suspect, capture state before you restart it, because a restart destroys the memory of the nginx processes. DETECTION & FORENSICS says what to look for, and ADVANCED FORENSICS says what to preserve

**Patching commands:**

Install the fixed package, then restart. The restart is not optional: a package on disk doesn't fix a process that is still running, and a reload doesn't replace the running program. Patch in this order: internet-facing servers with HTTP/2 on, then internal servers with HTTP/2 on, then servers with HTTP/2 off.

```bash
# Debian and Ubuntu with the nginx.org repository (run as root)
apt-get update && apt-get install --only-upgrade nginx
systemctl restart nginx
# RHEL 9 and 10, Rocky, AlmaLinux and Amazon Linux 2023 with the nginx.org repository (run as root)
dnf upgrade nginx
systemctl restart nginx
# Alpine edge and 3.24 (run as root)
apk update && apk upgrade nginx
rc-service nginx restart
# Arch Linux (run as root). This upgrades every package, including nginx or nginx-mainline
pacman -Syu
systemctl restart nginx
# FreeBSD (run as root). The ports tree has the fix; binary package availability was not checked
pkg upgrade nginx
service nginx restart
# Gentoo (run as root)
emerge --sync && emerge --ask --update www-servers/nginx
systemctl restart nginx
# On OpenRC instead of the line above, use: rc-service nginx restart
# Homebrew
brew update && brew upgrade nginx
brew services restart nginx
```

```dockerfile
# Docker: rebuild your image on a fixed tag, then recreate the containers from it
FROM nginx:1.30.7
# Mainline users: FROM nginx:1.31.9. The nginxinc/nginx-unprivileged image has no fixed tag yet
```

- NGINX Plus: install 37.3.0.1 (CR) or 37.0.8.1 (LTS) from F5's repository, then restart nginx with `systemctl restart nginx`. `nginx -v` shows the open source base, which can be below 1.31.9 on a fixed Plus build (37.3.0.1 is based on 1.31.8), so check the Plus package version instead (`apt-cache policy nginx-plus` on Debian and Ubuntu, `rpm -q nginx-plus` on the RHEL family).
- Kubernetes: F5 NGINX Ingress Controller v5.8.0 and NGINX Gateway Fabric v2.9.0 carry fixed builds (Option C). Recreate the pods from the patched images (Metnir: "Recreate containers from the patched image."). Community ingress-nginx has no fix and none is coming: use the HTTP/2 stopgap below or move to a maintained controller.

These commands reach a fixed build only on a platform marked fixed in Option A, or from the nginx.org repository. At the cut-off the distro-owned packages of Debian stable and testing, Ubuntu, RHEL, Rocky, Oracle, SUSE, AlmaLinux 8 and Alpine 3.21 had no fixed package, while Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid did (the same package-manager upgrade commands apply to them). Until yours ships one, use the HTTP/2 stopgap below. When it does, the same upgrade commands apply, but judge the package by the distro advisory, not by the nginx version string. Fedora could not be checked and has no command here: update the package with the platform's own tooling and restart nginx.

**Option A: Platforms with a fixed package (the fix is the package plus a restart)**

- Upstream and source builds: nginx 1.31.9 (mainline) and 1.30.7 (stable), released 18 November 2026. Rebuild anything you compile yourself on one of them.
- nginx.org repositories: 1.31.9-1 (mainline) and 1.30.7-1 (stable) are present for Debian (bookworm, trixie), Ubuntu (jammy, noble, resolute), RHEL 9 and 10, Alpine 3.24 (1.31.9-r1, 1.30.7-r1) and Amazon Linux 2023. The listing times (11 November, 20:04 to 21:12) are build times, not publication times.
- NGINX Plus: 37.3.0.1 (CR) and 37.0.8.1 (LTS) fix both bugs, released 18 November 2026. 37.2.0.1 (CR) and 37.0.7.1 (LTS) fix CVE-2026-123633 only (released 14 October 2026 per the release notes). Later releases on the same branch carry the earlier fix (inferred).
- Alpine: edge and 3.24 have nginx 1.30.7-r0 (builds at 17:06 and 17:11 UTC on 18 November). The security database lists CVE-2026-123007 and CVE-2026-123633 among the nine CVEs fixed in 1.30.7-r0.
- Arch Linux: nginx 1.30.7-1 (build 16:42:05, repository 17:08:59 UTC) and nginx-mainline 1.31.9-1 (build 16:51:03, repository 16:56:25 UTC).
- Homebrew: nginx 1.31.9 (formula generated 18 November, no time given).
- FreeBSD ports: www/nginx 1.30.7,3 ("Security update to 1.30.7", commit about 16:32, FreshPorts time zone not stated) and www/nginx-devel 1.31.9 are in the ports tree. There is no VuXML entry. Binary package availability was not checked. The first fetch at 19:41 UTC showed stale versions, and the 19:55 re-check shows the fix.
- Gentoo: www-servers/nginx 1.30.7 and 1.31.9 are in the tree (keywords and times not read, GLSA not checked).
- Heroku: the PHP platform runs nginx 1.30.7 (Dev Center changelog item 3920, "Change effective on 18 November 2026", no time given). The item names CVE-2026-123007, CVE-2026-123633 and CVE-2026-118899.

**Option B: Distro packages and other platforms, several with no fix, or no confirmed fix, yet**

- Debian: fixed in sid (unstable) only, with nginx 1.30.6-4 (the fixes for both CVEs backported from 1.30.7; the changelog is signed 18 November at 18:56 UTC and the tracker showed it later). No fixed package for bookworm (1.22.1-9+deb12u9, and 1.22.1-9+deb12u10 in security), trixie (1.26.3-3+deb13u7, and 1.26.3-3+deb13u10 in security) or forky (1.30.6-3), which are all listed "vulnerable". The tracker notes cite the upstream fix commits. Migration of 1.30.6-4 to testing is pending, and there is no DSA (nginx is not in dsa-needed). Checked at 04:29 and 04:35 UTC on 19 November.
- Ubuntu: no fixed package. Both CVEs were published on 18 November with priority high. trusty is "not-affected" (nginx 1.4.6 has no HTTP/2). xenial, bionic, focal, jammy, noble, resolute and stonking are "needed", and upstream is "released (1.31.9,1.30.7)". The newest 20 nginx notices include none for either CVE, and a search by CVE ID finds none (rechecked at 04:29 UTC on 19 November; the record was last updated on 18 November at 17:00 UTC). Ubuntu lists releases with nginx older than 1.19.7 (Xint: 22.04 ships 1.18.0) as needed for CVE-2026-123633, while nginx.org's range for it starts at 1.19.7. We found no explanation (COULD NOT VERIFY).
- Red Hat: no fixed package. RHEL 8 (module nginx:1.24), RHEL 9 (default, nginx:1.24 and nginx:1.26 streams), RHEL 10 and Hardened Images are known affected for both CVEs with no erratum and no RHSA. CVE-2026-123633 now has a Red Hat record (Affected). Red Hat's VEX files (revision 3, 18 November at 21:27 UTC for CVE-2026-123007 and 21:29 UTC for CVE-2026-123633) list 45 products each, with a workaround entry and no fix.
- Rocky Linux: no fixed package (no record: the Apollo and errata APIs and the OSV data for Rocky 8, 9 and 10 had no hit at 04:29 UTC on 19 November). AlmaLinux: fixed in 9 (ALSA-2026:A025, nginx 2:1.20.1-32.el9_9.1.alma.3) and 10 (ALSA-2026:A024, nginx 2:1.26.3-16.el10_3.1.alma.2), read from the OSV database (record modified 23:00 and 22:45 UTC on 18 November; the published field carries only the date). AlmaLinux 8 has no advisory. Oracle Linux: no record for either CVE (404 pages). SUSE: no fixed package and no SUSE-SU, but records now exist with state "Analysis" for every product (Bugzilla 1290868 and 1290872, both "NEW"). No record is not the same as not affected.
- Amazon Linux: fixed for both CVEs, severity Important. Amazon Linux 2023: ALAS2023-2026-3494 (nginx-1.30.7-1.amzn2023.0.1, released 18 November at 23:09 UTC). Amazon Linux 2 (Nginx1 Extra): ALAS2NGINX1-2026-018 (nginx-1.30.7-1.amzn2.0.1, released 19 November at 01:20 UTC). Amazon Linux 2027 Preview: ALAS2027-2026-386 (nginx) and ALAS2027-2026-385 (nginx-awslc), dated 18 November. All three showed "Pending Fix" on 18 November. The nginx.org repository build for Amazon Linux 2023 in Option A is a different source.
- Alpine 3.23 and 3.22: fixed in nginx 1.28.3-r8, a backport (listed builds at 01:10 and 01:08 on 19 November, time zone not stated). They had 1.28.3-r7 (built 23 July 2026) with no entry on 18 November. Alpine 3.21 is not fixed (nginx 1.26.3-r3, no entry). Alpine 3.24 and edge are in Option A.
- Fedora: COULD NOT VERIFY (bot challenge). Repology (stale) lists Fedora 43 to 45 at 1.30.6: weak evidence only. Red Hat Bugzilla has no bug for either CVE, and a web search found no Fedora update.
- Older upstream branches: no fixed release exists on any branch before 1.30 (inferred). Move to 1.30.7 or 1.31.9 and later.
- NGINX Plus R33 to R36: F5's table lists the fix for R34 to R36 as "None", and the CVE records also list R33 as affected with no upper bound. Our reading: no fixed release on those branches, so move to a fixed 37.x release. F5 says versions that have reached end of technical support are not evaluated.
- Docker nginxinc/nginx-unprivileged: no 1.31.9 or 1.30.7 tag. The newest tags are dated 19 October 2026.
- Bitnami: the source repository has "[bitnami/nginx] Release 1.31.9-debian-12-r0" (16:43 UTC) and the bitnami/nginx "latest" tag was updated at 18:48 UTC, but the image contents were not inspected, so treat it as unconfirmed. bitnamilegacy/nginx is frozen (2025).
- Forks and products built on nginx, all with no fix shipped at the cut-off: freenginx (newest 1.31.5, 27 October 2026; no statement), Angie (newest 1.12.4, 16 October 2026; no statement), OpenResty (newest v1.31.8.1, 26 October 2026, on an nginx 1.31.8 base), Tengine (newest 3.2.0-rc5, 4 September 2026), Kong OSS (newest 3.9.4, 12 October 2026) and community ingress-nginx (retired, no fix expected). Whether freenginx is affected is COULD NOT VERIFY. Angie's security page does not mention either CVE, and whether its HTTP/2 code shares the flaws is not established. Tengine's nginx core is 1.31.5, inside the affected range (inferred).
- cPanel and Plesk: COULD NOT VERIFY. AWS, Azure, Google Cloud, Cloudflare and Vercel: no statement found (COULD NOT VERIFY).
- Other F5 products (K-articles, WEAK, browser render): "NGINX One Console" and "F5 Distributed Cloud (all services)" are marked `**` (F5 still researching). BIG-IP, BIG-IQ, F5 Insight, F5OS, BIG-IP Next and CNF are "Not vulnerable". F5 App Protect and Instance Manager: COULD NOT VERIFY. F5 notice K000164058: COULD NOT VERIFY (script page).

While you wait for a fix, in order of preference:

1. Where a workload can move, move it to a source that already has a fixed build: the nginx.org repository, or an official image on a fixed tag. Test first, because a different package can bring different config paths and build options (our reading).
2. Turn HTTP/2 off on the server (the steps are below). This is advice from Wiz, Xint, CIRCL, CERT-FR, Metnir and an OpenResty issue reporter. It is not an F5 or nginx.org workaround: F5's records list the workaround as "None", and nginx.org's advisories page has no mitigation text.
3. Put the server behind a proxy that speaks HTTP/1.1 to the origin, and lock the origin to the proxy. No proxy is known to block either bug, so this is a layer, not a fix.
4. Check your vendor's page every day, and patch the day a fixed build appears.

Treat every measure below as interim. Vendor state moves fast, and this analysis is about 13.5 hours past disclosure, so re-check before you rely on a "no fix yet" or an "unconfirmed".

**Option C: Containers, Kubernetes, hosting stacks and images**

- Docker official image: rebuild on a fixed tag and redeploy (the Dockerfile line above). Docker Hub shows the tags 1.31.9, 1.30.7, latest, mainline, stable and the numeric and alpine variants pushed on 18 November between 17:15:03 and 17:21:46 UTC. The alpine-perl and alpine-otel variants had no images at 19:41 UTC and got them between 19:52 and 19:54 UTC. No tag was stale at the 19:55 check on 18 November, and the 04:32 check on 19 November found 14 tags for 1.31.9, the newest pushed at 22:51 on 18 November. Pull dates are a poor guide: check the version inside a container started from the image (`docker exec <container> nginx -v`). A running container keeps the old code until you replace it.
- nginxinc/nginx-unprivileged: not fixed (Option B). Turn HTTP/2 off in the image's config until a fixed tag appears.
- Community ingress-nginx: retired and archived on 24 March 2026 ("there will be no further releases, no bugfixes, and no updates to resolve any security vulnerabilities"). No fixed controller is expected. Set `use-http2` to "false" (below) as an interim step and plan a move to a maintained controller.
- F5 NGINX Ingress Controller: v5.8.0 is fixed (its compatibility row reads "1.31.9 / R37.3.0.1"). The 2026-lts-r11 tag has NGINX_OSS_VERSION 1.31.0 and NGINX_PLUS_VERSION R37.0, inside the affected range, so a fixed LTS build is COULD NOT VERIFY.
- F5 NGINX Gateway Fabric: v2.9.0 is fixed for the open source image (nginx 1.31.9). The Plus image uses nginx 1.31.8 with Plus R37.3 (patch level not shown), so check the Plus package version inside it. The release and image timestamps for both F5 projects (13:10 to 14:29 UTC on 18 November) come before F5's 15:00 UTC publication time, and when the images became public is not established.
- Conflict to know about: F5's K-articles (WEAK, browser render) list "NGINX (all other products)" as "Not vulnerable" and have no separate rows for Ingress Controller, Gateway Fabric or Instance Manager. Metnir says it crashed the shipped Gateway Fabric binaries (and those of Kong, Apache APISIX and community ingress-nginx) with the CVE-2026-123633 bug, and reproduced it in OpenResty. The F5 release notes we saw for both projects do not mention these CVEs. Check the version inside each controller or gateway image, from a shell in the pod, and do not rely on a "not vulnerable" line.
- OpenResty, Kong and Apache APISIX: no fixed release at the cut-off (Option B). Kong's source tree pins OPENRESTY=1.27.1.2, an nginx 1.27.1 core inside the affected range (inferred), and we found no Kong statement.
- EC2 and VM images: update or rebuild the golden image, and every launch template or autoscaling group that points at it. A new instance from an old image comes up vulnerable.
- Hosting stacks: cPanel and Plesk are COULD NOT VERIFY. Ask the vendor in writing whether nginx is part of the stack, which build it ships and whether HTTP/2 is on, and keep the answer with the inventory.

**The other eight fixes in the same release**

The release fixes 10 advisories, not two (nginx.org advisories page and news item, 18 November 2026). Turning HTTP/2 off covers only the two HTTP/2 bugs. All eight below are fixed in 1.31.9 and 1.30.7 unless noted.

| CVE | What nginx.org lists | nginx.org severity | Vulnerable range |
| --- | --- | --- | --- |
| CVE-2026-123634 | Use-after-free during response processing in the resolver | medium | 0.6.18 to 1.31.8 |
| CVE-2026-121810 | Use-after-free in HTTP/3 | medium | 1.25.0 to 1.31.8 |
| CVE-2026-118899 | Infinite loop while reading the client request body over TLS 1.3 | major | 1.13.0 to 1.31.8 |
| CVE-2026-113425 | Use-after-free in the mail proxy module | major | 0.5.33 to 1.31.8 |
| CVE-2026-120993 | NULL pointer dereference when using PROXY protocol version 2 | minor | 1.31.4 to 1.31.8 (fixed in 1.31.9; nginx.org lists no 1.30.x fix) |
| CVE-2026-125283 | Buffer overflow when using alias with try_files | minor | 0.9.6 to 1.31.8 |
| CVE-2026-120967 | SNI bypass when using client certificate validation in stream | medium | 1.25.5 to 1.31.8 |
| CVE-2026-123640 | Insufficient validation in the stream ssl_preread module | minor | 1.15.2 to 1.31.8 |

Xint counts three of these (CVE-2026-123634, CVE-2026-121810 and CVE-2026-113425) with the two HTTP/2 bugs as five nginx bugs of remote code execution class, and says disabling HTTP/2 "does not block the other three nginx vulnerabilities". We did not read the F5 records for those three. HTTP/3 (QUIC) is a separate switch (`--with-http_v3_module`, `listen ... quic`) and is not in scope for these two CVEs. A server with HTTP/2 off still needs the release.

*Sources: nginx.org security advisories page and news item, Xint write-up (state on 19 November 2026, 04:30 UTC)*

**Restart into the fixed build (the step people skip)**

Installing the package is half the job. A running nginx keeps the old code in memory until the main process restarts, and the server stays exposed the whole time. Each set of commands in the patching block ends with a restart. Use a restart, not a reload. Xint: "A configuration reload alone does not replace the running executable." CIRCL: "Restart to replace old workers and binaries." A reload also leaves connections that are already open, HTTP/2 ones included, on the old workers (Xint), and a restart drops the connections in progress. nginx.org documents a live binary upgrade in the "Upgrading Executable on the Fly" section of its control page. We give no commands for it: follow nginx.org's page, and use a full restart where you are unsure. In a container, rebuild and replace it, because restarting the old container starts the same old image.

**Can't patch today? Turn HTTP/2 off.** This is a bridge, not a fix. DEFENSE-IN-DEPTH MEASURES has the full list.

Check every server block that shares the listening address and port. A leftover `listen ... http2` parameter keeps HTTP/2 on even with `http2 off;` (inferred from the source, and matching Xint's advice to remove it).

```nginx
# nginx 1.25.1 and later: in each affected server block (or once in http {}), switch it off
listen 443 ssl;
http2 off;
```

```nginx
# Older syntax (nginx 1.9.5 to 1.25.0, and still accepted later): remove http2 from listen
# Before:
listen 443 ssl http2;
# After:
listen 443 ssl;
# Cleartext listeners: "listen 80 http2;" becomes "listen 80;"
```

```bash
# Test the new configuration (run as root)
nginx -t
# Apply it to new connections (run as root)
nginx -s reload
# Connections that were already open stay with the old workers. List old workers that are still shutting down
ps -eo user,pid,ppid,lstart,args | grep '[n]ginx: worker process is shutting down'
# If the line above prints anything and a short outage is acceptable, restart (run as root). This disconnects every client
systemctl restart nginx
```

Side effects and limits:

- It blocks only these two bugs. Disabling HTTP/2 blocks both (Xint's table says "Yes" for both, and Wiz, CIRCL and CERT-FR give the same advice), but it leaves the eight other fixes in the release open. CIRCL makes the same point: disabling HTTP/2 alone is not a complete mitigation. Re-enable HTTP/2 after the upgrade (Wiz).
- Clients that support HTTP/1.1 carry on, but services that require HTTP/2 end to end, such as native gRPC, break (Xint, Metnir, CIRCL). Metnir: "HTTP/1.1 clients may also open more connections, so check that the workers have enough capacity after the change."
- Why the restart step: Xint says "A reload applies the new configuration only to new connections. Connections that were already open, such as HTTP/2 or mail sessions, stay with the old workers and keep using the old configuration." Old workers show as "nginx: worker process is shutting down". Wiz: reload and "confirm the old workers have exited".
- Write down the date the measure comes off, and switch HTTP/2 back on only after the fixed build is running.
- Check the result from outside: the `curl` check from Phase 1 should print 1.1, and the `openssl` check should print "No ALPN negotiated" (Xint: that means the server does not accept HTTP/2). If a CDN or reverse proxy sits in front, run both against the nginx server directly.

**Products with their own switch (inferred from their default files unless noted)**

Community ingress-nginx (retired): set the ConfigMap key `use-http2` to "false".

```yaml
# ingress-nginx controller ConfigMap: turn HTTP/2 off (the default is "true")
data:
  use-http2: "false"
```

Kong: take `http2` out of the listen strings in kong.conf (the defaults carry it on the 8443 and 8444 listeners, and `status_listen` has none). The file's own text says `http2` is what lets clients open HTTP/2 connections on a listener. Apply with your normal Kong restart or redeploy.

```
# kong.conf: the default listen strings with http2 removed
proxy_listen = 0.0.0.0:8000 reuseport backlog=16384, 0.0.0.0:8443 ssl reuseport backlog=16384
admin_listen = 127.0.0.1:8001 reuseport backlog=16384, 127.0.0.1:8444 ssl reuseport backlog=16384
```

Apache APISIX: the default table has `enable_http2 = true,` inside the apisix section. Setting it to false in conf/config.yaml should turn HTTP/2 off, but we could not fetch config-default.yaml to confirm the key's place (inferred). Check APISIX's own docs before you rely on it.

```yaml
# conf/config.yaml (inferred from apisix/cli/config.lua)
apisix:
  enable_http2: false
```

- F5 NGINX Ingress Controller: HTTP/2 is off by default. If you turned it on, set the ConfigMap key `http2` to "false" and remove any `nginx.org/http2: "true"` annotation or VirtualServer `http2: true`.
- NGINX Gateway Fabric: Metnir says it enables HTTP/2 by default. We did not verify that (COULD NOT VERIFY), so read its configuration.
- OpenResty, Tengine, Angie and freenginx: no vendor mitigation text found. The nginx-level change above applies to the listen directives.

**Fronting while you wait (a layer, not a fix)**

- Cloudflare: "HTTP/2 to Origin" is on by default for Free, Pro and Business plans (Enterprise: off). Turning it off (Speed > Settings > Protocol Optimization) stops Cloudflare speaking HTTP/2 to the origin. Our reading: this removes the HTTP/2 path through Cloudflare, not the origin's own HTTP/2 listener.
- AWS ALB and CloudFront speak HTTP/1.1 to origins by default. Check that nobody changed the ALB target group's protocol version to HTTP/2 or gRPC.
- Lock the origin so it can only be reached through the proxy (our reading). Whether any CDN or WAF blocks either bug is unknown, so this is a layer, not a fix.
- CIRCL also advises limiting outbound connectivity, least-privilege accounts, isolating backends, and reviewing the vendor images of ingress controllers.

**Verification:**

```bash
# Version of the nginx program on disk (it does not show what is running)
nginx -v
# Installed packages. Debian and Ubuntu
dpkg -l | grep nginx
# RHEL family and Amazon Linux
rpm -q nginx
# Alpine
apk info -v | grep nginx
# Homebrew
brew list --versions nginx
# NGINX Plus: the package version is what counts. Debian and Ubuntu, then the RHEL family
apt-cache policy nginx-plus
rpm -q nginx-plus
# When the nginx processes started. The one owned by root is the main process (run as root)
ps -eo user,pid,ppid,lstart,args | grep '[n]ginx'
# From outside: prints 2 while HTTP/2 is on, and 1.1 after the interim measure. Replace www.example.com with your site
curl -sI --http2 -o /dev/null -w '%{http_version}\n' https://www.example.com/
# From outside: the site still answers over HTTP/1.1
curl -sI --http1.1 -o /dev/null -w '%{http_version}\n' https://www.example.com/
```

- Upstream builds: `nginx -v` must show 1.31.9 or 1.30.7, or later on the same branch.
- Distro builds: the package version must match or beat the fixed version in the distro advisory. No distro had published one at the cut-off.
- NGINX Plus: the Plus package must be 37.3.0.1 or 37.0.8.1 or later on those branches (inferred). `nginx -v` can show 1.31.8 on a fixed Plus build.
- `nginx -v` prints the version of the program on disk. Compare the start time of the main process (owned by root) with the time of the upgrade. If it started earlier, restart it. A minimal system such as Alpine ships a `ps` that may not accept these fields, so check the output layout before you trust the result.
- Containers: confirm the running container was created from the rebuilt image, and run `docker exec <container> nginx -v` in it. For a controller or gateway, run the same check from a shell in the pod.

**Post-patch checklist:**

- [ ] Every patched server shows the fixed build in the version checks, and its main process started after the upgrade
- [ ] The sites work after the restart: listeners are up, health checks pass and dependent systems reconnect
- [ ] Decide on purpose what stays of the interim measures. The patch does not remove `http2 off;` or an edited `listen` line. Keep HTTP/2 off as long as you want, or switch it back on with the fixed build running
- [ ] Rebuild the images and launch templates so that new servers don't come back on the old build
- [ ] For NGINX Plus, confirm the Plus package version, not the open source version
- [ ] If a scanner still flags a patched host, check the version-number trap before you open a ticket: a distro package can carry the fix under an older number, and a fixed Plus build can show 1.31.8
- [ ] Keep the version output and the process start times as evidence
- [ ] Update your asset inventory and record the restart time
- [ ] On servers still waiting for a fix, watch the error log for worker crashes. DETECTION & FORENSICS says which signals matter

*Sources: nginx.org security advisories, CHANGES and download pages, F5 CVE records and advisories K000163926 and K000163928 (WEAK, browser render), NGINX Plus and Ingress Controller release notes, F5 Ingress Controller and Gateway Fabric repositories, nginx.org package repositories, Docker Hub and docker-library, Debian, Ubuntu, Red Hat, Rocky, AlmaLinux, Oracle, SUSE, Amazon Linux and Alpine security data, Arch, Homebrew, FreeBSD, Gentoo and Repology package pages, Heroku Dev Center, Bitnami, Kong and APISIX default configuration files (inferred), Kubernetes ingress-nginx retirement notice, Xint, Wiz, Rapid7, Metnir and CIRCL write-ups, CERT-FR alert, Cloudflare and AWS documentation (state on 19 November 2026, 04:30 UTC)*

---

#### DETECTION & FORENSICS (Day 2-3)

No indicators of compromise have been published: no file hashes, address lists or request signatures. Xint says "An attack using CVE-2026-123007 may leave little evidence in nginx access logs." CIRCL says HTTP/2 control frames do not normally show up as individual nginx access-log requests, so "a lack of suspicious access-log lines is therefore not sufficient to exclude exploitation". What exists is one logged crash pattern, core dumps, a warning that fits the proxy bug, and the process and network signals that any web server compromise leaves. That leaves you looking for behaviour: servers that still run the bugs, worker crashes, commands started by the worker user, new files and outbound connections. Our reading: the only usable detection today is host-side.

Sources differ on how reliable exploitation is: Rapid7's notes limit its public code to a freshly started local container, and Xint says its own unreleased exploit works under concurrent normal traffic. Plan for the worse case. No exploitation has been reported (the review window under ADVANCED FORENSICS gives the dates and the sources), so most of this section is about finding exposed servers and spotting attempts. Every command here only reads. Commands marked "run as root" need it.

**Check for signs of attempts and compromise**

**Fleet inventory at scale:**

Ask four questions of every server. Which build is running, and did it restart after the upgrade? Is the HTTP/2 module compiled in? Is HTTP/2 switched on for any listener? Does the server proxy to a backend? Run the Phase 1 commands through your configuration management, remote execution or EDR tooling and collect the output into one table keyed by host. Your access log may record the protocol of each request. If it does, the share of HTTP/2 requests shows whether clients use it. We give no pattern for that, because log formats differ.

| What you see | Reading | Next step |
| --- | --- | --- |
| An affected version (1.9.5 to 1.31.8), the HTTP/2 module compiled in, and HTTP/2 on for a reachable listener | Exposed to CVE-2026-123007. Also exposed to CVE-2026-123633 when the build is 1.19.7 or later and the server proxies to a backend | Patch and restart, internet-facing servers first. Turn HTTP/2 off until then |
| An affected version with no `http2 on;` and no `listen ... http2` anywhere, or without the module | Not exposed to these two bugs today. One edit can change that | Take 1.31.9 or 1.30.7 in your normal window, because the release fixes eight other advisories |
| A static-only site with HTTP/2 on | Exposed to CVE-2026-123007. Outside CVE-2026-123633 (our reading of F5's wording). Wiz (secondary, a lab claim that is not in F5's text) says its test showed code execution on nginx serving ordinary static files, with no backend application or third party modules | Patch and restart. Do not treat "no backend" as safe |
| A Debian, Ubuntu, Red Hat or other distro package with an older-looking number | Not evidence either way, because distro packages backport fixes without changing the version (Xint) | Compare the package with the distro advisory (Option A and Option B under IMMEDIATE ACTIONS). Debian stable, Ubuntu and Red Hat had no fixed package at the cut-off, while Amazon Linux, AlmaLinux 9 and 10 and Debian sid did |
| NGINX Plus where `nginx -v` shows 1.31.8 | A fixed Plus build can still show 1.31.8: 37.3.0.1 is based on 1.31.8 | Check the Plus package version |
| NGINX Plus R33 to R36 | Affected by both, and F5's table lists the fix as "None" for R34 to R36. Our reading: no fixed release on those branches | Move to a fixed 37.x release |
| `http2 off;` in a server block, and a `listen ... http2` parameter on the same address and port | HTTP/2 is still on (inferred from the source) | Remove the parameter, test, reload, and check for old workers (Can't patch today? above) |
| Kong, Apache APISIX or community ingress-nginx anywhere in the estate | HTTP/2 is on by default in all three | Apply the product settings under IMMEDIATE ACTIONS. Community ingress-nginx has no fix and none is coming |
| A fixed package installed, but the main process started before the upgrade | The fix is on disk and the old code still runs | Restart (see Verification under IMMEDIATE ACTIONS) |

Containers carry their own nginx. A scan of the host does not see inside them, so list the running containers with your runtime and run the container commands from Phase 1 for each one. Controllers and gateways in Kubernetes are containers too: check the version inside each controller pod.

*Sources: nginx.org security advisories and documentation, F5 CVE records, Xint and Wiz write-ups, nginx source and shipped configuration files (inferred), distro trackers, NGINX Plus release notes (state on 19 November 2026, 04:30 UTC)*

**Network and edge signals:**

No indicator exists to match on. HTTP/2 over TLS is encrypted, so in our reading a network sensor sees no request content unless it sits where TLS ends. What we found at the cut-off:

- No Cloudflare WAF changelog entry for either CVE (the newest emergency release that day covers a different bug), and no AWS WAF managed-rule entry.
- No Emerging Threats Open rule (the ruleset file dates from 17 November, before disclosure; CONFIRMED by streaming it) and no Snort 3 community rule (0 matches in 4,040 rule lines; CONFIRMED).
- No Sigma, Elastic or CIRCL Rulezet rule, no Nuclei template at the path we checked, and no Metasploit module (searches returned 0; CONFIRMED).
- Akamai, Fastly, Imperva, Fortinet FortiGuard and F5 BIG-IP or Advanced WAF: no guidance found (COULD NOT VERIFY). Sophos (WEAK) says it is investigating and has announced no protection.
- Where a proxy ends the client's connection, its logs hold the client side, and the origin sees only the proxy. Keep the proxy logs for the review window.

A quiet sensor says nothing about success or failure. No published signature exists, and the only wire-level pattern a source offers is Wiz's: long-lived HTTP/2 connections that send large amounts of data.

*Sources: Cloudflare and AWS WAF changelogs, Emerging Threats Open and Snort community rule files, Sigma, Elastic, CIRCL Rulezet, Nuclei and Metasploit searches, vendor pages, Sophos advisory (WEAK), Wiz write-up (state on 19 November 2026, 04:30 UTC)*

**Host logs, and what clean logs mean:**

| Where it shows | What it looks like | Notes |
| --- | --- | --- |
| nginx error log | `[alert] ... worker process 12345 exited on signal 11` (the number is an example) | Xint: a failed attempt can crash a worker, so look for abnormal exits. CERT-EU says worker-crash lines are "not a high-fidelity indicator of successful remote code execution but rather an indication of exploitation attempts". Wiz calls unexpected worker crashes and commands launched by nginx "general warning signs, not confirmed indicators of these vulnerabilities". Other bugs crash workers too. One line proves nothing. A run of them on a server with HTTP/2 on needs a look |
| Core dumps | Dumps from nginx workers (on systemd hosts, `coredumpctl list nginx`) | Xint and CIRCL both name core dumps. Metnir's write-up names one function to look for in a core dump backtrace for CVE-2026-123633 |
| Error log, connection pressure | `[warn] ... 512 worker_connections are not enough, reusing connections` (the number is an example) | nginx logs this warning when it drains connections, at most once per second (Metnir). It also appears on busy servers that are simply short of connections. Repeated worker crashes after these warnings on an HTTP/2 proxy may indicate CVE-2026-123633 (Metnir) |
| Process list | Shells, download tools or interpreters started by the worker user | CIRCL names worker processes spawning unexpected executables. Weak on its own where your hosts run helper programs under that user. Strong where it is not in your baseline |
| Network | Unusual outbound connections or DNS activity from the nginx host. Long-lived HTTP/2 connections with heavy inbound traffic and few logged requests | CIRCL names both patterns. Wiz: "Detection rules covering long standing HTTP/2 connections sending large amounts of data may hint at an attack associated with this vulnerability" (CVE-2026-123007). Compare with the destinations the server normally talks to: backends, databases, APIs |
| Config and web roots | New or changed files | Compare with your deployment source or your file integrity monitoring |
| Access log | Nothing specific | Xint and CIRCL: little or no evidence. A clean access log does not clear a server |

```bash
# Worker crashes in the error log (run as root; the path comes from the error_log directive, this is the usual one)
grep -Ei 'worker process.*exited|signal 11|segfault' /var/log/nginx/error.log
# Connection-pressure warnings (also normal on busy servers)
grep -F 'worker_connections are not enough' /var/log/nginx/error.log
# Core dumps recorded for nginx on systemd hosts (Xint's suggestion)
coredumpctl list nginx
# Processes running as the worker user, with their parents. Change the names if your workers run as another user
ps -eo user,pid,ppid,lstart,args | grep -E '^(nginx|www-data|nobody) '
# Listening sockets with their processes (run as root)
ss -tlnp
```

Three caveats apply to the process list:

- It shows live processes only. A program that ran and exited leaves nothing for `ps`. Pair it with process-creation logging from your EDR or the Linux audit subsystem, filtered on the worker user. Xint suggests an audit rule for this. We give no rule text: take it from Xint's write-up and test it on a non-production host first.
- The normal workers are `nginx: worker process` entries whose parent is the root-owned main process. Look at what is not one of those. Hosts that run helper programs under the worker user show such processes as normal, so baseline a known-good server of the same role first.
- If your workers run as another user, change the pattern. A minimal system such as Alpine ships a `ps` that may not accept these fields.

For outbound connections and new files, use the tools you already have: firewall or flow logs for the connections, and file integrity monitoring or a comparison with your deployment source for the files. We give no commands for the connections, because no source gives a pattern to look for.

A quiet error log doesn't clear a server. Xint and CIRCL both say the evidence in nginx's own logs may be thin, and we have no source on what a successful attempt leaves behind. A fixed build closes the bugs, and it doesn't tell you what happened before it was running. If logs rotate fast or stay only on the host, the evidence may already be gone, so send them off the host (see Monitoring and alerting under DEFENSE-IN-DEPTH MEASURES).

**How to read the signals together:**

| What you see | Reading | What to do |
| --- | --- | --- |
| An unpatched server with HTTP/2 on and nothing else | Exposed, not known to be hit. Clean logs prove little | Patch and restart. Copy the logs off the server first |
| One worker crash line | Probably another cause, but an attempt cannot be ruled out. CERT-EU: not a high-fidelity indicator | Note the time, read the access log around it, and check whether the server is patched |
| Repeated worker crashes on an unpatched server with HTTP/2 on | A failed attempt can end as a worker crash (Xint). F5 says CVE-2026-123007 is typically followed by a worker segmentation fault | Treat it as an attempt. Keep the error and access logs and any core dumps, patch, and run the other checks on this server |
| Connection-pressure warnings, then crashes, on an HTTP/2 proxy | Fits what Metnir says may indicate CVE-2026-123633. A busy server short of connections also warns | Keep the error log and core dumps, patch, and look at worker_connections headroom after the change |
| A shell, download tool or interpreter started by the worker user, and it is not in your baseline | Possible code execution as the worker, which is the impact F5 and the researchers describe | Incident. Preserve first (see ADVANCED FORENSICS), then rebuild |
| A new or changed file in a web root or config that you did not deploy | Possible web shell or persistence | Incident |
| An outbound connection from the nginx host to an address you do not know | Possible download or reverse connection | Incident. Block it at your egress point and keep the flow logs |

**What the worker user could read:**

Every public demonstration ran code as the unprivileged worker user. Xint: "The commands run with the privileges of the nginx worker process that handles the request." Rapid7 says the memory corruption can "disclose data, interrupt service, and execute code with the nginx worker process's permissions", and Metnir reports a command running on the target as the unprivileged nginx user. Xint reached root only by chaining a separate Linux kernel flaw, and says so itself. In its tests that chain also escaped a Docker container running nginx. Wiz, Rapid7 and Metnir claim no root, and CIRCL says "A vulnerable NGINX instance does not by itself imply host-root access". So the scope is what that user and that process can read or reach. On a server set up to run workers as root, it is the whole host (our reading). Build your rotation list from what the server held:

- TLS private keys and certificates for the sites it serves (our reading: the process holds them in memory, and Rapid7 says the corruption can disclose data)
- Credentials in the proxy configuration: backend tokens and API keys set in headers, basic-auth files, client certificates and keys for upstream TLS
- Traffic the worker handled in clear text: session cookies, bearer tokens and form data from requests in flight (our reading)
- Credentials the host holds for other systems: cloud credentials, mail relays, backup targets, deploy keys
- Secrets mounted into the container or pod, where nginx runs in one, including the pod's service account token (our reading)
- Anything else the worker user can read

**Compromise indicators checklist:**

- [ ] Every internet-facing nginx with HTTP/2 on runs a fixed build, has HTTP/2 off, or has a written reason and a date
- [ ] No worker crash line or core dump since 11 November, or each one traced
- [ ] No shell, download tool or interpreter started by the worker user outside your baseline
- [ ] No new or changed file in a web root or config that you did not deploy
- [ ] No unexplained outbound connection from the nginx host
- [ ] You know which servers serve HTTP/2, containers, controllers and gateways included
- [ ] No unverified checker or proof-of-concept code was run on a production host

**If ANY indicator turns up:** start incident response. One crash line is weak evidence, and a shell started by the worker user, or a crash followed by a new file or a new outbound connection, is not. A clean log doesn't clear a server. If an exposed, unpatched server shows any indicator, treat it as compromised until you can show otherwise. Capture state before you restart it (see ADVANCED FORENSICS), rebuild the server on a fixed build, and rotate everything it held. Do it in this order: preserve evidence, rebuild, then rotate. New secrets on an unpatched server would go to the same attacker. Rotating signing keys logs users out, so plan for that.

**Evidence to keep before any restart:**

A restart ends the old processes, and a rebuild wipes the logs on the host. On a server you suspect, or one in the review window with HTTP/2 on, keep these first (ADVANCED FORENSICS has the commands and the handling):

- The process and socket listing, with start times, as it is now
- The nginx error logs, rotated ones included, and any core dumps from workers
- The access logs, and the proxy, load balancer and CDN logs for the same period. They may show little, but they date the traffic
- The nginx version output, the compile settings and the configuration files, with their modification times
- The web roots and any directory the worker user can write to, or a snapshot of them
- For a container or pod, the image reference, the filesystem and the pod spec
- Flow or firewall logs for the nginx host, and a memory image if you can take one

*Sources: Xint, Wiz, Rapid7, Metnir and CIRCL write-ups, CERT-EU advisory, F5 CVE records, nginx.org advisories, nginx documentation (state on 19 November 2026, 04:30 UTC)*

---

#### DEFENSE-IN-DEPTH MEASURES

The fix is nginx 1.31.9 or 1.30.7 (NGINX Plus 37.3.0.1 or 37.0.8.1, or your distro's fixed package once it ships) and a restart. Turning HTTP/2 off is advice from the researchers, CIRCL and CERT-FR, not an F5 or nginx.org workaround: F5's records say "None". Everything else in this section narrows the exposure or limits the damage, and none of it removes the bug. The first table shows what each control covers and what it leaves open.

| Control | What it covers | What it leaves open |
| --- | --- | --- |
| `http2 off;` with no `listen ... http2` parameter left on any listener | Both bugs on that server. Wiz, Xint, CIRCL, CERT-FR and Metnir give this advice | The eight other fixes in the release. Drift: a later edit can switch HTTP/2 back on, and a leftover `listen ... http2` keeps it on despite `http2 off;` (inferred). Services that need HTTP/2 end to end, such as native gRPC, break |
| A proxy that does not speak HTTP/2 to the origin (AWS ALB and CloudFront by default, Akamai by default, Cloudflare with "HTTP/2 to Origin" turned off) | Traffic through the proxy does not reach the origin over HTTP/2 (HTTP/1.1 for ALB and CloudFront), so the origin's HTTP/2 code is not on that path (our reading) | An origin that still answers directly with HTTP/2 on. Lock the origin to the proxy |
| A proxy that speaks HTTP/2 to the origin (Cloudflare by default on Free, Pro and Business, for origins that announce HTTP/2 through ALPN) | Not known to cover anything. No source tested whether either bug can be triggered through one | Treat the origin as exposed |
| Locking the origin to the proxy's address ranges | Direct requests to the origin's own address | The proxy path itself. Needs a maintained list of ranges |
| WAF or IPS rule | See the next table: we found no rule for either CVE | Everything |
| A product setting (`use-http2`, the Kong listen strings, `enable_http2`) | HTTP/2 on that product, where the setting works as described | Community ingress-nginx has no fix and none is coming. The APISIX setting is inferred |
| The fixed build, then a restart | Both bugs, once the package is installed and the main process has restarted | Nothing for these two CVEs |

**WAF and IPS coverage on 18 November 2026**

| Product | State | Note |
| --- | --- | --- |
| Cloudflare WAF | No changelog entry for either CVE | The newest emergency release that day covers a different bug |
| AWS WAF managed rules | No entry | |
| Emerging Threats Open | No rule | The ruleset file dates from 17 November, before disclosure (CONFIRMED by streaming it) |
| Snort 3 community rules | No rule | 0 matches in 4,040 rule lines (CONFIRMED) |
| Akamai, Fastly, Imperva, Fortinet FortiGuard, F5 BIG-IP or Advanced WAF | No guidance found | COULD NOT VERIFY. Ask your vendor |
| Sophos (WEAK) | Investigating, no protection announced | Read through an indirect fetch, so the wording is weaker |

Don't count on a WAF or IPS for these bugs. We found no rule for either CVE, and no proxy is known to block them.

*Sources: nginx.org and F5 advisories, Cloudflare and AWS documentation, Cloudflare and AWS WAF changelogs, Emerging Threats Open and Snort community rule files, vendor pages, Sophos advisory (WEAK), Wiz and CIRCL write-ups (state on 19 November 2026, 04:30 UTC)*

**Scanner and feed coverage**

The entries below come from the vendors' own pages and feeds, so they say what a product lists, not what it finds on your server. A clean scanner report still proves little. Here is what the data feeds held at 04:30 UTC on 19 November 2026:

| Source | State on 19 November 2026 | What a clean result means |
| --- | --- | --- |
| NVD | Both records "Received" (not analysed), published 18 November at 16:18:04 UTC, with later changes at 20:18 and 21:17 UTC and one more for CVE-2026-123633 at 23:17 UTC. No NVD score of its own and no CPE configuration data. It shows F5's scores | A tool that matches on CPE data has nothing to match yet (our reading), so a clean result there says nothing |
| CISA KEV | Not listed (catalog 2026.11.18, released 19:17 UTC; checked at 19:59 and 20:10 UTC on 18 November and at 04:27, 04:45 and 04:48 UTC on 19 November). CISA's SSVC entries say Exploitation none, Automatable no, Technical Impact total | A queue that ranks by KEV will not raise it |
| EPSS | No score yet for either CVE (the API returned no data at 19:35, 19:48 and 19:59 UTC on 18 November and at 04:27 and 04:45 UTC on 19 November) | A queue that ranks by EPSS shows nothing. Rank by exposure instead |
| GitHub Advisory Database | Two unreviewed advisories, GHSA-m4q8-cf44-f42r (CVE-2026-123007) and GHSA-7xxj-p8w5-434q (CVE-2026-123633), both Critical with CVSS v4 9.2 | A pointer, not a reviewed record |
| Tenable | Plugins "Coming Soon" for both CVEs | No check ships yet, so a clean Tenable report says nothing about these bugs |
| Rapid7 | Vulnerability database pages for both CVEs with F5 and NVD text, and no check shown | "Not flagged", not "not exposed" |
| Snyk | SNYK-UNMANAGED-NGINX-22598758 for CVE-2026-123007 (critical, Exploit Maturity "Proof of Concept") | A listing, not proof of exposure |
| Wiz | Says a pre-built query and advisory sit in its Threat Center (customers only) | We could not see it |
| Qualys | QIDs 736231 (NGINX Open Source) and 389654 (F5 NGINX Plus) are listed as pending, release shown as "TBD By EOD" (WEAK) | Do not assume a clean Qualys report covers these bugs until the QIDs ship |
| Metasploit and Nuclei | No Metasploit module (searches returned 0; CONFIRMED). No Nuclei template at the path we checked (searches at 19:36 and 20:02 UTC on 18 November, repeated at 04:28 to 04:45 UTC on 19 November with the same result; a template at another path would not show) | We found no module and no template, so a run with either proves little |
| Distro trackers | No fixed package at Debian stable and testing, Ubuntu, Red Hat, SUSE (state "Analysis") or Rocky. No record at Oracle Linux. Fixed at Amazon Linux, AlmaLinux 9 and 10, Alpine (edge, 3.24, 3.23 and 3.22), Debian sid, Arch, Homebrew, FreeBSD ports and Gentoo's tree | "Needed", "vulnerable", "Analysis" and "Pending Fix" all mean no fixed package. A tracker says a fixed package exists, not that your server runs it. A missing record is not a clean bill |
| Defaults we inferred | HTTP/2 is off in the stock configs we read (nginx source tree, nginx.org packages, Docker official image, Debian, Ubuntu, RHEL's CentOS Stream files, Alpine). Source builds do not compile the module unless asked | Confirm on the host with the Phase 1 checks. A default does not survive an admin's edit, and Kong, Apache APISIX and community ingress-nginx switch HTTP/2 on by default |

A remote version check can see neither whether HTTP/2 is on nor whether a distro backport is installed (our reading), so it cannot clear or flag a server on its own.

*Sources: NVD, CISA KEV catalog and SSVC entries, FIRST EPSS API, GitHub Advisory Database, Tenable, Rapid7, Snyk and Wiz pages, Metasploit and Nuclei searches, distro trackers, nginx and distro build and configuration files (inferred) (state on 19 November 2026, 04:30 UTC)*

**The version number trap.** There are four traps here.

- The distro number. Distro packages backport fixes without changing the nginx version: Xint lists Ubuntu 24.04 at 1.24.0, Ubuntu 22.04 at 1.18.0 and Debian 12 at 1.22.1. Judge distro packages by the distro advisory. At the cut-off Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid had shipped a fix, and Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux had not.
- Products that embed nginx. They carry their own numbers. OpenResty 1.31.8.1 is based on nginx 1.31.8 (inside the affected range, with no fix shipped), and Kong's source tree pins an nginx 1.27.1 core (inside the range, inferred). NGINX Plus 37.3.0.1 is based on 1.31.8 yet has the CVE-2026-123007 fix, so the open source version of a Plus build says nothing about the fix.
- Docker tags, which move. The official image tags were updated on 18 November, and nginxinc/nginx-unprivileged has no fixed tag.
- The running process. A server that installed the fixed package and has not restarted still runs the old code, and `nginx -v` prints the version of the program on disk. Compare the process start time with the upgrade time.

Where we inferred a status, check again when the vendor publishes a notice.

*Sources: Xint write-up, nginx.org advisories, NGINX Plus release notes, OpenResty and Kong source files and GitHub issue, Docker Hub, distro trackers (state on 19 November 2026, 04:30 UTC)*

---

**Edge architecture**

**Option 1: put a proxy that speaks HTTP/1.1 to the origin in front, and lock the origin.** These bugs are reached through HTTP/2 itself, so the question is which protocol the proxy speaks to your origin. AWS documents that "By default, Application Load Balancers send requests to targets using HTTP/1.1." and that CloudFront "forwards requests to your custom origin using HTTP/1.1". Check that nobody changed either default, including the ALB target group's protocol version (HTTP/2 or gRPC). It holds only if nothing can reach the origin directly. Lock the origin firewall to the proxy's IP ranges, then test from outside your network that the origin's own address no longer answers HTTP/2. If the hop to the origin is plain HTTP and the origin still has a `listen ... http2` parameter on that listener, a client that can reach the origin directly can speak cleartext HTTP/2 to it (inferred).

**Option 2: Cloudflare in front.** Cloudflare says "At Cloudflare, HTTP/2 connection to the origin is enabled by default." It connects with HTTP/2 only to origins that announce it through ALPN, and falls back to HTTP/1.1 otherwise. The setting reads "Enabled by default" on Free, Pro and Business plans and "Disabled by default (1 stream per connection)" on Enterprise. So on Free, Pro and Business plans, Cloudflare in front does not keep HTTP/2 away from an origin that offers it. The switch is Speed > Settings > Protocol Optimization > HTTP/2 to Origin. Turn it off for zones whose origin cannot be patched or switched to HTTP/1.1 yet (our reading: this removes the HTTP/2 path through Cloudflare, not the origin's own listener).

**Option 3: Akamai and Fastly.** Akamai says that when HTTP/2 is on, the connection from the edge to the origin is not HTTP/2 by default, and it offers an "HTTP/2 Edge to Origin" option (its changelog dates the option to 29 July 2025). Check whether it is on for your properties. For Fastly we could not verify an explicit HTTP/2-to-origin statement (COULD NOT VERIFY); its docs say it supports any backend that is an HTTP/1.1 compliant web server.

**Option 4: do not count on any proxy to block the bugs.** Whether either bug can be triggered through a proxy that speaks HTTP/2 to the origin is unknown, because no source tested it. Wiz says CDNs and WAFs that terminate HTTP/2 "may mitigate parts of the exploit" and adds "This depends on implementation". Rapid7's notes say a network proxy in the path will likely make its own public code fail. Those are the researchers' statements, and no CDN or WAF vendor rule or statement was found for either CVE. Treat every proxy setting as a layer on top of the patch. Xint adds a testing point: if a CDN or reverse proxy sits in front of nginx, a protocol test reaches only the proxy, so also test the nginx server directly.

*Sources: AWS Application Load Balancer and CloudFront documentation, Cloudflare HTTP/2 to Origin documentation, Akamai and Fastly documentation, Wiz, Xint and Rapid7 write-ups, nginx source (inferred) (state on 19 November 2026, 04:30 UTC)*

**HTTP/2 policy**

HTTP/2 is off in a stock install (inferred from the shipped files). The `http2` directive defaults to off, source builds do not compile the module unless asked ("This module is not built by default, it should be enabled with the --with-http_v2_module configuration parameter."), and the default configs we read have a plain `listen 80;` server. HTTP/2 comes on when an admin edits a server block, or when a product default does it. One edit can undo your interim measure.

Policy: HTTP/2 stays off on a server unless a service needs it and someone has written down why. Where you want HTTP/2 for clients, a proxy that speaks HTTP/1.1 to the origin can serve it at the edge, if your proxy supports that. Turning HTTP/2 off removes the exposure to these two bugs on that server. It does not replace patching, because the release fixes eight other advisories. Whether to switch HTTP/2 back on after patching is a decision for each server.

| Where | Setting | Notes |
| --- | --- | --- |
| nginx 1.25.1 and later | `http2 off;` in each server block, or once in `http {}` | Check every server block that shares the listening address and port. A leftover `listen ... http2` keeps HTTP/2 on (inferred) |
| Older syntax (1.9.5 and later) | Remove `http2` from `listen` | Cleartext listeners too: `listen 80 http2;` becomes `listen 80;` |
| Source builds | Leave out `--with-http_v2_module` where you do not need HTTP/2 | No module, no HTTP/2 code (Xint). Needs a rebuild and a restart |
| Stock packages, the Docker official image | Nothing to change on a stock install | The default site is `listen 80;` (inferred from shipped files). HTTP/2 comes on only after an edit |
| Kong | Take `http2` out of `proxy_listen` and `admin_listen` | The defaults carry it on the 8443 and 8444 listeners (inferred from kong.conf.default) |
| Apache APISIX | `enable_http2: false` in conf/config.yaml | Inferred. Check APISIX's own docs |
| Community ingress-nginx | ConfigMap key `use-http2` set to "false" | The default is "true". Retired, no fix coming |
| F5 NGINX Ingress Controller | ConfigMap key `http2`, annotation `nginx.org/http2`, VirtualServer `http2` field | Off by default. Check that nobody turned it on per resource |
| OpenResty, Tengine, Angie, freenginx | The nginx-level change above | Tengine's HTTP/2 module is off by default (inferred). Angie's is not built by default per its docs. OpenResty's Alpine image builds with both the HTTP/2 and HTTP/3 modules, and whether its own config turns HTTP/2 on is COULD NOT VERIFY |
| Containers | Put the change in the image's config, then rebuild | Check each image: a fixed tag does not change your own config |
| Hosting stacks | The panel's own setting | cPanel and Plesk: COULD NOT VERIFY |

To catch drift, run the Phase 1 `nginx -T` grep and the `curl` check on a schedule across the fleet, and alert when `http2 on;` or a `listen ... http2` parameter shows up where policy says HTTP/2 stays off (see Monitoring and alerting below).

*Sources: nginx.org documentation for ngx_http_v2_module, ngx_http_core_module and configure, nginx source and shipped configuration files (inferred), Kong, APISIX, ingress-nginx and F5 Ingress Controller configuration files (inferred), OpenResty, Tengine and Angie build files and documentation, Xint write-up (state on 19 November 2026, 04:30 UTC)*

**What does NOT help:**

- Reloading after a package upgrade. A reload does not replace the running executable (Xint), and a reload after an HTTP/2 change leaves open connections on the old workers.
- Installing the fixed package without restarting. The running process keeps the old code.
- Setting `http2 off;` and leaving a `listen ... http2` parameter in a server block that shares the address and port.
- Reading `nginx -v` on NGINX Plus. A fixed Plus build can show 1.31.8.
- Reading a distro package's number against nginx.org's versions. Distro packages backport fixes.
- Moving to an older branch. No fixed release exists on any branch before 1.30 (inferred), although some distro builds backport the fix, such as Alpine 3.23 and 3.22 with 1.28.3-r8.
- Counting on a CDN or proxy to block the bugs. No proxy is known to block them, and Cloudflare's HTTP/2 to Origin is on by default for Free, Pro and Business plans.
- Counting on a WAF or IPS rule. We found no rule for either CVE.
- Raising worker_connections. F5's text says CVE-2026-123633 needs a worker running low on it, but no source offers more headroom as a mitigation, so do not treat it as a fix (our reading).
- Tuning HTTP/2 stream or header settings. No source ties either bug to HPACK or stream settings.
- Turning HTTP/2 off as the only step. It leaves the eight other fixes in the release open.
- Running workers as an unprivileged user as the only measure. They already drop from root to the configured user. It limits what a successful attempt can do, and it does not stop the bug.
- Waiting for KEV or a high EPSS score. KEV does not list either CVE, and EPSS had no score at 04:30 UTC on 19 November.
- Code from public repositories that call themselves checkers or exploits. 18 repositories match a search for either CVE ID in quotes, and none of the third party code is verified.

*Sources: nginx.org advisories and CHANGES, F5 CVE records, Xint, Wiz, CIRCL and Rapid7 write-ups, Cloudflare documentation, Alpine package pages, CISA KEV catalog, FIRST EPSS API, GitHub repository search (state on 19 November 2026, 04:30 UTC)*

---

**Hardening that limits the damage**

None of this stops the bugs. It limits what a successful attempt can do, and it is our advice, not a vendor's. Code execution here is as the worker user. F5 says attackers "can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR", and Wiz says it confirmed code execution with an ASLR bypass on official 1.31.7 and 1.31.8 builds in the lab. Xint says full control of the host needs a privilege escalation bug as well, and that in its tests a separate Linux kernel flaw gave it root, including from a Docker container running nginx. So what the worker user can read, write and reach sets the damage.

- Least privilege: keep the workers on an unprivileged account that owns nothing, and do not set them to run as root. The master runs as root and the workers drop to the configured user, so check the worker line in the Phase 1 `ps` output. Keep the binary and the configuration owned by root and read-only to the worker.
- Keep ASLR on. F5 says attackers can execute code on systems where ASLR is disabled or can be bypassed. CIRCL: "ASLR remains an important defence-in-depth control, but is not an effective standalone mitigation for these vulnerabilities", and it says not to downgrade or close a finding merely because ASLR or PIE is enabled. Treat any host with ASLR off as a finding of its own.
- Keep the host kernel on your vendor's current security release. Xint's root claim rests on a separate kernel flaw, so a container is not a boundary you can rely on alone (our reading).
- Restrict outbound traffic from nginx hosts with an allow list at the host firewall, the security group or an egress proxy. It does not stop the bugs, but it breaks a reverse shell or a tool download after code execution. CIRCL also advises limiting outbound connectivity.
- Isolate backends: keep internet-facing nginx apart from hosts that hold other secrets, and from backends the worker has no reason to reach. Keep internal-only servers reachable only from the networks that need them. They are in our HIGH tier, not out of scope.
- Mount or load only the secrets each site needs, and use short-lived credentials where you can. Rotation after an incident is then a small job.
- In a container, run the process as a non-root user, mount the filesystem read-only where the image allows it, and drop capabilities you do not need. Pin the base image to a version tag such as `nginx:1.30.7`, and rebuild on a schedule so that new point releases reach your images.
- In Kubernetes, give a controller's service account only the permissions it needs, because code running in the controller pod can reach whatever that account and the mounted secrets allow (our reading). Review the vendor images of ingress controllers (CIRCL).
- Decide on purpose whether workers may write core dumps. They are evidence after a crash, and they hold whatever the worker held in memory, so limit who can read them.
- Send the error log, the access log and process-creation events to a place the server cannot change (see Monitoring and alerting below).

*Sources: F5 CVE records, Xint, Wiz, Rapid7 and CIRCL write-ups. The rest is our own advice, not a vendor's.*

**Patch cadence and the silent window**

The picture of how early the fix was public is not clear. The fix commits carry 11 November dates (committer dates 12:13 and 12:16 UTC on master), and the 1.31.9 and 1.30.7 tarballs on nginx.org carry file times of that day (17:59 and 18:09, time zone not stated). GitHub's activity log shows no push to nginx master between 9 November at 13:29 UTC and 18 November at 15:20 UTC, so the fixes reached GitHub on 18 November even though the commit dates say 11 November (our reading). Two Hacker News comments say the fix was public a week earlier, and the push log does not support that. Whether the 11 November tarballs were downloadable before 18 November is not established. NGINX Plus customers had the CVE-2026-123633 fix from 14 October per the release notes. The CVE IDs were only reserved on 9 November, so the CVE number was added to those notes later (our reading).

- Set a written cadence that gets each nginx release onto every server within days, with restart windows built in. A package that is installed and not restarted protects nothing.
- Watch nginx.org's advisories page, F5's K-articles and your distro's tracker, not only CVE alerts. The nginx-announce archive has no 2026 pages (COULD NOT VERIFY), and since August 2025 nginx.org's advisories page links F5's K-articles instead.
- Take every nginx release, not only the ones that name HTTP/2. This one fixed 10 advisories at once, eight of them outside these two bugs.
- Keep an emergency path outside the normal window for a web server bug. Patch internet-facing servers with HTTP/2 on first.

*Sources: nginx.org advisories, CHANGES and news item, nginx GitHub commits and activity log, F5 CVE records, NGINX Plus release notes, nginx-announce archive, Hacker News comments (state on 19 November 2026, 04:30 UTC)*

---

**Monitoring and alerting**

Turn the signals on before you alert on them. A rebuild wipes the server's own logs, so the copy that counts is the one that left the host. Write the queries in your own SIEM's syntax from the patterns in the table. Baseline first: your normal crash rate, your helper programs and your usual destinations decide the thresholds.

| What to watch | Where it comes from | Alert when |
| --- | --- | --- |
| Build and restart state | The Phase 1 and Verification commands, plus the process start time, run on a schedule | An internet-facing server with HTTP/2 on runs a build below the fixed one, or its main process started before the upgrade |
| HTTP/2 drift | The Phase 1 `nginx -T` grep and the `curl` check, run on a schedule across the fleet | `http2 on;` or a `listen ... http2` parameter appears where policy says HTTP/2 stays off |
| Worker crashes | `exited on signal 11` lines in the error log and core dump records, read from a log copy held off the server | Any, on a server with HTTP/2 on, until you know your baseline |
| Connection pressure | `worker_connections are not enough` warnings, from the same copy | Repeated warnings on an HTTP/2 proxy, or any followed by a crash |
| Process creation | EDR or audit events for processes owned by the worker user | A shell, download tool or interpreter that is not in your baseline |
| Long-lived HTTP/2 connections | Flow or proxy logs | Heavy inbound traffic and few logged requests (Wiz, CIRCL) |
| Config and web roots | File integrity monitoring, or a diff against your deployment source | Any change that does not come from a deploy |
| Outbound connections | Firewall or flow logs for the nginx hosts | A destination the server does not normally use |
| Proxy settings | The proxy's own config or API, read on a schedule | "HTTP/2 to Origin" or the origin protocol changes, or the origin answers directly again |
| Vendor status | Distro trackers, F5 K-articles and nginx.org advisories, checked daily until your platform is fixed | A "needed" or "Pending Fix" entry turns into a fixed package: patch that day |

---

#### ADVANCED FORENSICS

A restart destroys the memory of the nginx processes, and a rebuild wipes the server. We have no source that says what an attempt leaves behind, and Xint says it may leave little in the access logs, so volatile state may be the only evidence. On any server that showed one of the signals above, capture first and patch second. Work in order of how fast things disappear: processes and connections first, then memory, then logs and core dumps, then config and web roots, then the disk.

**Capture volatile state before any restart:**

Bring trusted tools to the server, and send each output to a file on an evidence volume or a remote destination, not to the application disk.

```bash
# run as root. Every process with its parent, owner and start time
ps -eo user,pid,ppid,lstart,args
# The same as a tree, to see what each process started (Linux procps only)
ps -eo user,pid,ppid,lstart,args --forest
# Listening sockets with their processes
ss -tlnp
# Version, compile settings and the configuration on disk. The dump can hold secrets, so treat the file as sensitive
nginx -v
nginx -V
nginx -T
# Service log lines kept by the journal
journalctl -u nginx --no-pager
# Core dumps recorded for nginx on systemd hosts
coredumpctl list nginx
# Files under the nginx config directory changed since the start of the review window. Add your web roots as further paths
find /etc/nginx -type f -newermt '2026-11-11'
```

```bash
# Container: version, compile settings and configuration as they are now (replace <container> with its name or ID)
docker exec <container> nginx -v
docker exec <container> nginx -V
docker exec <container> nginx -T
```

```bash
# Kubernetes: record the pod's full spec, including the image it runs (add your namespace flag if the pod is not in the current namespace)
kubectl get pod <pod> -o yaml
```

`nginx -T` reads the config on disk. If the config changed without a reload, the running config may differ (Xint), so also copy the config files and note their modification times. For established connections, use your EDR or flow logs. Copy the error logs, the access logs (rotated ones too), any core files, the nginx config and the web roots to the evidence volume, and hash them as soon as they are there.

If you can, take a memory image as well, with a Linux memory acquisition tool of your choice and its own documentation, or a hypervisor snapshot that includes memory. This document gives no capture commands. A memory image holds every secret the server had, so encrypt it and limit who can read it. Reading one takes specialist tools, so capture it, hash it and hand the analysis to someone who does this for a living. Keep the version output with it.

Then isolate the server: cut its network at the switch, the security group or the hypervisor, and do not shut it down. For a container, do not remove it. Export or snapshot its filesystem with your runtime's tools before you replace it. For a pod, keep the pod and its node until the evidence is copied, and keep the controller's service account token in scope for rotation.

**Process hunting for the worker user:**

Run the hunt from DETECTION & FORENSICS before anything changes the process list. Record each hit in full: the process, its parent and children, its start time, and its sockets from the list you captured.

```bash
# Processes running as the worker user, with their parents. Change the names if your workers run as another user
ps -eo user,pid,ppid,lstart,args | grep -E '^(nginx|www-data|nobody) '
```

The normal workers are `nginx: worker process` entries whose parent is the root-owned main process. A shell, a download tool or an unknown binary owned by the worker user, and not in your baseline, is an incident. If its start time lines up with crashes in the error log, that is the sequence to chase. A clean result does not clear the server: the command lists live processes only, and anything that has already exited leaves nothing.

**Why a code-execution compromise means rebuilding the server:**

Once an attacker has run code as the worker user, everything that user can write may have changed: web roots, uploads, caches, temp directories, and any file the application writes. The process list, the file listing and the logs come from a system the attacker has touched, so a scan that finds nothing proves nothing. A fixed build stops new attempts and removes nothing that is already installed. This is our reasoning, not a vendor statement, and it is standard practice after a code-execution compromise. The nginx bugs give code execution as the worker user, not root, and Xint reached root only by chaining a separate kernel flaw in its lab. Where the workers run as root, treat the whole host as compromised.

If a server shows a shell, a new file or an unexplained outbound connection, or you cannot rule one out, rebuild it:

- Preserve first: process and socket state, logs, core dumps, memory if you can, and a disk image or snapshot.
- Rebuild from a known-good image that carries a fixed build, not from a copy of the old system disk.
- Restore content and data only after you have checked them. Do not restore web roots, scripts, cron entries, unit files or configuration from the old server without reading them.
- Rotate everything the server could read or reach (see What the worker user could read under DETECTION & FORENSICS). Rotate after the rebuild, not before: new secrets on an unpatched server would go to the same attacker. Rotating signing keys logs users out, so plan for that.
- Treat every container that ran from a compromised image or on a compromised host as exposed, with the secrets mounted into it.
- Check the neighbours: every host that the server could reach with the credentials it held.

Patching in place is acceptable for a server with no indicator and no link to an attempt.

**Evidence handling:**

- Record who collected what, when, from which server, and with which tool and version. Record the server's clock offset from UTC, and keep every timestamp in UTC.
- Hash each item with SHA-256 right after you collect it, write the hashes to a separate file, and keep a read-only copy off the server.
- Work on copies. Keep the originals untouched.
- Encrypt memory images, core dumps, logs and exports, at rest and in transit, and limit who can read them.
- Log every command you run on the suspect server, and note whether it only read or changed something.
- If you expect legal action or an insurance claim, image the disk (a volume snapshot on a cloud server) before you rebuild.

**Building the timeline:**

Put every source on a single UTC timeline and mark each entry: exposure (an exposed build was running), attempt (crashes), or possible success (a process, a file or a connection that is not in your baseline).

| Source | What it gives you |
| --- | --- |
| Package and restart history | When each server last ran an exposed build, and when it installed and restarted into the fix |
| Error logs | Worker-crash lines and connection-pressure warnings, with their times |
| Core dumps | Which worker crashed, and when |
| Access logs | The client addresses and requests around each crash. They may show little (Xint, CIRCL) |
| Process start times | The `lstart` column for every hit in the process hunt |
| File times | Creation and change times of files in config and web roots |
| Firewall, flow and proxy logs | Outbound connections, long-lived HTTP/2 connections, and what the proxy saw of the client |
| Platform logs | Cloud audit logs and instance events, and for containers the orchestrator events |
| Credential use | Where the secrets from the server were used afterwards, and from which addresses |

No published attack pattern exists beyond the signals above, so we cannot tell you which requests to look for. The sequence to chase is a run of crashes followed by a process, a file or a connection that is not in your baseline.

**The window to review:**

No exploitation had been reported at about 04:30 UTC on 19 November 2026, 13.5 hours after disclosure at 15:00 UTC on 18 November. CISA's SSVC entries say Exploitation none, and its KEV catalog (2026.11.18) does not list either CVE. The Hacker News says neither the vendor nor the Wiz and Rapid7 researchers have reported attacks, and CERT-EU says none had been reported yet. CIRCL's sightings feed showed 0 "exploited" sightings for both CVEs at the 18 November check (68 sightings for CVE-2026-123007 and 47 for CVE-2026-123633; not re-run). Previdian (WEAK, its own sensors and no data shown) says "Previdian sensors have not observed exploitation attempts against either of these vulnerabilities." Our reading: confidence is moderate, because no primary telemetry was reachable (GreyNoise and Shadowserver: COULD NOT VERIFY).

NCSC-NL, at 16:07 UTC, expects proof-of-concept code soon and large-scale exploitation after it, and Wiz says widespread attacks tend to start against packaged products where many customers run the same build and configuration. Public proof-of-concept material exists for CVE-2026-123007: Rapid7 published a proof of concept (its repository was last pushed at 15:23 UTC, and CIRCL's feed first saw one at 17:04 UTC), unverified third party exploit code has appeared since, Censys Research published proof-of-concept material and HKCERT says one is public. Wiz, Xint and Metnir withhold their exploits.

| Window | Starts | Use it when |
| --- | --- | --- |
| Minimum | 11 November 2026 | Always. It is the date on the fix commits, the 1.31.9 and 1.30.7 tarballs and the nginx.org package builds. It is also a week before disclosure, which is when two Hacker News comments say the fix was public. The fixes reached GitHub on 18 November at 15:20 UTC, and whether the tarballs were downloadable earlier is not established, so treat 11 November as a margin, not as a known exposure date |
| Maximum, servers that proxy to a backend | 12 September 2026 | The server is internet-facing with HTTP/2 on, holds sensitive data, and you keep logs that long. That is the date Metnir says it reported CVE-2026-123633 to F5. No source says anything was public then or that anyone else knew, so treat it as a margin and not as a known exposure date |
| Maximum, other servers with HTTP/2 on | 16 October 2026 | The same conditions. That is the date Xint says it reported to F5 through HackerOne, and the same caveat applies |

Don't start later than 11 November. Weigh the hours from 15:00 UTC on 18 November more heavily: the public proof of concept appeared that afternoon, and the NCSC-NL expectation points the same way. The window ends when each server runs a fixed build and its main process has restarted, not on the day you installed the package. Re-run the hunt once the first attack reports appear, because a review made about 13.5 hours after disclosure is a short one.

*Sources: nginx.org advisories, nginx GitHub commits and activity log, F5 CVE records, NGINX Plus release notes, Xint, Wiz, Rapid7 and Metnir write-ups, CISA SSVC entries and KEV catalog, FIRST EPSS API, CIRCL sightings feed, CERT-EU advisory, NCSC-NL advisory, The Hacker News, Previdian (WEAK), Hacker News comments (state on 19 November 2026, 04:30 UTC)*

**Public repositories named after the CVEs:** as of 04:45 UTC on 19 November, a GitHub search for either CVE ID in quotes returns 18 repositories, 7 of them created after 20:10 UTC on 18 November. The figure counts search matches. By their own descriptions, the repositories we read include third party exploit and proof-of-concept claims for CVE-2026-123007, one of which claims a full code execution chain, a lab repository from Censys Research with proof-of-concept material, Docker labs and read-only scanners. None of the third party code is verified, and we read descriptions and file lists only and ran nothing. The claims for CVE-2026-123633 describe a crash or a denial of service, with code execution only as a possibility. One repository describes the CVE-2026-123633 mechanism in a way that conflicts with nginx's own fix commit, and one mislabels a different nginx CVE, so treat all six of the claims we first reviewed as unreliable. One claims, about four hours after disclosure, to reproduce code execution on a stock container image, and another describes a non-destructive check mode next to an exploit mode. Our reading: a non-destructive check mode makes mass scanning easier to build. The count was still rising (17 at 04:28 UTC, 18 at 04:45 UTC), and a Telegram post flagged as a proof of concept for both CVEs is unverified.

Running unknown proof-of-concept code is a common way to get compromised, so do not test your servers with it, and that includes the defensive tools. If anyone on your team ran one against a real server or a laptop, treat that machine as suspect. We have no hashes, addresses or request signatures for these CVEs, so there is nothing to put on a blocklist.

**When to bring in outside help:**

- A shell, download tool or interpreter started by the worker user, and you cannot explain it from your baseline
- Crashes followed by a new file in a web root or an outbound connection from the nginx host, on a server that was not patched at the time
- Secrets from a suspect server were used from addresses you do not recognise
- You hold a memory image or core dumps and nobody on the team can read them
- The workers on a suspect server ran as root, or you suspect the host or the container boundary was crossed
- A controller or gateway pod that ran an affected build with HTTP/2 on shows any signal above, because what it can read in the cluster sets the damage (our reading)
- A server was already restarted or rebuilt and its logs rotated, and it handled customer or regulated data. The question then changes from "was it exploited" to "what could the worker user read", and the notification duties in COMPLIANCE & LEGAL REQUIREMENTS apply

Do not wipe or rebuild a suspect server before you have preserved it.

---

## BUSINESS IMPACT ANALYSIS

### Financial impact scenarios

The scenarios stay qualitative. No source for these two bugs gives cost figures, so none are given here.

#### Scenario 1: Prevention (patch this week)

**Costs:**

- Staff time: finding every nginx instance (distro packages, container images, Kubernetes ingress controllers, API gateways, appliances), checking which ones have the HTTP/2 module compiled in and HTTP/2 switched on, then an upgrade and a restart for each
- Testing: a regression pass per critical site after the restart, covering TLS, proxying, logins and monitoring
- Restarts: a reload doesn't replace the running program, so every server needs a restart (or a supported live binary upgrade) after the upgrade, and a restart drops the connections in progress
- Version traps: distro packages backport fixes without changing the nginx version, products that embed nginx carry their own numbers (OpenResty 1.31.8.1 is based on nginx 1.31.8), NGINX Plus 37.3.0.1 is based on open source 1.31.8 yet carries the fix for CVE-2026-123007, and Docker tags move, so each platform needs its own check against its own advisory
- No fixed package yet on several platforms: at the cut-off Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux had none, so those servers need the HTTP/2 stopgap, or a build from the nginx.org repository, until their distro ships one
- Products with no fix to install (see Scenario 5)
- Downtime: none if you restart one node at a time behind a load balancer, a short maintenance window for a single server

**Benefits:**

- No breach costs, no notifications, no letters from regulators
- An accurate nginx inventory that records which servers speak HTTP/2 and which protocol each CDN or proxy in front of them speaks to the origin. You'll want it for the next advisory
- Eight other fixes arrive with the same release, including bugs outside HTTP/2 (HTTP/3, resolver, mail proxy), so the upgrade pays off even on servers where HTTP/2 is off

*Sources: nginx.org security advisories and CHANGES, F5 CVE records and advisories K000163926 and K000163928 (WEAK, read through a browser render), Debian, Ubuntu, Red Hat, Amazon Linux and Alpine trackers, Docker Hub image tags, OpenResty issue tracker, Xint*

---

#### Scenario 2: Compromise of an exposed internet-facing server

**How it plays out:** an attacker with no credentials sends HTTP/2 traffic to a server that has HTTP/2 switched on and, if the conditions line up, runs commands as the nginx worker user (nginx, www-data or nobody, depending on the package or build). For CVE-2026-123007, F5 says an attacker could "crash the NGINX worker process, corrupt its memory, or potentially execute code remotely" (for CVE-2026-123633 it says a denial of service or possibly code execution), and in both records it adds that attackers can execute code on systems with ASLR disabled or when the attacker can bypass ASLR. That user is not root: the main process runs as root, but the workers drop to the configured user (inferred from the shipped config files and the nginx source). Xint says it reached root only by chaining a separate Linux kernel flaw, a claim we could not verify. Even as the worker user an attacker can do damage, and Rapid7 says the memory corruption can "disclose data". Our reading, from how nginx works: a worker that proxies traffic handles the requests and responses of every site behind that server, so an attacker running code as that user can see what passes through it, change what the server returns and use the server as a foothold to reach the backends behind it. This is a plausible chain, not an observed one: no exploitation in the wild had been reported by about 04:30 UTC on 19 November 2026, 13.5 hours after disclosure. Xint, Wiz, Rapid7 and Metnir each report code execution in lab settings (Xint, Rapid7 and Metnir say as the worker user, and Wiz names no account), and of those four teams only Rapid7 has released exploit code, for CVE-2026-123007 only, although unverified third party code has appeared since. Sources differ on how reliable exploitation is: Rapid7's notes limit its code to a freshly started local container, while Xint says its unreleased exploit works under concurrent normal traffic.

**Costs:**

- Forensics and incident response, legal counsel, breach notification
- Downtime while you rebuild the server from a clean image and rotate every secret the worker could read or that passed through it
- Regulatory exposure if personal data was involved
- Reputational damage if the site was defaced or what it serves was changed
- Higher cyber insurance premiums at renewal

*Sources: F5 CVE records, Rapid7, Xint, Wiz and Metnir write-ups, CIRCL technical report TR-105, nginx source and package files (our reading)*

---

#### Scenario 3: Quiet compromise with no crash and no log entry you recognise

**What's different:** no indicators of compromise have been published for these bugs, and no source says what a successful attack looks like in nginx's own logs (Xint calls a program started by an nginx worker the clearest sign of one). Xint says an attack using CVE-2026-123007 "may leave little evidence in nginx access logs". CIRCL says HTTP/2 control frames don't normally show up as individual nginx access-log requests, so "a lack of suspicious access-log lines is therefore not sufficient to exclude exploitation". F5 says the CVE-2026-123007 overflow is "typically followed by an NGINX worker segmentation fault", and Xint says a failed attempt can crash a worker, but no source says whether a successful attack leaves a crash line. Our reading is that a compromise could look like ordinary traffic until a stolen credential turns up somewhere else, or an unexpected process or outbound connection appears on the server.

**Costs:**

- Rotating every secret a suspect server held or that passed through it (backend and upstream credentials, API keys, signing and session secrets, cloud and third party tokens, and, our reading, the certificate keys on servers that terminate TLS) and forcing users to log in again
- Investigating every system those secrets open (backends, databases, payment APIs, cloud accounts, email)
- Notification if personal data passed through or was reachable from the server at the time. One server often fronts many sites (our reading), so that can include other people's data
- Evidence against speed: restarting the server to patch it ends the running processes and their state, and drops every connection. On a server you suspect, capture the process list, network connections and logs first and patch second, which delays the fix
- Time: leaked credentials can sit unused for a long time

*Sources: Xint and CIRCL write-ups, F5 CVE records, our reasoning from how nginx runs*

---

#### Scenario 4: Outages from worker crashes

**What's different:** the attacker doesn't need code execution to cost you something. F5 says the CVE-2026-123007 overflow is "typically followed by an NGINX worker segmentation fault", and says CVE-2026-123633 may allow "a denial-of-service (DoS) on the NGINX system". The error log shows a crash as "worker process ... exited on signal 11". Our reading is that repeated attempts could mean repeated crashes and a site that keeps dropping connections even where no code ever runs. No source reports an attack of that kind. A crash alone doesn't tell you which bug caused it: the same release fixes eight other bugs, among them three use-after-free flaws, a NULL pointer dereference and a buffer overflow, and the worker_connections warnings that go with CVE-2026-123633 also appear on busy servers that are simply short of connections.

**Costs:**

- Lost availability for every site behind the server, and the support load that comes with it
- On-call time spent on crashes that look like application or platform faults
- Capacity risk during the stopgap: turning HTTP/2 off means HTTP/1.1 clients may open more connections, so check that the workers have enough capacity after the change (Metnir)
- Investigation effort to tell crash noise from an attack. CERT-EU calls worker-crash lines "not a high-fidelity indicator of successful remote code execution but rather an indication of exploitation attempts". A worker crash on an exposed server with HTTP/2 on needs an explanation (see the EMERGENCY row in the DECISION MATRIX)

*Sources: F5 CVE records, nginx.org security advisories, Xint, Metnir, CERT-EU*

---

#### Scenario 5: Kubernetes ingress, API gateways and other products with no fix to install

**What's different:** a normal package update can't fix these today. Community ingress-nginx is retired and archived (24 March 2026), and its README says "there will be no further releases, no bugfixes, and no updates to resolve any security vulnerabilities", so no fixed controller is expected. It also switches HTTP/2 on by default (ConfigMap key use-http2, default "true"). Kong and Apache APISIX switch it on by default too (inferred from their default files). At the cut-off no fix had shipped for Kong OSS (newest 3.9.4, 12 October 2026), OpenResty (newest v1.31.8.1, 26 October 2026, built on nginx 1.31.8), Tengine, Angie or freenginx, and this analysis has no patch status for APISIX. Metnir says it reproduced the CVE-2026-123633 use-after-free in OpenResty and crashed the shipped binaries of Kong, Apache APISIX, NGINX Gateway Fabric and community ingress-nginx. Wiz says widespread attacks "initially start against packaged products where many customers use the exact same build and configuration". F5's own NGINX Ingress Controller is a different project and defaults HTTP/2 off, and its v5.8.0 and NGINX Gateway Fabric v2.9.0 carry fixed builds. This analysis can't tell you when the others will ship, so the wait has no known end date.

**Costs:**

- Exposure for as long as the vendor takes, with the fix out of your hands, and for good on community ingress-nginx
- Compensating controls in the meantime: switch HTTP/2 off through each product's own setting where you can (the settings are in the technical questions below), which breaks anything that needs HTTP/2 end to end, and restrict network paths to the controller or gateway
- Chasing vendors for a written answer on whether the product is affected and when a fix ships
- A migration project off community ingress-nginx to a maintained controller, and replacement or isolation if a vendor won't ship a fix
- CIRCL also advises limiting outbound connectivity, least-privilege accounts, isolating backends and reviewing the vendor images of ingress controllers

*Sources: Kubernetes retirement notice and ingress-nginx README, ingress-nginx, Kong and APISIX default files (our reading), F5 documentation and release notes, Metnir, Wiz, OpenResty issue tracker, release feeds of the nginx-based projects, CIRCL*

---

### Operational impact timeline

**Hour 0-24: Inventory and patching**

- Platform and ops teams pulled off roadmap work
- A list of every host, container image, Kubernetes ingress controller, API gateway and appliance that runs nginx or a product built on it: version, whether the HTTP/2 module is compiled in, whether HTTP/2 is switched on for any listener, whether the server proxies to a backend, whether it is internet facing, and which protocol any CDN or proxy in front of it speaks to the origin
- Fixed versions installed and servers restarted, internet-facing servers with HTTP/2 on first (nginx 1.31.9 or 1.30.7, NGINX Plus 37.3.0.1 or 37.0.8.1, or your distro's fixed package once it ships)
- A stopgap for servers that must wait for a restart window, a distro fix or a vendor fix: HTTP/2 off
- Decisions on community ingress-nginx, Kong, APISIX and any other product with no fix

**Day 2-7: Verification**

- Confirm on every server that the main nginx process started after the update. An installed fixed package proves nothing on its own
- Log review for worker crashes, programs started by the worker user, unexpected outbound connections and long HTTP/2 connections with heavy inbound traffic, over the window set out under DETECTION & FORENSICS and further back where your retention allows
- Chasing distros, hosting providers and product vendors for written answers, and for the fixes still unconfirmed on 19 November (Debian stable and testing, Ubuntu, Red Hat, SUSE, Rocky Linux, AlmaLinux 8, Kong, APISIX, OpenResty, the nginxinc/nginx-unprivileged image, F5's 2026-lts-r11 Ingress Controller tag, Fedora, cPanel, Plesk)
- Putting HTTP/2 back on where you turned it off and want it, once the patch is confirmed

**Week 2-4: Hardening**

- Move off community ingress-nginx and off branches with no fix (anything older than the 1.30 stable branch, and NGINX Plus R33 to R36, which need a fixed 37.x release)
- Origin lock-down behind any proxy or CDN, and a review of which protocol each proxy speaks to your origin (Cloudflare's HTTP/2 to Origin is on by default for Free, Pro and Business plans)
- New detection rules (worker crashes, programs started by the worker user, outbound connections from nginx) and longer log retention
- Least privilege, outbound limits and backend isolation (CIRCL's advice), and a review of the vendor images of ingress controllers
- A routine update cadence for nginx and the images you build from it: the November release fixed ten advisories at once

**Month 2-6: Only if you found a compromise**

- Regulator questions, customer communications, possible claims
- Audit follow-ups and insurer reviews

*Sources: nginx.org security advisories, Debian, Ubuntu, Red Hat, Rocky Linux, Amazon Linux and Alpine trackers, F5, Kubernetes and Cloudflare documentation, CIRCL technical report TR-105*

---

### Cost-benefit analysis

| Option | Effort | What's left exposed | Verdict |
| --- | --- | --- | --- |
| Patch and restart now | A package or image upgrade and a restart per server (one node at a time behind a load balancer). Possible only where a fixed build exists: the nginx.org repository, the Docker official image, Amazon Linux, AlmaLinux 9 and 10, Alpine edge, 3.24, 3.23 and 3.22, Debian sid, Arch, Homebrew, FreeBSD ports, Gentoo (in the tree), NGINX Plus 37.x | Nothing known for these two CVEs once the running process is the fixed version | Do this |
| HTTP/2 off until you can patch | Take http2 out of every server block that shares the listener, including any legacy listen parameter, test the config, reload, then restart to drop the old workers | Nothing for these two bugs. The other eight fixes in the release stay open. Anything that needs HTTP/2 end to end, such as native gRPC, breaks | A bridge for days, not weeks. Not an F5 or nginx.org workaround: F5's records say "None" |
| Put exposed servers behind a CDN or proxy | An architecture change per site, plus an origin lock so the server can't be reached around the proxy | Whatever reaches the origin around the proxy. Cloudflare's HTTP/2 to Origin is on by default for Free, Pro and Business plans, for origins that announce HTTP/2, so it doesn't keep HTTP/2 away from them. ALB and CloudFront speak HTTP/1.1 to origins by default. Whether either bug can be triggered through a proxy that speaks HTTP/2 to the origin is unknown | A layer, not a fix |
| Move off community ingress-nginx | A migration project | Nothing once moved. Until then everything, because the project is retired and no fix is coming | Required. Internet-facing clusters first |
| Kong, APISIX, OpenResty or another product waiting on its vendor | A written query to the vendor, plus HTTP/2 off through the product's own setting and network placement | Everything until the vendor ships a fix | Compensating controls now, the vendor's fix when it ships |
| Wait | None today | Everything | Not acceptable on an internet-facing server with HTTP/2 on. Both fixes have been public since 18 November 2026, CIRCL's feed first saw a public proof of concept for CVE-2026-123007 at 17:04 UTC that day, NCSC-NL expects large-scale exploitation once proof-of-concept code is out, and more public exploit code, none of it verified, has appeared since |

*Sources: nginx.org security advisories, F5 CVE records, Cloudflare, AWS and Akamai documentation, Rapid7, NCSC-NL, CIRCL*

---

## COMPLIANCE & LEGAL REQUIREMENTS

### Regulatory notification obligations

If you find signs of compromise, these timelines may start running. A clean upgrade triggers none of them, and a worker crash on its own is not a personal data breach. Whether personal data was reached is a legal judgment that depends on what the worker user could read and what passed through the server, and an attacker who runs code as that user can read whatever the worker can. This is a summary, not legal advice.

#### GDPR (EU) and UK GDPR

- **Timeline:** 72 hours to notify the supervisory authority after becoming aware of a personal data breach, unless it's unlikely to put people at risk
- **Individuals:** without undue delay if the risk to them is high
- **Fines:** up to EUR 20 million or 4% of worldwide annual turnover (UK: GBP 17.5 million or 4%)
- *Source: GDPR Articles 33, 34 and 83*

#### NIS2 (EU essential and important entities)

- **Early warning:** within 24 hours of becoming aware of a significant incident
- **Incident notification:** within 72 hours
- **Final report:** within one month
- *Source: Directive (EU) 2022/2555, Article 23*

#### India: CERT-In and DPDP

- **CERT-In:** report covered cyber incidents, including unauthorised access and compromise of systems, within 6 hours of noticing them
- **DPDP Act 2023:** breach-reporting duties phase in under the DPDP Rules 2025, so check whether they apply to you yet
- *Source: CERT-In Directions under Section 70B(6) of the IT Act, 28 April 2022*

#### SEC (US-listed companies)

- **Timeline:** Form 8-K Item 1.05 within four business days of determining that a cybersecurity incident is material
- *Source: SEC cybersecurity disclosure rules (2023)*

#### HIPAA (US healthcare data)

- **Timeline:** notify affected individuals without unreasonable delay, and no later than 60 days after discovery. HHS too, and the media if more than 500 residents of a state or jurisdiction are affected
- *Source: 45 CFR 164.400-414*

#### US state breach laws

- All 50 states have breach notification laws. Timelines and triggers vary by state

---

### Documentation requirements checklist

**Create and maintain:**

- [ ] **Incident timeline** with precise timestamps
    - When the issue became public (18 November 2026: disclosure at 15:00 UTC, nginx 1.31.9 and 1.30.7 and the CVE records the same day, a public proof of concept for CVE-2026-123007 first seen by CIRCL at 17:04 UTC)
    - When your organization learned about it
    - When inventory, patching, restarts and verification finished
- [ ] **Technical details:**
    - Inventory of nginx instances, with version, distro package version (for NGINX Plus, the Plus package version), whether the HTTP/2 module is compiled in, where HTTP/2 is switched on, whether the server proxies to a backend and the exposure path
    - Versions before and after patching, with restart times
    - Any evidence of compromise
    - Stopgaps applied and removed (HTTP/2 off, product settings, proxy settings)
- [ ] **Business impact assessment:**
    - Systems and data at risk
    - Customer impact
- [ ] **Decision log:**
    - Who authorized what, and why
    - Risk decisions on servers that waited for a distro or vendor fix, on community ingress-nginx, and on anything left on HTTP/2 for a while
    - The reasoning behind any "no compromise" conclusion. No indicators of compromise have been published, and Xint says an attack may leave little evidence in nginx access logs, so "we found nothing" is weaker evidence here than it would be for a bug with a known fingerprint
- [ ] **Communications log:**
    - Who was told what, and when

**Retention:** follow your industry's record-keeping rules. Seven years is a common default.

---

### Insurance considerations

- [ ] Check that your cyber policy is active and what it covers (investigation, business interruption, liability, notification costs)
- [ ] Check the notification deadline in the policy. Many require notice within 24 to 72 hours of a suspected incident
- [ ] Check whether you must use the insurer's panel of response firms
- [ ] Keep evidence of your patching speed: dates, versions and restart times. Insurers look hard at known, unpatched vulnerabilities

**Call your broker straight away if:**

- You find indicators of compromise
- You're taking systems offline or running on stopgaps for more than a few days
- You're unsure what your policy covers

---

## DECISION MATRIX

### What should we do right now?

| Your situation | Immediate action | Priority | Timeline |
| --- | --- | --- | --- |
| Running nginx 1.31.9 or later, 1.30.7 or later, NGINX Plus 37.3.0.1 or 37.0.8.1, or your distro's fixed package (checked against its advisory), and the main process has been restarted | Document it, keep monitoring | LOW | This week |
| Fixed package installed, main process not restarted (a reload doesn't replace the program) | Restart now (one node at a time) | HIGH | Today |
| Affected version (1.9.5 to 1.31.8), HTTP/2 on, internet facing | Upgrade to 1.31.9 or 1.30.7 where a fixed build exists, then restart. If that has to wait, take HTTP/2 off until you can patch | CRITICAL | Today |
| Affected version, HTTP/2 on, reachable only from trusted internal networks | Patch and restart | HIGH | 48 hours |
| Affected version, HTTP/2 off (module not compiled in, or no http2 setting anywhere) | Not exposed to these two bugs. Take 1.31.9 or 1.30.7 in the normal window: the release fixes eight other bugs, and turning HTTP/2 off doesn't cover them | LOW | Normal window |
| HTTP/2 on, static files only, no proxying | CVE-2026-123633 needs proxying, so it is outside that bug (our reading of F5's wording). CVE-2026-123007 needs only HTTP/2 on, and Wiz says its test showed code execution on nginx serving ordinary static files. Treat the server as exposed to CVE-2026-123007 | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| HTTP/2 on, proxying to a backend | Both bugs apply from 1.19.7 on (CVE-2026-123633 also needs a worker running low on worker_connections). Patch as in the rows above | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| Branch with no fix (any release before 1.30, or NGINX Plus R33 to R36) with HTTP/2 on | No fixed release exists on your branch (inferred). Move to 1.30.7, 1.31.9 or a fixed NGINX Plus 37.x release, and take HTTP/2 off meanwhile | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| Behind Cloudflare with HTTP/2 to Origin on (the default on Free, Pro and Business plans, for origins that announce HTTP/2) | Don't count on the CDN: no source says it blocks either bug, and Wiz says terminating CDNs and WAFs "may mitigate parts of the exploit" and adds "This depends on implementation". Patch the origin. Where you can't yet, turn off HTTP/2 to Origin for the zone, turn HTTP/2 off at the origin, and lock the origin so it can't be reached around the proxy | HIGH, CRITICAL if the origin is reachable directly with HTTP/2 on | 48 hours, or today |
| Behind AWS ALB or CloudFront (HTTP/1.1 to the origin by default) or Akamai (non-HTTP/2 to the origin by default) | Check that nobody changed the ALB target group to HTTP/2 or gRPC, or switched on Akamai's HTTP/2 Edge to Origin option. An origin that can also be reached directly keeps its own exposure | LOW, HIGH if the origin is reachable directly with HTTP/2 on | Normal window, or 48 hours |
| Community ingress-nginx (retired, HTTP/2 on by default) | No fix and none is coming. Set the ConfigMap key use-http2 to "false" now, restrict network paths to the controller and plan the move to a maintained controller | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| Kong or Apache APISIX | Both switch HTTP/2 on by default, and no fixed Kong OSS release had shipped (newest 3.9.4, 12 October 2026). This analysis has no APISIX patch status. Take http2 out of the Kong listen strings, set enable_http2 to false in APISIX (inferred, check APISIX's own docs), and ask the vendor in writing | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| F5 NGINX Ingress Controller or NGINX Gateway Fabric | Use the fixed builds (Ingress Controller v5.8.0, Gateway Fabric v2.9.0 open source image) and recreate the pods. The 2026-lts-r11 Ingress Controller tag is inside the affected range. HTTP/2 is off by default in the Ingress Controller | HIGH if HTTP/2 is on, CRITICAL if internet facing | 48 hours, or today |
| OpenResty, Tengine, Angie or freenginx with HTTP/2 on | No fix shipped. OpenResty 1.31.8.1 is built on nginx 1.31.8. Whether Tengine, Angie and freenginx are affected is not established. Turn HTTP/2 off at the listen directives until the project says more | HIGH, CRITICAL if internet facing | 48 hours, or today |
| Debian stable or testing, Ubuntu, Red Hat Enterprise Linux, SUSE or Rocky Linux packages, or Alpine 3.21 and older | No fixed package at the cut-off. Take HTTP/2 off until your distro's advisory names a fixed build, or install a fixed build from the nginx.org repository, or move to a container on a fixed tag. Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid now have fixed packages: install them and restart. Check the tracker again before you act | CRITICAL if internet facing with HTTP/2 on, otherwise HIGH | Today, or 48 hours |
| Don't know which servers run nginx or have HTTP/2 on | Run the inventory commands | CRITICAL | 2 hours |
| nginx older than 1.9.5 | Not affected by these two bugs (no HTTP/2 module). Other fixes in the release reach back much further (the mail proxy bug's range starts at 0.5.33), so plan the upgrade | LOW | Normal window |
| On an exposed server with HTTP/2 on: worker crashes you can't explain ("worker process ... exited on signal 11"), core dumps, shells, download tools or interpreters started by the worker user, or unexpected outbound connections | Start incident response. Capture the process list, network connections and logs before any restart | EMERGENCY | Immediately |

*Sources: nginx.org security advisories, F5 CVE records, Debian, Ubuntu, Red Hat, Rocky Linux, Amazon Linux and Alpine trackers, Cloudflare, AWS and Akamai documentation, Wiz, Xint, CIRCL, Kubernetes retirement notice, Kong and APISIX default files (our reading)*

---

### Risk decision framework

**For each nginx instance, container image, ingress controller, gateway and appliance:**

```
Step 1: Exposure path (take the first line that matches)
- HTTP/2 module compiled in and HTTP/2 on for a listener that
  the internet can reach                                      HIGH
- Same setup, reachable only from trusted internal networks   MEDIUM
- Behind a proxy that speaks HTTP/2 to the origin (Cloudflare's
  HTTP/2 to Origin is on by default on Free, Pro and Business):
  whether either bug passes through is unknown. Origin
  reachable around the proxy                                  HIGH
- Behind a proxy that speaks HTTP/1.1 to the origin (the ALB
  and CloudFront default), origin locked to the proxy         LOWER
- HTTP/2 module not compiled in, or HTTP/2 off on every
  listener                                                    LOWER

Step 2: Version and fix status
- 1.9.5 to 1.31.8 upstream (CVE-2026-123007), 1.19.7 to 1.31.8
  (CVE-2026-123633), HTTP/2 on                                HIGH, patch today
- Distro package: judge by the distro advisory, not by the
  nginx number                                                HIGH until its fix runs
- Branch with no fix (before 1.30, NGINX Plus R33 to
  R36)                                                        HIGH, move to a fixed release
- Fixed package installed, main process not restarted         HIGH, restart today
- 1.31.9 or 1.30.7, NGINX Plus 37.3.0.1 or 37.0.8.1,
  restarted                                                   LOWER

Step 3: Data and blast radius
- Personal, payment or health data, or secrets for other
  systems that pass through the server or that the worker
  user can read                                               HIGH
- Public content only, no secrets, restricted network paths   LOWER

Step 4: Action
Internet facing + any other HIGH       Patch and restart today (HTTP/2 off until then)
Internal + any other HIGH              Patch within 48 hours
Everything else                        Patch in the normal window
```

Three situations are easy to miss. A leftover `listen ... http2` parameter keeps HTTP/2 on even with `http2 off;` (inferred from the source, and matching Xint's advice to remove any legacy parameter and check every server block that shares the listening address and port). No source says whether either bug is reachable over cleartext HTTP/2 (h2c), so our reading is that a `listen 80 http2;` listener belongs in the same tier until a source says otherwise. And Kong, APISIX and community ingress-nginx switch HTTP/2 on for you, so a config you never wrote by hand can still have it on.

*Sources: nginx.org security advisories, F5 CVE records, Xint, nginx source and documentation, Cloudflare and AWS documentation, ingress-nginx, Kong and APISIX default files (our reading)*

---

### Go/no-go decision checklist

**Before you approve emergency patching:**

- [ ] Backup or snapshot taken (a copy of the nginx configuration directory, and for cloud hosts an image of the current state, with the previous package version still available so you can go back)
- [ ] Rollback plan written down. A rollback puts the vulnerable version back, so give it a time limit and keep HTTP/2 off while it lasts
- [ ] Stakeholders told about the maintenance window and the restart (a restart drops the connections in progress)
- [ ] Short test plan agreed (`nginx -t` passes, sites load over HTTP/1.1 and HTTP/2, TLS, proxying and logins work, health checks and monitoring tools stay quiet)
- [ ] Someone on call during and after the change
- [ ] Restart method confirmed (one node at a time behind the load balancer, a rebuilt image for containers, recreated pods for Kubernetes, or the live binary upgrade from nginx.org's control page)
- [ ] Right fix confirmed for each platform: the package that your distro's advisory names, or a fixed nginx.org, Docker or NGINX Plus build, not an nginx version string
- [ ] Capacity checked if you are turning HTTP/2 off: HTTP/1.1 clients may open more connections (Metnir)
- [ ] Servers you suspect: process list, network connections and logs captured before the restart

**If you can't tick every box:**

- Switch HTTP/2 off on the exposed servers and keep it off until you can patch (see the QUICK REFERENCE CARD)
- Restrict access to trusted networks where you can
- Take the exposed service offline for now if neither of those is possible

---

## FREQUENTLY ASKED QUESTIONS

### Questions from executives

**Q: How do we know if we're affected?**

**A:** Ask IT four questions. Which servers run nginx or a product built on it (ingress controllers, API gateways, appliances, container images), and which version is each running right now (check the running process as well as the installed package)? Is the HTTP/2 module compiled in, and is HTTP/2 switched on for any listener? Does the server proxy requests to a backend, which decides whether CVE-2026-123633 applies as well? Can an outsider reach it over the network, directly or through a CDN that speaks HTTP/2 to it? nginx.org lists 1.9.5 to 1.31.8 as vulnerable to CVE-2026-123007 and 1.19.7 to 1.31.8 as vulnerable to CVE-2026-123633. A build with no HTTP/2 module has no HTTP/2 code, and a server with HTTP/2 off isn't exposed to these two bugs. Distro packages backport fixes without changing the nginx version, so IT has to check them against the distro advisory, and at the cut-off several major distros had no fixed package. If a hosting company or platform runs your servers, ask in writing. The inventory commands are under AM I AFFECTED? SELF-ASSESSMENT.

*Sources: nginx.org security advisories, F5 CVE records, Xint, distro trackers*

---

**Q: We don't use HTTP/2, so are we safe?**

**A:** Probably, for these two bugs, but check before you say so. The `http2` directive defaults to off, and the nginx source tree, the nginx.org packages, the Docker official image, Debian, Ubuntu, RHEL (CentOS Stream files) and Alpine all ship a plain `listen 80;` server (inferred from the shipped files). A source build doesn't even compile the HTTP/2 module unless asked. The catch is that "we don't use it" is often a guess. HTTP/2 needs an admin edit or a product default: community ingress-nginx, Kong and Apache APISIX switch it on by default. A leftover `listen ... http2` parameter also keeps HTTP/2 on even when another line says `http2 off;` (inferred from the source). A server with HTTP/2 off is still worth moving to 1.31.9 or 1.30.7 in the normal window, because the release fixes eight other bugs, some of them outside HTTP/2.

*Sources: nginx documentation and source files, nginx.org security advisories, ingress-nginx, Kong and APISIX default files, Debian, Ubuntu, CentOS Stream and Alpine package files (our reading)*

---

**Q: What's the worst that could happen?**

**A:** Someone on the internet, with no login and no help from a user, sends crafted HTTP/2 traffic to a server that has HTTP/2 on. Our reading is that a crashed worker is the usual outcome of a failed attempt, and code execution is the harder outcome. The worst case is code execution as the worker user. F5 says attackers can execute code "on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR", and Rapid7 says the memory corruption can "disclose data, interrupt service, and execute code with the nginx worker process's permissions". From there, our reading is that an attacker can see what the worker sees, including traffic passing through it, change what the server returns and use the server as a step toward the systems behind it. It doesn't give root by itself (see the root question below): Xint says it reached root only by chaining a separate Linux kernel flaw. Whether a reliable attack is practical is in dispute, and the next question covers it.

*Sources: F5 CVE records, Rapid7, Xint, CIRCL technical report TR-105, our reading*

---

**Q: Is anyone exploiting this?**

**A:** Not that anyone has reported. As of about 04:30 UTC on 19 November 2026 (disclosure was at 15:00 UTC on 18 November), F5 told The Register it has "found no evidence of active exploitation of any of these vulnerabilities in the wild", Tenable's FAQ says there are "no reports of threat actors exploiting these CVEs as of November 18", and The Hacker News says "Neither the vendor nor the Wiz and Rapid7 researchers have reported any attacks exploiting the flaw so far". CERT-EU says "no exploitation in the wild has been reported yet". CISA's SSVC entries say Exploitation none and Automatable no, and CISA hasn't added either CVE to its exploited list (catalog 2026.11.18, released 19:17 UTC, checked at 19:59 and 20:10 UTC on 18 November and at 04:27, 04:45 and 04:48 UTC on 19 November). EPSS has no score for either CVE yet. CIRCL's sightings feed counted, at the 18 November check (not re-run), 68 sightings for CVE-2026-123007 (66 "seen", 2 "published-proof-of-concept", 0 "exploited") and 47 for CVE-2026-123633 (46 "seen", 1 "published-proof-of-concept", 0 "exploited"). Previdian (WEAK, on its page for these bugs) says its sensors have not observed exploitation attempts against either. Our reading: moderate confidence, because no primary telemetry was reachable (GreyNoise and Shadowserver: COULD NOT VERIFY).

Whether working exploit code is public is more nuanced. Proof-of-concept material for CVE-2026-123007 is public: Rapid7 published a proof of concept, Censys Research published proof-of-concept material, HKCERT says one is public, and unverified third party repositories claim exploit code, one with a full code execution chain. Its own notes say it is only suitable to demonstrate its approach against a local freshly started Docker container, and will likely fail against a server with several concurrent clients, a worker that has been running for some time or a network proxy in the path. Xint says the opposite about its own unreleased exploit, which it says "works under concurrent normal traffic and across servers with different hardware specifications". Sources differ on how reliable exploitation is. No proof of concept from Wiz, Xint or Metnir is public for CVE-2026-123633, because they withhold their exploits, although Censys Research's repository says it holds lab reproductions of the five nginx bugs in Xint's set. As of 04:45 UTC on 19 November, a GitHub search for either CVE ID in quotes returns 18 repositories, and none of the third party code is verified (see the question on running public code below). NCSC-NL (16:07 UTC, before the first proof-of-concept sighting) says it expects proof-of-concept code soon, after which it expects large-scale exploitation. That picture can change quickly, so check again before you rely on it. The sources are set out under ATTACK TIMELINE.

*Sources: The Hacker News, CERT-EU, CISA SSVC entries and KEV catalog, FIRST EPSS API, CIRCL sightings feed, Previdian (WEAK), Rapid7, Xint, Wiz, Metnir, NCSC-NL, GitHub repository search for the CVE IDs (names withheld)*

---

**Q: The ratings disagree: 8.1 or 9.2, and nginx.org says major and medium. Which is it?**

**A:** All of them are on the record, and they come from different scales. F5, the CNA for both records, gives both bugs the same two scores: CVSS 3.1 8.1 (High) and CVSS 4.0 9.2 (Critical). Our reading: that is one set of ratings (attack complexity High, no privileges, no user action, full impact) scored under two CVSS versions, not two assessors disagreeing. nginx.org uses its own scale (none, minor, medium, major, with no "critical") and rates CVE-2026-123007 major and CVE-2026-123633 only medium. CISA's assessment says Exploitation none and Automatable no. NVD shows both records as "Received", with no score of its own, and displays F5's scores. Ubuntu says priority High, Amazon Linux says Important, NCSC-NL rates its advisory H/H and CERT-EU titles its advisory "Critical vulnerabilities in Nginx". Our position: critical for internet-facing nginx on an affected version with HTTP/2 on, including servers behind a CDN that speaks HTTP/2 to the origin and products that turn HTTP/2 on by default. High for internal servers with HTTP/2 on. Servers with HTTP/2 off aren't exposed to these two bugs but should still upgrade. That tier rests on exposure of the HTTP/2 code to untrusted input, not on proven exploitability: F5 scores attack complexity High, nginx.org is calmer, CISA sees no exploitation and the public demonstration has narrow conditions. Patch first, argue about the label later. RISK DASHBOARD lists every rating, and the technical questions below explain the scores.

*Sources: F5 CVE records, nginx.org security advisories, CISA SSVC entries, NVD, Ubuntu, Amazon Linux, NCSC-NL, CERT-EU*

---

**Q: Was the fix public before disclosure, and could we have been hit earlier?**

**A:** We found no sign of it. The commit dates say 11 November 2026, but GitHub's activity log shows no push to nginx master between 9 November (13:29 UTC) and 18 November (15:20 UTC), so the fixes reached GitHub on 18 November, after the 15:00 UTC disclosure (our reading). Two Hacker News comments say the fix was public a week earlier, and the push log doesn't support that. Whether the 11 November tarballs on nginx.org were downloadable before 18 November is not established. NGINX Plus customers had the CVE-2026-123633 fix from 14 October per the release notes, before the CVE IDs were reserved on 9 November (our reading: the CVE number was added to the notes later). No source reports exploitation as of about 04:30 UTC on 19 November, but no indicators of compromise have been published, so nothing lets you tell either way. Check the error logs and process history on exposed servers as far back as retention allows (see DETECTION & FORENSICS).

*Sources: GitHub activity log and commits, nginx.org download index, F5 release notes for NGINX Plus, CVE records, Hacker News comments, our reading*

---

**Q: We use a managed host, a hosting platform or a product with nginx inside. Do we need to do anything?**

**A:** Get a written answer from the provider: is the product affected, is HTTP/2 on, which nginx version is running right now, and when will the fix ship? At the cut-off the picture was patchy. Heroku has a changelog entry, effective 18 November 2026, that moves its PHP platform to nginx 1.30.7 and names CVE-2026-123007, CVE-2026-123633 and CVE-2026-118899. We could not verify cPanel or Plesk (COULD NOT VERIFY), and we found no statement on these CVEs from AWS, Azure, Google Cloud, Cloudflare or Vercel. Products with nginx inside have their own version numbers and their own schedules: see the questions on Kong, APISIX and OpenResty and on F5's products below. Until a vendor answers, ask them to turn HTTP/2 off where they can.

*Sources: Heroku Dev Center changelog, cPanel and Plesk documentation (nothing found), cloud vendor pages (no statement found)*

---

**Q: We run Kubernetes with the community ingress-nginx controller, and it is retired. What now?**

**A:** Treat it as unfixable and plan to leave it. The Kubernetes project retired and archived it on 24 March 2026, and its README says "there will be no further releases, no bugfixes, and no updates to resolve any security vulnerabilities", so no fixed controller is expected. It also switches HTTP/2 on by default (inferred from its default files: the ConfigMap key `use-http2` defaults to "true"), and Metnir says it crashed a shipped build with the CVE-2026-123633 bug. A controller that faces the internet therefore sits in the critical tier with no patch coming. What to do: set `use-http2` to "false" now (the setting is in the technical questions below), restrict network paths to the controller and plan the move to a maintained controller. F5's NGINX Ingress Controller is a different project, defaults HTTP/2 off and has a fixed v5.8.0. CIRCL also advises reviewing the vendor images of ingress controllers. To find what runs in a cluster:

```bash
# Kubernetes: find ingress controllers and gateways, and the images they run
kubectl get deployments -A -o wide | grep -i -E 'ingress|kong|apisix|gateway'
kubectl get daemonsets -A -o wide | grep -i -E 'ingress|kong|apisix|gateway'
```

*Sources: Kubernetes retirement notice, ingress-nginx README and ConfigMap documentation, Metnir, F5 documentation, CIRCL*

---

**Q: How long does patching take, and will it break things?**

**A:** For most servers it's a package upgrade, a restart and some checks. The restart is the cost. A reload doesn't replace the running program: Xint says "A configuration reload alone does not replace the running executable." A restart drops the connections in progress, and Xint says it "forcibly disconnects every client". A single server with no load balancer needs a short window. Behind a load balancer, restart one node at a time and watch the first one. Test that sites load, TLS, proxying and logins work and monitoring stays quiet. Containers need a rebuilt image and a redeploy, and Kubernetes needs recreated pods. Where no fixed package exists yet, the quick step is turning HTTP/2 off, which has its own cost (next question). Patch internet-facing servers with HTTP/2 on first, then roll out.

*Sources: Xint, nginx documentation, F5 and Docker image tags*

---

**Q: Will turning HTTP/2 off break our site?**

**A:** For most sites, no. Clients that support HTTP/1.1 carry on. The cost is any service that needs HTTP/2 end to end, such as native gRPC, which breaks (Xint, Metnir and CIRCL all say so). Metnir adds that HTTP/1.1 clients may open more connections, so check that the workers have enough capacity after the change. The catch is "every": a leftover `listen ... http2` parameter keeps HTTP/2 on (inferred), and several server blocks can share one listening address and port, so find them all and test the config before you reload (the commands are in the QUICK REFERENCE CARD and in the technical questions below). A reload applies to new connections only, so connections that are already open can stay on the old workers until you restart. It's a bridge, not a fix. It is advice from Wiz, Xint, CIRCL, CERT-FR and Metnir, not an F5 or nginx.org workaround: F5's records say "None".

*Sources: Xint, Metnir, CIRCL, Wiz, CERT-FR, F5 CVE records*

---

**Q: Should we tell our customers?**

**A:**

- If you patch and find no sign of compromise, this is routine maintenance, and usually no notification is needed.
- If you find indicators of compromise, talk to legal straight away. GDPR, NIS2, CERT-In, HIPAA, SEC and US state laws may all apply, some with deadlines measured in hours.

---

**Q: Should we pay for outside help?**

**A:** Yes if you see any sign of compromise, run many internet-facing nginx servers across many teams, work in a regulated industry, or depend on community ingress-nginx, Kong, APISIX or distro packages with no fix. Probably not if you have a handful of servers on platforms that already ship the fix and a team that can patch and restart today.

---

### Questions from technical teams

**Q: How do we check whether HTTP/2 is on, and for which listeners?**

**A:** A server is exposed only when all three hold: it runs an affected version (or an unpatched distro build), the HTTP/2 module is compiled in, and HTTP/2 is switched on for a listener that untrusted clients can reach. CVE-2026-123633 also needs proxying to a backend and a worker running low on worker_connections. So check each half. `nginx -V` shows `--with-http_v2_module` when the module is compiled in (Xint: absent means not affected), and `nginx -T` shows whether the config on disk switches HTTP/2 on, through `http2 on;` per server (1.25.1 and later) or the legacy `listen ... http2` parameter. Either one enables it (inferred from the source), so `http2 off;` doesn't override a leftover listen parameter. On a plain listener the same switch accepts cleartext HTTP/2 (h2c) from clients that send the HTTP/2 preface first (inferred; no HTTP/1.1 Upgrade path found in the source). Defaults differ by platform, and all of these are our reading of shipped files, not vendor statements (nothing was run):

- Source builds: the HTTP/2 module is not built by default ("This module is not built by default, it should be enabled with the --with-http_v2_module configuration parameter"). The stock conf/nginx.conf has `listen 80;` and a commented TLS block with no http2
- nginx.org packages (Debian, RPM and Alpine) and the Docker official image, which installs those packages: the module is compiled in. The packages' default.conf is `listen 80;` only, and the Docker entrypoint scripts have no http2
- Debian and Ubuntu: the module is compiled in (Debian 1.30.6-3 and 1.26.3-3+deb13u10 rules read, bookworm not; Ubuntu launchpad rules, version not read). The default sites are `listen 80 default_server;` with a commented 443 line
- RHEL family (CentOS Stream files, the upstream of RHEL packaging, not RHEL itself): c10s has `listen 80;` with `http2 on;` only in commented lines, and c9s has a commented `listen 443 ssl http2;`
- Alpine: default.conf is `listen 80 default_server;`
- Fedora: COULD NOT VERIFY (bot challenge)

```bash
# Version of the nginx program on disk (prints to the error stream)
nginx -v
# Whether the HTTP/2 module is compiled in. No output means it is not (run as root if nginx is not on your path)
nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
# Whether HTTP/2 is switched on in the config on disk. Reads every included file (run as root)
nginx -T 2>&1 | grep -nE '^[[:space:]]*(listen[[:space:]][^#]*[[:space:]]http2([[:space:]]|;)|http2[[:space:]]+on[[:space:]]*;)'
# Which ports nginx listens on (run as root to see process names)
ss -tlnp | grep nginx
# Which user the worker processes run as. The master is owned by root
ps -eo user,pid,ppid,args | grep '[n]ginx: '
# From outside: which protocol a site negotiates (prints 2 for HTTP/2, 1.1 otherwise)
curl -sI --http2 -o /dev/null -w '%{http_version}\n' https://www.example.com/
# From outside: whether the server offers h2 in the TLS handshake ("ALPN protocol: h2" means yes)
openssl s_client -connect www.example.com:443 -servername www.example.com -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol:|No ALPN negotiated'
```

Notes on the checks. `nginx -t` and `nginx -T` try to open the files named in the config (certificate keys, logs, pid file), which are usually root-only. Xint runs them with sudo (documentation level; we did not run them). `nginx -T` reads the config on disk, so if it changed without a reload, the running config may differ (Xint). The dump can include secrets from included files, so keep the grep (our reading). A hit means a directive exists, not that the port is reachable: follow with the curl and openssl checks. Xint: if a CDN or reverse proxy sits in front of nginx, those two checks reach only the proxy, so also run them against the nginx server directly. `nginx -V` and `nginx -v` need only permission to run the binary.

*Sources: nginx documentation and source files, nginx.org, Debian, Ubuntu, CentOS Stream and Alpine package files (our reading), Xint*

---

**Q: We only serve static files. Are we safe?**

**A:** From CVE-2026-123633, probably. From CVE-2026-123007, no. CVE-2026-123633 needs HTTP/2 for client connections plus proxying to a backend, so a server that only serves static files is outside it (our reading of F5's wording). CVE-2026-123007 needs only HTTP/2 enabled: F5 says "This issue affects NGINX Plus or NGINX Open Source configurations that use HTTP/2" and states no proxy, static-file, server push, HPACK or stream-setting condition. Wiz (secondary, a lab claim that is not in F5's text) says its test of this bug "demonstrated code execution on NGINX serving ordinary static files, without a backend application or third-party modules", over HTTPS on 64-bit systems. So a static-only site with HTTP/2 on stays in the same tier as any other.

*Sources: F5 CVE records, Wiz, Xint*

---

**Q: What does CVE-2026-123633 need, and how would we spot it?**

**A:** Three things together, in F5's words: HTTP/2 for client connections, proxying client requests to a backend, and a worker "running low on worker_connections", where "a specially crafted request can result in use-after-free in the worker process". Xint's table says "HTTP/2 with requests forwarded to an upstream (backend) server". The bug starts at nginx 1.19.7 (16 February 2021), not 1.9.5, because the fix commit's message says that having an HTTP/2 connection with streams registered as reusable "became possible after" an earlier change from 11 February 2021. Metnir says nginx "logs a warning when it drains connections, at most once per second", and that on an HTTP/2 proxy, repeated worker crashes after these warnings, or core dumps, may indicate this bug. Its sample lines (the numbers are examples) are `[warn] ... 512 worker_connections are not enough, reusing connections` and `[alert] ... worker process 12345 exited on signal 11`. The warning also appears on busy servers that are simply short of connections. Metnir says its tests against older releases found related failures back to nginx 1.9.5, but the official range for CVE-2026-123633 is 1.19.7 and later. We go with F5 and nginx.org.

*Sources: F5 CVE records, nginx.org security advisories and CHANGES, the nginx fix commits, Xint, Metnir*

---

**Q: Does this give root, and which user do the workers run as?**

**A:** Not by itself. The nginx bugs give code execution as the worker user. The main process runs as root and the workers drop to the configured user (nginx documentation and source). The worker user, inferred from shipped config files: `nginx` on the nginx.org packages, RHEL (CentOS Stream files) and Alpine, `www-data` on Debian and Ubuntu, `nginx` (uid 101) in the Docker official image, and `nobody` on a source build with the default. Xint, Rapid7 and Metnir each say their lab result through the nginx bug ran as that user, and Wiz names no account. Xint says "The commands run with the privileges of the nginx worker process that handles the request", Wiz's article never claims root, Rapid7 says the corruption can "execute code with the nginx worker process's permissions" and Metnir says "id runs on the target as the unprivileged nginx user". Xint also says it chained CVE-2026-123007 with a separate flaw in the Linux kernel to gain root on the host, and that in its tests the chain also escaped a Docker container running nginx and obtained root on the underlying host. Xint withholds the kernel flaw's details, and we could not verify the chain (COULD NOT VERIFY), so treat it as Xint's claim. Xint itself says that because workers normally run with restricted permissions, full control of the host needs a privilege escalation bug as well. CIRCL: "A vulnerable NGINX instance does not by itself imply host-root access", and the full root chain needs a reachable vulnerable kernel path or another privilege escalation route. The Hacker News says code run this way "gets the permissions of an NGINX worker process". Our reading: plan for worker-level compromise on every exposed server, and don't rule out more where the host has other weaknesses.

*Sources: Xint, Wiz, Rapid7 and Metnir write-ups, CIRCL technical report TR-105, The Hacker News, nginx documentation and source, shipped config files of the nginx.org, Debian, Ubuntu, CentOS Stream, Alpine and Docker packages (our reading)*

---

**Q: I upgraded the package. Do I still need to restart?**

**A:** Yes, a restart or a supported live binary upgrade. A reload alone isn't enough. Xint: "A configuration reload alone does not replace the running executable." CIRCL: "Restart to replace old workers and binaries." A reload also leaves connections that are already open, HTTP/2 ones included, on the old workers (Xint), and a restart drops the connections in progress. The live binary upgrade is documented in the "Upgrading Executable on the Fly" section of nginx.org's control page. This analysis gives no commands for it. `nginx -v` only reads the program on disk. First compare the package version with the fixed version in your distro advisory (for NGINX Plus, see the Plus question below). Then check that the main nginx process, the one owned by root, started after you installed the package. If it started earlier, it is still running the old code:

```bash
# Version of the nginx program on disk (it does not show what is running)
nginx -v
# When the nginx processes started. The one owned by root is the main process (run as root)
ps -eo user,pid,ppid,lstart,args | grep '[n]ginx'
```

*Sources: Xint, CIRCL technical report TR-105, nginx.org control page*

---

**Q: nginx -v shows an old or an affected number. Are we fixed or not?**

**A:** The number can mislead in both directions. Three traps:

- Distro packages backport fixes without changing the nginx version. Xint: Ubuntu 24.04 ships 1.24.0, Ubuntu 22.04 ships 1.18.0 and Debian 12 ships 1.22.1, and these distributions may backport security fixes to the existing version instead of replacing it with a new nginx release. Judge distro packages by the distro advisory, not by the nginx version string. At the cut-off no distro had shipped a fix for those releases (see the distribution question below)
- Products that embed nginx carry their own numbers: OpenResty 1.31.8.1 is based on nginx 1.31.8 (inside the affected range, no fix shipped), Kong's source pins OPENRESTY=1.27.1.2 (nginx core 1.27.1, inside the affected range, inferred, and no Kong statement was found), and NGINX Plus 37.3.0.1 is based on open source 1.31.8 yet contains the CVE-2026-123007 fix
- Docker tags move: the official image tags (latest, mainline, stable and the numbered ones) were updated on 18 November, so an image pulled earlier keeps its old nginx, and the nginxinc/nginx-unprivileged image has no fixed tag

Where sources disagree on versions, state it once. The CVE records list NGINX Plus R33 as affected, while F5's table starts at R34, and F5 says versions that have reached End of Technical Support are not evaluated. The Hacker News headline calls the HTTP/2 flaw "10-Year-Old" and Wiz says "nearly six years" for CVE-2026-123633. Only CVE-2026-123007 goes back to 2015 (the HTTP/2 module shipped in nginx 1.9.5 on 22 September 2015). CVE-2026-123633 starts in February 2021. Anyone on a release before 1.30 has no fixed release on that branch (inferred from nginx.org's "Not vulnerable: 1.31.9+, 1.30.7+" and F5's note) and has to move to 1.30.7 or 1.31.9 and later. Distro builds are the exception: Alpine 3.23 and 3.22 ship 1.28.3-r8, a patched 1.28.3 that is not an upstream release.

*Sources: Xint, nginx.org security advisories, F5 CVE records, OpenResty and Kong source files, F5 release notes, The Hacker News, Wiz, Alpine package pages*

---

**Q: We run NGINX Plus. How do we tell whether we're fixed?**

**A:** F5 fixes CVE-2026-123007 in 37.3.0.1 (CR) and 37.0.8.1 (LTS), both released on 18 November 2026, and CVE-2026-123633 in 37.2.0.1 (CR) and 37.0.7.1 (LTS), released on 14 October 2026 per the release notes. So 37.3.0.1 and 37.0.8.1 fix both (inferred: later releases on the same branch carry the earlier fix). The affected ranges are 37.1.0 to 37.2.0.1 and 37.0.0 to 37.0.7.1 for CVE-2026-123007, and 37.1.0 to 37.2.0 and 37.0.0 to 37.0.6.1 for CVE-2026-123633. R34 to R36 are affected by both, and F5's table lists the fix as "None" (WEAK: read through a browser render). The CVE records also list R33 as affected with no upper bound. Our reading: Plus customers on R33 to R36 have no fixed release on their branch and must move to a fixed 37.x release. `nginx -v` shows the open source base, which can be below 1.31.9 on a fixed Plus build (37.3.0.1 is based on 1.31.8), so check the Plus package version instead, then restart nginx with `systemctl restart nginx`:

```bash
# NGINX Plus package version on Debian and Ubuntu
apt-cache policy nginx-plus
# NGINX Plus package version on the RHEL family
rpm -q nginx-plus
```

*Sources: F5 CVE records, F5 advisories K000163926 and K000163928 (WEAK), NGINX Plus release notes*

---

**Q: Our distribution hasn't shipped a fix. What do we do?**

**A:** Judge by the distro's own advisory. At the cut-off Debian stable and testing, Ubuntu, Red Hat, SUSE and Rocky Linux had no fixed package, and Amazon Linux, AlmaLinux 9 and 10, Alpine 3.23 and 3.22 and Debian sid did. Status at 04:30 UTC on 19 November 2026:

- Debian: fixed in sid (unstable) only, with nginx 1.30.6-4 (the fixes for both CVEs backported from 1.30.7; the changelog is signed 18 November at 18:56 UTC and the tracker showed it later). No fixed package for bookworm 1.22.1-9+deb12u9 and 1.22.1-9+deb12u10 (security), trixie 1.26.3-3+deb13u7 and 1.26.3-3+deb13u10 (security) or forky 1.30.6-3, which are all "vulnerable". The tracker notes cite the upstream fix commits. Migration of 1.30.6-4 to testing is pending, and there is no DSA (nginx is not in dsa-needed). Checked at 04:29 and 04:35 UTC on 19 November
- Ubuntu: no fixed package. Both CVEs were published on 18 November (15:23) with priority high. trusty is "not-affected" (nginx 1.4.6 has no HTTP/2), xenial, bionic, focal, jammy, noble, resolute and stonking are "needed", and upstream is "released (1.31.9,1.30.7)". No notice for either CVE among the newest 20 nginx notices, and a search by CVE ID finds none (rechecked at 04:29 UTC on 19 November; the record was last updated on 18 November at 17:00 UTC). Ubuntu lists releases with nginx older than 1.19.7 (Xint: 22.04 ships 1.18.0) as needed for CVE-2026-123633, while nginx.org's range for it starts at 1.19.7, and we found no explanation (COULD NOT VERIFY)
- Red Hat: no fixed package. RHEL 8 (module nginx:1.24), RHEL 9 (default, nginx:1.24 and nginx:1.26 streams), RHEL 10 and Hardened Images are known affected for both CVEs with no erratum and no RHSA. Red Hat's CSAF VEX files (revision 3, 18 November at 21:27 UTC for CVE-2026-123007 and 21:29 UTC for CVE-2026-123633) list 45 products each as known affected, with a workaround entry and no fix. CVE-2026-123633 now has a Red Hat record (Affected). The CVE pages are WEAK: we read them from the pages' embedded data
- Rocky Linux: no fixed package (no record: the Apollo and errata APIs and the OSV data for Rocky 8, 9 and 10 had no hit at 04:29 UTC on 19 November). AlmaLinux: fixed in 9 (ALSA-2026:A025, nginx 2:1.20.1-32.el9_9.1.alma.3) and 10 (ALSA-2026:A024, nginx 2:1.26.3-16.el10_3.1.alma.2), read from the OSV database (record modified 23:00 and 22:45 UTC on 18 November; the published field carries only the date), and AlmaLinux 8 has no advisory. Oracle Linux: no record for either CVE (404 pages). SUSE: no fixed package and no SUSE-SU, but records now exist with state "Analysis" for every product (Bugzilla 1290868 and 1290872, both "NEW")
- Amazon Linux: fixed for both CVEs, severity Important. Amazon Linux 2023: ALAS2023-2026-3494 (nginx-1.30.7-1.amzn2023.0.1, released 18 November at 23:09 UTC). Amazon Linux 2 (Nginx1 Extra): ALAS2NGINX1-2026-018 (nginx-1.30.7-1.amzn2.0.1, released 19 November at 01:20 UTC). Amazon Linux 2027 Preview: ALAS2027-2026-386 (nginx) and ALAS2027-2026-385 (nginx-awslc), dated 18 November. All three showed "Pending Fix" on 18 November
- Alpine: fixed in edge and 3.24 (nginx 1.30.7-r0, builds at 17:06 and 17:11 UTC; the security database key "1.30.7-r0" lists both CVEs among nine fixed CVEs), and in 3.23 and 3.22 (nginx 1.28.3-r8, a backport, listed builds at 01:10 and 01:08 on 19 November, time zone not stated; they had 1.28.3-r7, built 23 July 2026, with no entry on 18 November). Not fixed in 3.21 (nginx 1.26.3-r3, no entry)
- Arch Linux: fixed (nginx 1.30.7-1, repository 17:08:59 UTC, and nginx-mainline 1.31.9-1, repository 16:56:25 UTC)
- Homebrew: fixed (nginx 1.31.9). FreeBSD ports: fixed (www/nginx 1.30.7,3 and www/nginx-devel 1.31.9; binary package availability was not checked and there is no VuXML entry). Gentoo: 1.30.7 and 1.31.9 are in the tree (keywords and times not read, GLSA not checked)
- Fedora: COULD NOT VERIFY (bot challenge). Repology (stale) lists Fedora 43 to 45 at 1.30.6, which is weak evidence only. Red Hat Bugzilla has no bug for either CVE, and a web search found no Fedora update

Until yours ships a fix, either turn HTTP/2 off (see the HTTP/2 questions below) or install a fixed build from the nginx.org repository. 1.31.9-1 (mainline) and 1.30.7-1 (stable) are present there for Debian (bookworm, trixie), Ubuntu (jammy, noble, resolute), RHEL 9 and 10, Alpine 3.24 (1.31.9-r1, 1.30.7-r1) and Amazon Linux 2023, and their listing times (11 November, 20:04 to 21:12, time zone not stated) are build times, not publication times. When your distro does ship a fix, the same upgrade commands apply (see the QUICK REFERENCE CARD), but judge the package by the distro advisory, not by the nginx version string.

*Sources: Debian, Ubuntu, Red Hat (WEAK), Rocky Linux, AlmaLinux, Oracle, SUSE, Amazon Linux, Alpine, Arch, Homebrew, FreeBSD ports, Gentoo and Repology pages, nginx.org package listings, Xint*

---

**Q: What about Docker images and containers?**

**A:** A container runs the nginx inside its image, so patching the host changes nothing. Rebuild the image on a fixed tag and recreate the containers from it:

```dockerfile
# Docker: rebuild your image on a fixed tag, then recreate the containers from it
FROM nginx:1.30.7
# Mainline users: FROM nginx:1.31.9. The nginxinc/nginx-unprivileged image has no fixed tag yet
```

The official image's tags (1.31.9, 1.30.7, latest, mainline, stable and the numeric and alpine variants) were pushed on 18 November between 17:15:03 and 17:21:46 UTC. The alpine-perl and alpine-otel variants had no images at 19:41 UTC and got them between 19:52 and 19:54 UTC, and no tag was stale at the 19:55 check on 18 November, and the 04:32 check on 19 November found 14 tags for 1.31.9, the newest pushed at 22:51 on 18 November. Pull dates are a poor guide, so check the version inside the image:

```bash
# Docker: version and HTTP/2 module inside a running container
docker exec <container> nginx -v
docker exec <container> nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
```

The nginxinc/nginx-unprivileged image is not fixed: it has no 1.31.9 or 1.30.7 tag, and its newest tags are dated 19 October 2026. Bitnami's source repository has "[bitnami/nginx] Release 1.31.9-debian-12-r0" (16:43 UTC) and the bitnami/nginx "latest" tag was updated at 18:48 UTC, but we didn't inspect the image contents, and bitnamilegacy/nginx is frozen (2025). An image pinned to an older tag keeps its old nginx until you rebuild it.

*Sources: Docker Hub image tags, the docker-library repository, Bitnami source repository and Docker Hub tags*

---

**Q: Our servers sit behind Cloudflare, AWS ALB, CloudFront or Akamai. Are we covered?**

**A:** Partly, and it depends on which protocol the proxy speaks to your origin. Cloudflare says "At Cloudflare, HTTP/2 connection to the origin is enabled by default." It connects with HTTP/2 only to origins that announce it through ALPN and falls back to HTTP/1.1 otherwise. Free, Pro and Business plans are "Enabled by default" and Enterprise is "Disabled by default (1 stream per connection)". The switch is Speed > Settings > Protocol Optimization > HTTP/2 to Origin. AWS says "By default, Application Load Balancers send requests to targets using HTTP/1.1" (you can set the target group protocol version to HTTP/2 or gRPC), and CloudFront "forwards requests to your custom origin using HTTP/1.1". Akamai's connection from the edge to the origin is non-HTTP/2 by default when HTTP/2 is on, and an "HTTP/2 Edge to Origin" option exists (introduced 29 July 2025; the 7 May 2026 catalog says it is now in General Availability, a line we didn't read to the end). Fastly: COULD NOT VERIFY an explicit HTTP/2-to-origin statement, and its docs say it supports any backend that is an HTTP/1.1 compliant web server.

Our reading: a CDN that speaks HTTP/2 to the origin leaves the origin's HTTP/2 code reachable through that CDN, so those origins sit in the critical tier. A CDN that speaks HTTP/1.1 to the origin removes that path, but not for an origin that can also be reached directly. Whether either bug can be triggered through a proxy that speaks HTTP/2 to the origin is unknown, because no source tested it. Wiz says only that CDNs and WAFs that terminate HTTP/2 "may mitigate parts of the exploit by not reflecting the exact payload back to the underlying NGINX server. This depends on implementation." Rapid7's notes say a proxy in the path will likely break its own public exploit. We don't claim that any CDN or WAF blocks either bug, and no CDN or WAF vendor rule or statement was found for either CVE. Xint: if a CDN or reverse proxy sits in front of nginx, a protocol test reaches only the proxy, so also test the nginx server directly. What to do: patch the origin. Where you can't yet, turn off Cloudflare's "HTTP/2 to Origin" for the zone (our reading: this removes the HTTP/2 path through Cloudflare, not the origin's own HTTP/2 listener), turn HTTP/2 off at the origin, and lock the origin so it can't be reached around the proxy (our reading). That is a layer, not a fix.

*Sources: Cloudflare, AWS ALB and CloudFront, Akamai and Fastly documentation, Wiz, Rapid7, Xint*

---

**Q: What about Kong, Apache APISIX and OpenResty?**

**A:** They embed nginx, so their own version numbers matter, and no fix had shipped at the cut-off for Kong OSS (newest 3.9.4, 12 October 2026) or OpenResty (newest v1.31.8.1, 26 October 2026). This analysis has no patch status for APISIX. What each one does with HTTP/2 (inferred from default files unless noted):

- Kong: kong.conf.default has `proxy_listen = 0.0.0.0:8000 reuseport backlog=16384, 0.0.0.0:8443 http2 ssl reuseport backlog=16384` and `admin_listen = 127.0.0.1:8001 reuseport backlog=16384, 127.0.0.1:8444 http2 ssl reuseport backlog=16384`, so HTTP/2 is on for the 8443 and 8444 listeners by default. `status_listen` has no http2. Kong's source tree pins OPENRESTY=1.27.1.2 (nginx core 1.27.1, inside the affected range), and we found no Kong statement
- Apache APISIX: the default table in apisix/cli/config.lua has `enable_http2 = true,` and the nginx template adds `http2 on;` when it is true
- OpenResty: the docker-openresty alpine image (RESTY_VERSION 1.31.8.1) builds with both `--with-http_v2_module` and `--with-http_v3_module`. Whether a source build or OpenResty's own config enables HTTP/2 by default: COULD NOT VERIFY. An OpenResty GitHub issue (1165, opened 18 November, 16:33 UTC) says "OpenResty 1.31.8.1 is based on nginx 1.31.8, which is vulnerable to CVE-2026-123633 and CVE-2026-123007. Please update Openresty ASAP. Mitigations: disable http2." The saved page shows no maintainer reply
- Tengine: HTTP/2 module off by default (HTTP_V2=NO), nginx core 1.31.5 (inside the affected range, inferred), no statement. Angie: HTTP/2 module not built by default per its docs, its security page doesn't mention either CVE, and whether its HTTP/2 code shares the flaws is not established. freenginx (newest 1.31.5, 27 October 2026): no statement, and whether it is affected is COULD NOT VERIFY

Metnir says Kong, Apache APISIX, NGINX Gateway Fabric and community ingress-nginx "enable HTTP/2 by default", and that it crashed the shipped binaries of all four and reproduced the CVE-2026-123633 use-after-free in OpenResty. We didn't verify the Gateway Fabric default (COULD NOT VERIFY). Until the vendors ship fixes, take HTTP/2 off through each product's own setting. These come from the products' default files, and the APISIX one is inferred, so check each product's own documentation before you rely on it. For OpenResty, Tengine, Angie and freenginx no vendor mitigation text was found, and the nginx-level change under the HTTP/2 questions below applies to their listen directives.

```yaml
# ingress-nginx controller ConfigMap: turn HTTP/2 off (the default is "true")
data:
  use-http2: "false"
```

Kong: take `http2` out of the listen strings in kong.conf (the defaults carry it on the 8443 and 8444 listeners). The file's own text says `http2` is what lets clients open HTTP/2 connections on a listener. Apply with your normal Kong restart or redeploy.

```
# kong.conf: the default listen strings with http2 removed
proxy_listen = 0.0.0.0:8000 reuseport backlog=16384, 0.0.0.0:8443 ssl reuseport backlog=16384
admin_listen = 127.0.0.1:8001 reuseport backlog=16384, 127.0.0.1:8444 ssl reuseport backlog=16384
```

Apache APISIX: the default table has `enable_http2 = true,` inside the apisix section. Setting it to false in conf/config.yaml should turn HTTP/2 off, but we couldn't fetch config-default.yaml to confirm the key's place (inferred).

```yaml
# conf/config.yaml (inferred from apisix/cli/config.lua)
apisix:
  enable_http2: false
```

*Sources: Kong, APISIX, OpenResty, Tengine, Angie and freenginx default files and release feeds (our reading), the OpenResty issue tracker, Metnir, F5 CVE records*

---

**Q: What about F5 NGINX Ingress Controller, NGINX Gateway Fabric and F5's other products?**

**A:** F5 NGINX Ingress Controller v5.8.0 is fixed (compatibility row "1.31.9 / R37.3.0.1", and its Makefile has NGINX_OSS_VERSION 1.31.9 and NGINX_PLUS_VERSION R37.3). The 2026-lts-r11 tag has NGINX_OSS_VERSION 1.31.0 and NGINX_PLUS_VERSION R37.0, inside the affected range, so a fixed LTS build is COULD NOT VERIFY. NGINX Gateway Fabric v2.9.0 is fixed for the open source image (NGINX_VERSION 1.31.9). Its Plus image uses nginx 1.31.8 with Plus R37.3 (patch level not shown). HTTP/2 is off by default in the Ingress Controller: the ConfigMap key `http2` defaults to "False", and the `nginx.org/http2` annotation or the VirtualServer `http2` field can turn it on per resource. If you turned it on and can't upgrade yet, set the ConfigMap key `http2` to "false" and remove any `nginx.org/http2: "true"` annotation or VirtualServer `http2: true`. Recreate the pods from the patched images (Metnir: "Recreate containers from the patched image.").

One conflict, stated once: F5's K-articles (WEAK, browser render) list "NGINX (all other products)" as "Not vulnerable" and have no separate rows for Ingress Controller, Gateway Fabric or Instance Manager, while Metnir says it crashed shipped Gateway Fabric binaries with the CVE-2026-123633 bug. F5 shipped new Ingress Controller and Gateway Fabric releases on 18 November, and the notes we saw don't mention these CVEs. Their image and release timestamps (13:10 to 14:29 UTC) come before F5's 15:00 UTC publication, so public availability of the images before then isn't established. Don't rely on either statement: patch. For F5's other products (K-articles, WEAK): "NGINX One Console" and "F5 Distributed Cloud (all services)" are marked "**" (F5 still researching), and BIG-IP, BIG-IQ, F5 Insight, F5OS, BIG-IP Next and CNF are "Not vulnerable". F5 App Protect and Instance Manager: COULD NOT VERIFY (nothing found).

*Sources: F5 documentation and changelog, F5 Ingress Controller and Gateway Fabric Makefiles and Dockerfiles, F5 advisories K000163926 and K000163928 (WEAK), Metnir*

---

**Q: Do TLS, cleartext HTTP/2, 32-bit builds, server push or HPACK settings change anything?**

**A:** Mostly unanswered. The saved demonstrations all used TLS with HTTP/2, and no source says whether either bug is reachable over cleartext HTTP/2 (h2c). On a plain listener the same switch accepts h2c from clients that send the HTTP/2 preface first (inferred), so our reading is to treat a `listen 80 http2;` listener like a TLS one. No source says whether 32-bit builds are affected, and Wiz's test was on 64-bit systems. Server push was removed in nginx 1.25.1, so it can't be a precondition on current releases, and no source ties either bug to HPACK or stream settings. HTTP/3 (QUIC) is a separate switch (`--with-http_v3_module`, `listen ... quic`) and is not in scope for these two CVEs. The HTTP/3 use-after-free CVE-2026-121810 is fixed in the same release and isn't blocked by turning HTTP/2 off.

*Sources: Wiz, F5 CVE records, nginx.org CHANGES and documentation, nginx source (our reading)*

---

**Q: Is this the same as the other fixes in the release?**

**A:** No. nginx.org's advisories page and news item for 18 November 2026 list ten advisories, not two, and turning HTTP/2 off covers only the two HTTP/2 bugs. The other eight, with nginx.org's severity and vulnerable range (all fixed in 1.31.9 and 1.30.7 unless noted):

- CVE-2026-123634: use-after-free during response processing in resolver, medium, 0.6.18 to 1.31.8
- CVE-2026-121810: use-after-free in HTTP/3, medium, 1.25.0 to 1.31.8 (the nginx.org link text reads "CVE-CVE-2026-121810")
- CVE-2026-118899: infinite loop while reading client request body over TLS 1.3, major, 1.13.0 to 1.31.8
- CVE-2026-113425: use-after-free in mail proxy module, major, 0.5.33 to 1.31.8
- CVE-2026-120993: NULL pointer dereference when using PROXY protocol version 2, minor, 1.31.4 to 1.31.8 (fixed in 1.31.9, and nginx.org lists no 1.30.x fix for it)
- CVE-2026-125283: buffer overflow when using alias with try_files, minor, 0.9.6 to 1.31.8
- CVE-2026-120967: SNI bypass when using client certificate validation in stream, medium, 1.25.5 to 1.31.8
- CVE-2026-123640: insufficient validation in stream ssl_preread module, minor, 1.15.2 to 1.31.8

Xint's five RCE-class nginx bugs are CVE-2026-123007, CVE-2026-123634, CVE-2026-123633, CVE-2026-121810 and CVE-2026-113425, and Xint says disabling HTTP/2 "does not block the other three nginx vulnerabilities". We did not read the F5 records for those three. A server with HTTP/2 off can still be exposed to the others if it uses the HTTP/3, resolver or mail proxy features.

*Sources: nginx.org security advisories and news item, Xint*

---

**Q: Our scanner is silent, or it flags a version we know is patched. Can we trust it?**

**A:** Read both results with care. Tenable still shows no plugins for either CVE ("Coming Soon", with empty plugin lists at 04:48 UTC on 19 November). Rapid7's vulnerability database has pages for both CVEs with F5 and NVD text and no check shown. Snyk lists SNYK-UNMANAGED-NGINX-22598758 for CVE-2026-123007 (critical, Exploit Maturity "Proof of Concept"). Wiz mentions a pre-built query and advisory in its Threat Center (customers only). Sophos (WEAK) says it is investigating and has announced no protection, and Qualys lists QIDs 736231 and 389654 as pending (WEAK, release "TBD By EOD"). On the network side we found no Cloudflare WAF changelog entry for either CVE (the newest emergency release that day covers a different bug), no AWS WAF managed-rule entry, no Emerging Threats Open rule (the ruleset file dates from 17 November, before disclosure) and no Snort 3 community rule (0 matches in 4,040 rule lines). We found nothing from Akamai, Fastly, Imperva, Fortinet FortiGuard or F5 BIG-IP and Advanced WAF either, and no Sigma, Elastic or CIRCL Rulezet rule, no Nuclei template (at the path we checked) and no Metasploit module. A remote version check can't see whether HTTP/2 is on or whether a distro backport is installed (our reading), so it can flag a patched distro package or a server with HTTP/2 off. A silent scanner means little too, because the records are hours old. Our reading: the only usable detection today is host-side (worker crash lines, worker-spawned processes, long HTTP/2 connections with heavy inbound traffic). Judge by the distro advisory and the HTTP/2 check above.

*Sources: Tenable, Rapid7, Snyk, Wiz, Sophos (WEAK), Cloudflare and AWS WAF changelogs, Emerging Threats and Snort rule sets, rule and template repositories (searches by us)*

---

**Q: Why do the scores differ, 8.1 versus 9.2?**

**A:** Our reading: they don't differ in substance. F5 gives both CVEs the same vector under two CVSS versions: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` scores 8.1 (High) and `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` scores 9.2 (Critical). In both, attack complexity is High, no privileges or user action are needed and the impact is full. The weaknesses are CWE-191 (Integer Underflow, Wrap or Wraparound) and CWE-787 (Out-of-bounds Write) for CVE-2026-123007, and CWE-416 (Use After Free) for CVE-2026-123633. Sources use different words for the same CVE-2026-123007 flaw: F5's weakness list and Rapid7 say integer underflow, while nginx CHANGES and Xint say overflow. We use F5's wording (the flow control window "can exceed the allowed threshold") and don't pick a side. nginx.org rates CVE-2026-123007 major and CVE-2026-123633 medium on a scale that has no critical. NVD shows both as "Received" with no score of its own. EPSS has no score yet (the API returned no data at 19:35, 19:48 and 19:59 UTC on 18 November and at 04:27 and 04:45 UTC on 19 November). Our position stays the same: critical for internet-facing servers with HTTP/2 on, high for internal servers with HTTP/2 on.

*Sources: F5 CVE records, nginx.org security advisories and CHANGES, Rapid7, Xint, NVD, FIRST EPSS API*

---

**Q: Does turning HTTP/2 off fully protect us?**

**A:** For these two bugs, yes, if it really is off everywhere. Xint's table says "Yes" for both, and Wiz, CIRCL and CERT-FR give the same advice. Know the limits:

- It has to cover every server block that shares the listening address and port, and any legacy `listen ... http2` parameter. One line you missed keeps HTTP/2 on
- A reload applies the new configuration only to new connections. Connections that were already open stay with the old workers and keep using the old configuration (Xint), so restart if you can accept a short outage
- It closes these two bugs only. The other eight fixes in the release stay open until you upgrade, and CIRCL says merely disabling HTTP/2 is not a complete mitigation
- Services that need HTTP/2 end to end, such as native gRPC, break (Xint, Metnir, CIRCL), and HTTP/1.1 clients may open more connections, so check the workers' capacity after the change (Metnir)
- It is not an F5 or nginx.org workaround: F5's records say "None", and nginx.org's advisories page has no mitigation text. Re-enable HTTP/2 after the upgrade (Wiz)

```nginx
# nginx 1.25.1 and later: in each affected server block (or once in http {}), switch it off
listen 443 ssl;
http2 off;
```

```nginx
# Older syntax (nginx 1.9.5 to 1.25.0, and still accepted later): remove http2 from listen
# Before:
listen 443 ssl http2;
# After:
listen 443 ssl;
# Cleartext listeners: "listen 80 http2;" becomes "listen 80;"
```

```bash
# Test the new configuration (run as root)
nginx -t
# Apply it to new connections (run as root)
nginx -s reload
# Connections that were already open stay with the old workers. List old workers that are still shutting down
ps -eo user,pid,ppid,lstart,args | grep '[n]ginx: worker process is shutting down'
# If the line above prints anything and a short outage is acceptable, restart (run as root). This disconnects every client
systemctl restart nginx
```

Confirm from outside with the curl and openssl checks in the first technical question: curl should print 1.1, and the openssl check should print "No ALPN negotiated" (Xint: that means the server doesn't accept HTTP/2).

*Sources: Xint, Wiz, CIRCL technical report TR-105, CERT-FR, Metnir, F5 CVE records, nginx.org security advisories*

---

**Q: Is the public proof of concept, or any GitHub repository that claims one, safe to run?**

**A:** Don't. As of 04:45 UTC on 19 November 2026, a GitHub search for either CVE ID in quotes returns 18 repositories (7 of them created after 20:10 UTC on 18 November). The figure counts search matches. By their own descriptions, the repositories we read include third party exploit and proof-of-concept claims for CVE-2026-123007 (one claims a full code execution chain), a lab repository published by Censys Research, Docker labs and read-only scanners. None of the third party code is verified, and we read descriptions and file lists only. Of the six claims we first reviewed on 18 November, the ones for CVE-2026-123633 describe a crash or denial of service, with code execution only as a possibility. One describes the CVE-2026-123633 mechanism in a way that conflicts with nginx's own fix commit, and one mislabels a different nginx CVE, so treat all six as unreliable. One third-party repository claims, about four hours after disclosure, to reproduce code execution on a stock container image, and another describes a non-destructive check mode and an exploit mode. Our reading: a non-destructive check mode makes mass scanning easier to build. The count was still rising (17 at 04:28 UTC, 18 at 04:45 UTC). A Telegram post flagged as a proof of concept for both CVEs is unverified.

Running unknown code is a common way to get compromised, above all as root or on a production server, and a "scanner" is code you would run with your own privileges. Rapid7's proof of concept is a researcher release for CVE-2026-123007 only, and its own notes limit it to a local freshly started Docker container, but it is still exploit code, so keep it out of production. We name none of the repositories, opened none and ran none. No Metasploit module or pull request and no Nuclei template or pull request was found (searches at 19:36 and 20:02 UTC on 18 November, repeated at 04:28 to 04:45 UTC on 19 November with the same result; a template at another path would not show), and Exploit-DB and Packet Storm could not be queried (COULD NOT VERIFY). Use the read-only commands in this document, your distro's advisory and the version checks instead. If you must test, use an isolated lab VM with no route to production.

*Sources: GitHub repository search for the CVE IDs (names withheld, none opened or run), Rapid7, Metnir and Xint write-ups, Metasploit and Nuclei searches*

---

**Q: Is the fix complete?**

**A:** For these two bugs, nginx 1.31.9 and 1.30.7 are the fix, and nginx.org lists both as not vulnerable there. Each bug has its own fix commit, both by Roman Arutyunyan. For CVE-2026-123007 it is e27f5fa, "HTTP/2: account for queued frames when validating WINDOW_UPDATE" (3 files under src/http/v2/, 6 insertions, 2 deletions), with the stable-1.30 copy b89c410. Its message says the flaw led to broken buffer size control when nginx sends response data, followed by memory corruption and a possible segmentation fault, and that the fix is "to account for the queued frames when validating a client WINDOW_UPDATE". For CVE-2026-123633 it is 2df48a5, "HTTP/2: reset reusable connection status on stream creation" (1 file, src/http/v2/ngx_http_v2.c, 2 insertions), with the stable-1.30 copy 0c87dd1. Its message says having an HTTP/2 connection with streams registered as reusable became possible after an earlier change from 11 February 2021, and the fix marks the connection non-reusable when a stream is created. That is why this bug starts at 1.19.7 and not 1.9.5. We say no more about the mechanism. This analysis has no independent test of either fix to report, and no source we used says either is incomplete. The same release fixes eight other bugs, so keep nginx on a regular update cycle.

*Sources: nginx.org security advisories and CHANGES, the nginx fix commits, F5 CVE records*

---

## SUCCESS CRITERIA & VERIFICATION

### You have successfully responded when:

**Technical validation checklist:**

- [ ] **All nginx instances inventoried:**
    - Hosts, VMs, container images and running containers, Kubernetes ingress controllers and gateways, API gateways, appliances and any product that bundles nginx
    - Version, distro package version (for NGINX Plus, the Plus package version), whether the HTTP/2 module is compiled in, where HTTP/2 is switched on and the exposure path recorded for each (direct, or behind a proxy, and which protocol that proxy speaks to the origin)
- [ ] **All exposed servers patched:**
    - Running nginx 1.31.9 or later, 1.30.7 or later, NGINX Plus 37.3.0.1 or 37.0.8.1, or the package that your distro's advisory names
    - Where the distro or vendor has no fix yet: HTTP/2 off, and a dated task to patch the day the fix ships
    - Community ingress-nginx and branches with no fix replaced or isolated
    - Kong, APISIX, OpenResty and other products: the vendor's answer in writing, and compensating controls until the fix ships
- [ ] **All patched servers restarted:** the main nginx process started after the fixed package was installed
- [ ] **Verification passes:**

    ```bash
    # Version of the nginx program on disk (it does not show what is running)
    nginx -v
    # Whether the HTTP/2 module is compiled in. No output means it is not (run as root if nginx is not on your path)
    nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
    # Whether HTTP/2 is switched on in the config on disk. Reads every included file (run as root)
    nginx -T 2>&1 | grep -nE '^[[:space:]]*(listen[[:space:]][^#]*[[:space:]]http2([[:space:]]|;)|http2[[:space:]]+on[[:space:]]*;)'
    # Installed packages
    dpkg -s nginx | grep '^Version'
    rpm -q nginx
    # Alpine and Homebrew: installed versions
    apk info -v | grep nginx
    brew list --versions nginx
    # NGINX Plus package version (Debian and Ubuntu, then the RHEL family)
    apt-cache policy nginx-plus
    rpm -q nginx-plus
    # When the nginx processes started. The one owned by root is the main process (run as root)
    ps -eo user,pid,ppid,lstart,args | grep '[n]ginx'
    # Processes running as the worker user, with their parents
    ps -eo user,pid,ppid,lstart,args | grep -E '^(nginx|www-data|nobody) '
    # Worker crashes in the error log (run as root; the path comes from the error_log directive, this is the usual one)
    grep -Ei 'worker process.*exited|signal 11|segfault' /var/log/nginx/error.log
    # Connection-pressure warnings (also normal on busy servers)
    grep -F 'worker_connections are not enough' /var/log/nginx/error.log
    # Core dumps on systemd hosts
    coredumpctl list nginx
    # From outside: which protocol a site negotiates (prints 2 for HTTP/2, 1.1 otherwise)
    curl -sI --http2 -o /dev/null -w '%{http_version}\n' https://www.example.com/
    # From outside: whether the server offers h2 in the TLS handshake ("ALPN protocol: h2" means yes)
    openssl s_client -connect www.example.com:443 -servername www.example.com -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol:|No ALPN negotiated'
    ```

- [ ] **No indicators of compromise** (see the checklist under DETECTION & FORENSICS)
- [ ] **Defense in depth:**
    - [ ] Origins locked so they can't be reached around the proxy, where you rely on a proxy
    - [ ] The protocol each proxy speaks to your origin recorded (Cloudflare's HTTP/2 to Origin on or off, ALB and CloudFront at their HTTP/1.1 default)
    - [ ] Alerts on worker crashes ("worker process ... exited on signal 11") and core dumps
    - [ ] Alerts on programs started by the worker user (shells, download tools, interpreters)
    - [ ] Alerts on unusual outbound connections or DNS activity from the server, and on long HTTP/2 connections with heavy inbound traffic and few logged requests
    - [ ] Log retention extended for forensics

---

**Operational validation checklist:**

- [ ] **Services work:** sites load over HTTP/1.1 and, where you kept it, HTTP/2, and TLS, proxying, logins, health checks, backups and monitoring tools are tested
- [ ] **No new crashes, restart loops or 5xx spikes** after the restart
- [ ] **Capacity holds:** where you turned HTTP/2 off, the workers cope with the extra HTTP/1.1 connections
- [ ] **Stopgaps cleaned up:** http2 settings and product switches back on purpose, or kept off on purpose; Cloudflare's HTTP/2 to Origin setting back on purpose, or kept off on purpose
- [ ] **Documentation done:** timeline, versions before and after, restart times
- [ ] **Stakeholders updated:**
    - [ ] Leadership briefed
    - [ ] Legal told whether any compromise was found
    - [ ] Insurer told the remediation is complete

---

**Compliance validation checklist:**

- [ ] **Audit trail kept:** every action timestamped, every decision explained
- [ ] **Evidence preserved** where there was any doubt
- [ ] **Breach decision documented:** legal agrees on whether notification is needed, and the evidence supports that conclusion

---

### Post-incident review checklist

**Hold within a week of finishing:**

- [ ] **What went well:**
    - Time from the disclosure (18 November 2026, 15:00 UTC) to patch
    - How fast you found every nginx instance
- [ ] **What needs work:**
    - Gaps in the inventory (ingress controllers, API gateways, container images, vendor products that bundle nginx)
    - Restart procedures and maintenance windows
    - How many servers waited on a distro or vendor with no fix
    - Contacts at distro security teams, hosting providers and product vendors
- [ ] **Metrics captured:**
    - Time to inventory: [X hours from the day you learned of it]
    - Time to patch: [X hours]
    - Time to verified restart: [X hours]
    - Systems affected: [X]
    - Staff hours: [X]
- [ ] **Actions:**
    - Move off community ingress-nginx, and retire servers on branches that have no fix
    - Keep the nginx inventory current, with the HTTP/2 setting per listener
    - Add running-version verification to the patch process
    - Rebuild images on a schedule instead of waiting for an advisory

---

## ADDITIONAL RESOURCES

### Official security advisories

- **nginx.org security advisories:** https://nginx.org/en/security_advisories.html (CVE-2026-123007, "Memory corruption in HTTP/2 flow control", major, vulnerable 1.9.5 to 1.31.8. CVE-2026-123633, "Use-after-free in HTTP/2", medium, vulnerable 1.19.7 to 1.31.8. Not vulnerable: 1.31.9+ and 1.30.7+. Ten advisories in the 18 November 2026 release)
- **Change logs:** https://nginx.org/en/CHANGES (mainline) and https://nginx.org/en/CHANGES-1.30 (stable 1.30)
- **Downloads:** https://nginx.org/en/download.html (nginx 1.31.9 mainline and 1.30.7 stable, released 18 November 2026) and the project site https://nginx.org/
- **F5 advisories:** https://my.f5.com/manage/s/article/K000163926 (CVE-2026-123007) and https://my.f5.com/manage/s/article/K000163928 (CVE-2026-123633). Both are script pages that we read through a browser render, so quotes from them are WEAK. The F5 CVE records are the firm F5 source
- **NGINX Plus release notes:** https://docs.nginx.com/nginx/releases/ (37.3.0.1 and 37.0.8.1 list the CVE-2026-123007 fix, 18 November 2026, and 37.2.0.1 and 37.0.7.1 list the CVE-2026-123633 fix, 14 October 2026; that the later releases fix both is inferred)
- **F5 NGINX Ingress Controller:** the changelog https://docs.nginx.com/nginx-ingress-controller/changelog/ and the ConfigMap reference https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/ (v5.8.0 is fixed, and HTTP/2 is off by default)
- **Fix commits (CVE-2026-123007):** https://github.com/nginx/nginx/commit/e27f5fa84fe6e98505e70bc543b748747dad0a3b ("HTTP/2: account for queued frames when validating WINDOW_UPDATE") and its stable-1.30 copy https://github.com/nginx/nginx/commit/b89c4100bf6762a45e4a6463eaf4b70368277c94
- **Fix commits (CVE-2026-123633):** https://github.com/nginx/nginx/commit/2df48a501d0fb8212b7d39dffeeff5876332ba59 ("HTTP/2: reset reusable connection status on stream creation") and its stable-1.30 copy https://github.com/nginx/nginx/commit/0c87dd1db413e440a4e3ef7ee8acc518509e8809
- **CVE records:** https://cveawg.mitre.org/api/cve/CVE-2026-123007 and https://cveawg.mitre.org/api/cve/CVE-2026-123633 (published 18 November 2026, 15:23 UTC, with F5 as the CNA; CISA's entries add the SSVC result)
- **NVD:** https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-123007 and https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-123633 (both "Received" and not analysed, published 18 November 2026, 16:18:04 UTC, with later reference changes at 20:18 and 21:17 UTC and one more change to CVE-2026-123633 at 23:17 UTC (status unchanged at 04:45 UTC on 19 November); no NVD score of its own and no CPE configuration data, so it shows F5's scores)
- **GitHub advisories:** https://github.com/advisories/GHSA-m4q8-cf44-f42r (CVE-2026-123007) and https://github.com/advisories/GHSA-7xxj-p8w5-434q (CVE-2026-123633), both unreviewed, Critical, CVSS v4 9.2
- **nginx documentation:** the HTTP/2 module https://nginx.org/en/docs/http/ngx_http_v2_module.html, the core module https://nginx.org/en/docs/http/ngx_http_core_module.html, the command-line switches https://nginx.org/en/docs/switches.html, control and the live binary upgrade https://nginx.org/en/docs/control.html, build options https://nginx.org/en/docs/configure.html and the core functionality page https://nginx.org/en/docs/ngx_core_module.html

### Government and CERT advisories

- **CISA:** neither CVE is in the KEV catalog (catalog 2026.11.18, released 19:17 UTC, 1786 entries, checked at 19:59 and 20:10 UTC on 18 November and at 04:27, 04:45 and 04:48 UTC on 19 November): https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json. CISA's SSVC entries in the CVE records (16:04:40 UTC for CVE-2026-123007, 16:38:06 UTC for CVE-2026-123633): Exploitation none, Automatable no, Technical impact total
- **NCSC-NL:** NCSC-2026-0506 (18 November 2026, 16:07 UTC), rated H/H (high likelihood, high impact): https://advisories.ncsc.nl/2026/ncsc-2026-0506.html. It expects proof-of-concept code soon, after which it expects large-scale exploitation
- **CERT-EU:** Security Advisory 2026-022, "Critical vulnerabilities in Nginx": https://cert.europa.eu/publications/security-advisories/2026-022/ (18 November, 18:30 CET, which is 17:30 UTC; "no exploitation in the wild has been reported yet")
- **CERT-FR:** alert CERTFR-2026-ALE-017: https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-017/ (recommends disabling HTTP/2 until fixes are applied, and confirms a public proof of concept for CVE-2026-123007)
- **Canadian Centre for Cyber Security:** AV26-1174: https://cyber.gc.ca/en/alerts-advisories/f5-security-advisory-av26-1174 (updated 18 November, 19:02 UTC)
- **CERT.at:** a warning page on NGINX Plus and NGINX Open Source (November 2026, in German): https://www.cert.at/de/warnungen/2026/11/kritische-sicherheitslucken-in-nginx-plus-und-nginx-open-source-updates-verfugbar
- **CCB Belgium (WEAK, headline and time only):** "Warning: Multiple Critical NGINX Vulnerabilities, Patch Immediately!" (18 November, 17:27 UTC, listed by a news aggregator because the page itself returned Access Denied): https://ccb.belgium.be/advisories/warning-multiple-critical-nginx-vulnerabilities-patch-immediately
- **HKCERT:** security bulletin dated 19 November 2026, 09:00 (+0800), which is 01:00 UTC: https://www.hkcert.org/security-bulletin/nginx-multiple-vulnerabilities_20261119 ("Proof of Concept exploit code is publicly available for CVE-2026-123007")
- **oss-security mailing list:** a post, "CVE-2026-123633, CVE-2026-123007: nginx RCE via HTTP/2" (18 November, 20:35 UTC): https://www.openwall.com/lists/oss-security/2026/11/18/16 (lists the ten bugs fixed in the release and points to nginx.org's advisories page)
- **Cloud providers:** Heroku's Dev Center changelog item 3920 names CVE-2026-123007, CVE-2026-123633 and CVE-2026-118899 (effective 18 November 2026, nginx 1.30.7 on the PHP platform): https://devcenter.heroku.com/changelog-items/3920. No AWS, Azure, Google Cloud, Cloudflare or Vercel statement was found

### Research and threat intelligence

- **Wiz (18 November 2026, 15:13 UTC):** https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities. Wiz says it confirmed remote code execution with an ASLR bypass on official nginx 1.31.7 and 1.31.8 builds, built exploits for both bugs and won't release them at this time. It advises disabling HTTP/2 temporarily if you can't upgrade
- **Rapid7 (post metadata date 18 November 2026, 14:00 UTC; when it went live is not established):** https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/ (CVE-2026-123007 only, CVSSv4 9.2 (Critical), CWE-191). Its proof-of-concept repository is not linked here
- **Xint (18 November 2026, 15:07 UTC):** cited by name only. It covers CVE-2026-123007 and CVE-2026-123633 among other nginx bugs, and says disabling HTTP/2 blocks both
- **Metnir:** cited by name only. It covers CVE-2026-123633 only (CVSS 4.0 9.2) and withholds its exploit while patched builds reach distributions and downstream products
- **CIRCL technical report TR-105:** https://www.circl.lu/pub/tr-105/ (ASLR is "not an effective standalone mitigation" for these bugs, and the report advises restarting to replace old workers and binaries)
- **The Hacker News (18 November 2026, 18:31 UTC):** https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html (no attacks reported so far; its "10-Year-Old" fits only CVE-2026-123007)
- **The Register (18 November 2026):** https://www.theregister.com/a/5310887 (F5's spokesperson: "At this time, we have found no evidence of active exploitation of any of these vulnerabilities in the wild")
- **Censys Research, Qualys and Tenable (FAQ):** cited by name only, because their addresses carry another name for the bugs. Censys Research published proof-of-concept material in a lab repository (not linked). Qualys (post dated 18 November, WEAK) says it has not seen public confirmation of exploitation as of 18 November, and Tenable's FAQ (19 November, 00:18 UTC) says there are no reports of threat actors exploiting these CVEs as of 18 November
- **Scale (proxies only, not exposure counts):** W3Techs (18 November 2026) says "Nginx is used by 29.7% of all the websites whose web server we know" (https://w3techs.com/technologies/details/ws-nginx) and puts HTTP/2 on 35.6% of all websites (https://w3techs.com/technologies/details/ce-http2), a separate population, so don't multiply the two. Netcraft's September 2026 survey counts 1,470,435,351 sites and 225,366,509 on nginx, 15.3% (https://www.netcraft.com/blog/september-2026-web-server-survey). Netcraft's August 2026 narrative shows a large swing in nginx's count, so that figure is volatile
- **Exposure counts:** no source we can use counts nginx hosts with HTTP/2 on. Censys has a public exposure tracker (since 18 November, snapshot refreshed at 04:06 UTC on 19 November), and we do not quote its figures (its page says they count services). Shadowserver lists nothing for these CVEs, and GreyNoise, Netlas and LeakIX gave us nothing (COULD NOT VERIFY). Xint's figures (10 November): Shodan returned 56.7 million hosts for product:nginx, 11.94 million (21.1%) reported an identifiable version, and among those 98.9% fell within the range affected by CVE-2026-123007 (1.9.5 through 1.31.8). Xint: "These numbers are based on reported version strings and don't confirm that a server is vulnerable." HTTP/2 may be off, and a reported version may hide a backported fix. Our arithmetic, not a source figure: 98.9% of 11.94 million is about 11.8 million hosts

### Detection and scanning tools

- **Checkers:** this analysis has no checker script. Use the read-only commands under AM I AFFECTED? SELF-ASSESSMENT and DETECTION & FORENSICS
- **Exploit tracking:** CIRCL's sightings feed counted 68 sightings for CVE-2026-123007 and 47 for CVE-2026-123633 at the 18 November check (not re-run), none "exploited". EPSS has no score for either CVE yet (https://api.first.org/data/v1/epss?cve=CVE-2026-123007,CVE-2026-123633, no data at 19:35, 19:48 and 19:59 UTC on 18 November and at 04:27 and 04:45 UTC on 19 November), and CISA KEV doesn't list either CVE (catalog 2026.11.18)
- **Tenable:** still no plugins for either CVE ("Coming Soon" on 18 November, empty plugin lists at 04:28, 04:45 and 04:48 UTC on 19 November): https://www.tenable.com/cve/CVE-2026-123007/plugins. A remote version check can't see whether HTTP/2 is on or whether a distro backport is installed (our reading)
- **Rapid7 vulnerability database and Snyk:** Rapid7 has pages for both CVEs with F5 and NVD text and no check shown. Snyk lists SNYK-UNMANAGED-NGINX-22598758 for CVE-2026-123007 (critical, Exploit Maturity "Proof of Concept"). Wiz mentions a pre-built query and advisory in its Threat Center (customers only). Sophos (WEAK): investigating, no protection announced. Qualys: QIDs 736231 (NGINX Open Source) and 389654 (F5 NGINX Plus), both naming F5 notice K000164058, listed as pending with release "TBD By EOD" (WEAK, read through a fetch tool after curl was blocked)
- **No rule or template yet:** no Cloudflare WAF changelog entry for either CVE, no AWS WAF managed-rule entry, no Emerging Threats Open rule, no Snort 3 community rule, no Sigma, Elastic or CIRCL Rulezet rule, no Nuclei template (path checked) and no Metasploit module. Akamai, Fastly, Imperva, Fortinet FortiGuard and F5 BIG-IP or Advanced WAF guidance: nothing found
- Treat GitHub repositories that claim to be proofs of concept as unreviewed and untrusted

### Vendor and distro advisories

- **Debian:** https://security-tracker.debian.org/tracker/CVE-2026-123007 and https://security-tracker.debian.org/tracker/CVE-2026-123633 (fixed in sid with nginx 1.30.6-4, whose changelog https://metadata.ftp-master.debian.org/changelogs/main/n/nginx/nginx_1.30.6-4_changelog is signed 18 November, 18:56 UTC; no fixed package in bookworm 1.22.1-9+deb12u9 and 1.22.1-9+deb12u10, trixie 1.26.3-3+deb13u7 and 1.26.3-3+deb13u10 or forky 1.30.6-3, all "vulnerable")
- **Ubuntu:** https://ubuntu.com/security/CVE-2026-123007 and https://ubuntu.com/security/CVE-2026-123633 (priority high; no fixed package; trusty "not-affected", xenial through resolute and stonking "needed"; upstream "released (1.31.9,1.30.7)")
- **Red Hat:** https://access.redhat.com/security/cve/CVE-2026-123007 and https://access.redhat.com/security/cve/CVE-2026-123633, and the CSAF VEX files https://access.redhat.com/security/data/csaf/v2/vex/2026/cve-2026-123007.json and https://access.redhat.com/security/data/csaf/v2/vex/2026/cve-2026-123633.json (RHEL 8, 9, 10 and Hardened Images known affected, 45 products listed in each file, no fix and a workaround entry, no erratum; the CVE pages are WEAK, read from the pages' embedded data)
- **Amazon Linux:** https://explore.alas.aws.amazon.com/CVE-2026-123007.html and https://explore.alas.aws.amazon.com/CVE-2026-123633.html (fixed on Amazon Linux 2 Nginx1 Extra, 2023 and 2027 Preview; severity Important, CVSS v3 base score 8.1), and the advisories https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3494.html (nginx-1.30.7-1.amzn2023.0.1) and https://alas.aws.amazon.com/AL2/ALAS2NGINX1-2026-018.html (nginx-1.30.7-1.amzn2.0.1)
- **Alpine:** https://secdb.alpinelinux.org/edge/main.json and https://secdb.alpinelinux.org/v3.24/main.json (nginx 1.30.7-r0 in edge and 3.24), https://secdb.alpinelinux.org/v3.23/main.json and https://secdb.alpinelinux.org/v3.22/main.json (nginx 1.28.3-r8 in 3.23 and 3.22, a backport; Alpine 3.21 has no entry), and the package page https://pkgs.alpinelinux.org/packages?name=nginx&branch=edge
- **AlmaLinux:** ALSA-2026:A025 (AlmaLinux 9, nginx 2:1.20.1-32.el9_9.1.alma.3) and ALSA-2026:A024 (AlmaLinux 10, nginx 2:1.26.3-16.el10_3.1.alma.2), read from the OSV database because the errata site is a script page. AlmaLinux 8 has no advisory
- **SUSE:** https://www.suse.com/security/cve/CVE-2026-123007.html and https://www.suse.com/security/cve/CVE-2026-123633.html (state "Analysis" for every product, no SUSE-SU; Bugzilla 1290868 and 1290872 are both "NEW")
- **Arch Linux:** https://archlinux.org/packages/extra/x86_64/nginx/json/ (nginx 1.30.7-1) and https://archlinux.org/packages/extra/x86_64/nginx-mainline/json/ (nginx-mainline 1.31.9-1)
- **Homebrew:** https://formulae.brew.sh/api/formula/nginx.json (nginx 1.31.9)
- **FreeBSD ports:** https://www.freshports.org/www/nginx/ (www/nginx 1.30.7,3) and https://www.freshports.org/www/nginx-devel/ (www/nginx-devel 1.31.9). No VuXML entry, and binary package availability was not checked
- **Gentoo:** https://packages.gentoo.org/packages/www-servers/nginx (1.30.7 and 1.31.9 in the tree; keywords and times not read, GLSA not checked)
- **Docker official image:** https://raw.githubusercontent.com/docker-library/official-images/master/library/nginx (the manifest of tags and build commits for the official image, listing 1.31.9, 1.30.7, latest, mainline, stable and the variants; Docker Hub shows them pushed 18 November 2026 between 17:15:03 and 17:21:46 UTC). The nginxinc/nginx-unprivileged image is not fixed
- **Heroku:** https://devcenter.heroku.com/changelog-items/3920 (nginx 1.30.7 on the PHP platform, effective 18 November 2026)
- **OpenResty:** https://github.com/openresty/openresty/issues/1165 (issue opened 18 November 2026, 16:33 UTC; OpenResty 1.31.8.1 is based on nginx 1.31.8; no fix shipped)
- **Community ingress-nginx:** https://github.com/kubernetes/ingress-nginx (retired and archived 24 March 2026), the retirement notice https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/ and the ConfigMap reference https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/docs/user-guide/nginx-configuration/configmap.md (the `use-http2` key)
- **Kong:** https://raw.githubusercontent.com/Kong/kong/master/kong.conf.default (HTTP/2 on the 8443 and 8444 listeners by default; no fixed Kong OSS release at the cut-off)
- **Apache APISIX:** https://raw.githubusercontent.com/apache/apisix/master/apisix/cli/config.lua (`enable_http2 = true` by default)
- **Cloudflare:** https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/ (HTTP/2 to the origin is on by default for Free, Pro and Business plans)
- **AWS Application Load Balancer:** https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html (HTTP/1.1 to targets by default)
- **AWS CloudFront:** https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html (HTTP/1.1 to custom origins)
- **Akamai:** https://techdocs.akamai.com/property-mgr/docs/http2-support (says the edge-to-origin connection is non-HTTP/2 when HTTP/2 is on; Akamai changelog entries, not linked here, describe an "HTTP/2 Edge to Origin" option)
- **No fixed release at the cut-off:** freenginx (newest 1.31.5, 27 October 2026), Angie (newest 1.12.4, 16 October 2026), OpenResty (newest v1.31.8.1, 26 October 2026), Tengine (newest 3.2.0-rc5, 4 September 2026), Kong OSS (newest 3.9.4, 12 October 2026) and community ingress-nginx (retired)
- **No fixed package or advisory found:** Rocky Linux (no record), AlmaLinux 8 (no advisory), Fedora (COULD NOT VERIFY) and Oracle Linux (no record for either CVE). SUSE has records in the "Analysis" state and no fixed package. cPanel and Plesk: COULD NOT VERIFY. AWS, Azure, Google Cloud, Cloudflare and Vercel: no statement found
- F5 NGINX Ingress Controller and NGINX Gateway Fabric: see the F5 entries under Official security advisories

### Emergency support contacts

- **Product and platform vendors (F5, Kong, APISIX, OpenResty, your hosting provider):** the vendor's security contact (not an incident hotline)
- **CISA:** report@cisa.gov or +1 888-282-0870
- **FBI Internet Crime Complaint Center (IC3):** report online (US)
- **CERT-In (India):** incident@cert-in.org.in or 1800-11-4949
- **NCSC-UK:** its online incident reporting service
- **Your hosting provider's security contact, your Linux distributor's security team and your incident response retainer**

---

## QUICK REFERENCE CARD

### Print and post this

```
===============================================================
  NGINX2SHELL: CVE-2026-123007 AND CVE-2026-123633
  HEAP BUGS IN NGINX HTTP/2: FIX IT, THEN RESTART NGINX
  F5 CVSS 3.1: 8.1 | CVSS 4.0: 9.2 | nginx.org: major, medium
===============================================================

AFFECTED (HTTP/2 on):
  nginx 1.9.5 to 1.31.8 (CVE-2026-123007)
  nginx 1.19.7 to 1.31.8 (CVE-2026-123633)
  NGINX Plus before 37.3.0.1 (CR) or 37.0.8.1 (LTS)
  No fixed release on older branches: move to 1.30.7 or
  1.31.9 (Plus R33 to R36: move to a fixed 37.x release)

FIXED IN (18 November 2026):
  nginx 1.31.9 (mainline) and 1.30.7 (stable)
  NGINX Plus 37.3.0.1 (CR) and 37.0.8.1 (LTS)
  Fixed packages: nginx.org repository, Docker official
  image, Amazon Linux (2, 2023, 2027 Preview), AlmaLinux 9
  and 10, Alpine edge, 3.24, 3.23 and 3.22, Debian sid,
  Arch, Homebrew, FreeBSD ports, Gentoo (in the tree)
  No fixed package: Debian stable and testing, Ubuntu,
  RHEL, SUSE, Rocky, AlmaLinux 8, Alpine 3.21,
  nginx-unprivileged image
  No fix shipped: community ingress-nginx (retired), Kong,
  OpenResty, Tengine, Angie, freenginx
  Judge distro packages by the distro advisory, not by the
  nginx version string

NOT EXPOSED TO THESE TWO BUGS:
  HTTP/2 off everywhere, or no HTTP/2 module compiled in
  Still upgrade: the release fixes eight other bugs

---------------------------------------------------------------
YOU ARE EXPOSED WHEN ALL OF THESE ARE TRUE:
---------------------------------------------------------------

  1. nginx 1.9.5 to 1.31.8 (or an unpatched distro build),
     or a product built on it
  2. The HTTP/2 module is compiled in and HTTP/2 is on for
     a listener
  3. An attacker can reach that listener (no login needed)
  CVE-2026-123633 also needs proxying to a backend and a
  worker running low on worker_connections

  A CDN in front does not clear you. Cloudflare's HTTP/2 to
  Origin is on by default (Free, Pro, Business), and no
  source has tested whether any proxy blocks either bug

---------------------------------------------------------------
IMMEDIATE ACTIONS:
---------------------------------------------------------------

1. CHECK (1 minute), as root where needed:
   # Version on disk, then whether the HTTP/2 module is in
   nginx -v
   nginx -V 2>&1 | grep -o -- '--with-http_v2_module'
   # Which ports nginx listens on
   ss -tlnp | grep nginx
   # Is HTTP/2 switched on? Use the nginx -T grep under
   # SUCCESS CRITERIA. From outside, the first line shows
   # HTTP/2 or HTTP/1.1
   curl -sI --http2 https://www.example.com/

2. PATCH (internet-facing servers with HTTP/2 on first),
   as root, except Homebrew (run it as your normal user):
   # Debian and Ubuntu with the nginx.org repository
   apt-get update && apt-get install --only-upgrade nginx
   systemctl restart nginx
   # RHEL 9 and 10, Rocky, AlmaLinux, Amazon Linux 2023
   # with the nginx.org repository
   dnf upgrade nginx
   systemctl restart nginx
   # Alpine edge and 3.24
   apk update && apk upgrade nginx
   rc-service nginx restart
   # Arch Linux (this upgrades every package)
   pacman -Syu
   systemctl restart nginx
   # FreeBSD (binary package availability not checked)
   pkg upgrade nginx
   service nginx restart
   # Gentoo (on OpenRC use: rc-service nginx restart)
   emerge --sync && emerge --ask --update www-servers/nginx
   systemctl restart nginx
   # Homebrew
   brew update && brew upgrade nginx
   brew services restart nginx
   # Docker: rebuild on the fixed tag, then recreate containers
   FROM nginx:1.30.7
   # Mainline: FROM nginx:1.31.9 (nginx-unprivileged: no fix)
   # NGINX Plus: install 37.3.0.1 or 37.0.8.1, then restart
   systemctl restart nginx

3. RESTART, THEN CONFIRM THE FIX IS RUNNING:
   A reload does not replace the running program. nginx -v
   reads the program on disk, not the running one. On NGINX
   Plus it shows the open source base, so check the package
   (apt-cache policy nginx-plus, or rpm -q nginx-plus).
   Then check that the main nginx process, owned by root,
   started after the update:
   ps -eo user,pid,ppid,lstart,args | grep '[n]ginx'

4. CAN'T PATCH TODAY? Turn HTTP/2 off. A bridge, not a fix.
   Not an F5 or nginx.org workaround (F5 says "None"). In
   every server block that shares the listener, on nginx
   1.25.1 and later, set:

   listen 443 ssl;
   http2 off;

   Older syntax: remove http2 from the listen line, so
   "listen 443 ssl http2;" becomes "listen 443 ssl;"
   Then, as root:
   nginx -t
   nginx -s reload
   # Open connections stay on the old workers. Restart if a
   # short outage is acceptable
   systemctl restart nginx
   This breaks services that need HTTP/2 end to end (native
   gRPC). It blocks only these two bugs: patch anyway
   Products: ingress-nginx ConfigMap use-http2 "false", Kong
   (take http2 out of the listen strings), APISIX
   enable_http2: false (inferred). See the technical questions

5. BEHIND A PROXY OR CDN? A layer, not a fix:
   Cloudflare: turn off HTTP/2 to Origin where the origin
   can't be patched yet (on by default: Free, Pro, Business)
   AWS ALB and CloudFront speak HTTP/1.1 to origins by
   default: check that nobody changed that
   Lock the origin so it can't be reached around the proxy
   Whether any proxy blocks either bug is unknown

---------------------------------------------------------------
WHAT TO WATCH (no indicators of compromise are published):
---------------------------------------------------------------

  Worker crashes: "worker process ... exited on signal 11"
  Core dumps (systemd hosts: coredumpctl list nginx)
  Programs started by the worker user (nginx, www-data,
  nobody): shells, download tools, interpreters
  Long HTTP/2 connections with heavy inbound traffic and
  few logged requests
  CVE-2026-123633: worker_connections warnings, then crashes
  Clean logs prove little: no known fingerprint exists

---------------------------------------------------------------
THREAT LEVEL (19 November 2026, 04:30 UTC):
---------------------------------------------------------------

  No exploitation in the wild reported (checked 04:30 UTC)
  Public proof of concept for CVE-2026-123007: Rapid7's
  (limited to a fresh container), plus unverified third
  party code, one claim of full code execution, and
  Censys Research material. HKCERT says one is public
  No proof of concept from Wiz, Xint or Metnir is public
  18 GitHub repositories match the CVE IDs: none verified,
  do not run any of them
  Not in CISA KEV. EPSS: no score yet
  CISA SSVC: Exploitation none, Automatable no, Technical
  impact total
  NCSC-NL expects large-scale exploitation once proof of
  concept code is out

---------------------------------------------------------------
IF COMPROMISED:
---------------------------------------------------------------

  1. Isolate the server (keep it running for evidence)
  2. Capture the process list, network connections and logs
     BEFORE any restart or patch. Preserve logs. Do NOT
     delete anything
  3. Rotate every secret the worker user could read or that
     passed through the server
  4. Bring in incident response, legal and your insurer
  5. Contact: [Your security team / CISO]

---------------------------------------------------------------
MORE INFORMATION:
---------------------------------------------------------------

  nginx.org: security advisories page, CVE-2026-123007 and
             CVE-2026-123633
  F5:        K000163926 and K000163928
  Fix:       commits e27f5fa and 2df48a5, nginx 1.31.9 and
             1.30.7 (18 November 2026)
  Vendors:   the CVE page of your distribution (see
             ADDITIONAL RESOURCES)

  Emergency Support: [Your IT Security Contact]
  Phone: [Phone Number]
  Email: [Email Address]

===============================================================
  A reload does not replace the running program, and a fixed
  package on disk does not fix a running one. Patch, restart.
===============================================================

Document Version: 1.0
Last Updated: 19 November 2026
Data cut-off: 19 November 2026, 04:30 UTC
Classification: TLP:CLEAR, public distribution
```

*Sources: nginx.org security advisories, F5 CVE records, distro advisories (Debian, Ubuntu, Red Hat, Amazon Linux, Alpine), CISA and CERT notices. Details are in the sections above.*

---

## FINAL RECOMMENDATIONS

### The bottom line

**If your servers run nginx 1.31.9 or later, 1.30.7 or later, NGINX Plus 37.3.0.1 or 37.0.8.1, or your distro's fixed package, and every server has been restarted:**

- You're fixed for these two CVEs
- Keep the detection on: worker crashes, programs started by the worker user, unexpected outbound connections
- Ignore a scanner that judges distro packages by the nginx version alone

**If you run an affected nginx with HTTP/2 on and it faces the internet:**

- Patch and restart today where a fixed build exists
- Where a restart or a distro fix has to wait, switch HTTP/2 off until you can patch. It is a bridge, not a fix, and not an F5 or nginx.org workaround
- Check your error logs and process history as far back as retention allows

**If you run Debian stable or testing, Ubuntu, Red Hat Enterprise Linux, SUSE or Rocky Linux packages:**

- No fixed package at the cut-off. Switch HTTP/2 off until your distro's advisory names a fixed build, or install a fixed build from the nginx.org repository, or run a container on a fixed tag. Check your distro's tracker again before you act

**If you run Amazon Linux, AlmaLinux 9 or 10, Alpine, Debian sid, Arch, Homebrew, FreeBSD ports or Gentoo:**

- Fixed packages exist (Amazon Linux 2, 2023 and 2027 Preview, AlmaLinux 9 and 10, Alpine edge, 3.24, 3.23 and 3.22 but not 3.21, Debian sid but not its stable and testing releases, and Gentoo has 1.30.7 and 1.31.9 in the tree). Install the one that your platform's advisory or package page names, then restart. The versions are under ADDITIONAL RESOURCES

**If you run Fedora, AlmaLinux 8, Oracle Linux or SUSE:**

- We found no fixed package for any of them (SUSE has records in the "Analysis" state, Oracle Linux has none, AlmaLinux 8 has no advisory and Fedora could not be checked). Check what your repository offers, update the day a fixed package is confirmed, and switch HTTP/2 off until then

**If you run NGINX Plus:**

- Install 37.3.0.1 or 37.0.8.1 and restart. R33 to R36 have no fixed release on their branch (our reading), so move to a fixed 37.x release. Check the Plus package version, not `nginx -v`

**If you run Docker images:**

- Rebuild on a fixed tag (nginx:1.30.7 or nginx:1.31.9) and redeploy. Patching the host doesn't change an image. The nginxinc/nginx-unprivileged image has no fixed tag yet

**If you run Kubernetes:**

- F5 NGINX Ingress Controller v5.8.0 and NGINX Gateway Fabric v2.9.0 carry fixed builds: recreate the pods from the patched images. Community ingress-nginx has no fix and none is coming: set `use-http2` to "false" now and move to a maintained controller

**If you run Kong, Apache APISIX or OpenResty:**

- No fix had shipped for Kong or OpenResty at the cut-off, and this analysis has no APISIX patch status. Switch HTTP/2 off through the product's own setting and ask the vendor in writing

**If you're behind Cloudflare, ALB, CloudFront or Akamai:**

- Patch the origin. Cloudflare's HTTP/2 to Origin is on by default for Free, Pro and Business plans, and no source has tested whether any proxy blocks either bug. Lock the origin so it can't be reached around the proxy, and turn HTTP/2 off at the origin where you can't patch yet

**If you don't know what nginx you run:**

- Find out in the next two hours. Start with the inventory commands under AM I AFFECTED? SELF-ASSESSMENT

### Takeaway for leadership

CVE-2026-123007 and CVE-2026-123633 are simple to scope once you know where to look, and easy to get wrong if you judge by a version string. Their severity label depends on who you ask: F5 and the researchers say critical (CVSS 4.0 9.2, and 8.1 under CVSS 3.1), nginx.org says major for one bug and medium for the other, and CISA's assessment says Exploitation none. Our reading is that 8.1 and 9.2 are one rating scored under two CVSS versions. Exposure turns on one setting. A server with HTTP/2 off isn't exposed to these two bugs. A server on 1.9.5 to 1.31.8 with HTTP/2 on is, and most teams haven't mapped which of theirs are which. Version numbers mislead: distro packages backport fixes without changing the nginx version, products that embed nginx carry their own numbers, and NGINX Plus 37.3.0.1 is based on open source 1.31.8 yet carries a fix. At the cut-off Debian stable, Ubuntu, Red Hat, SUSE and Rocky Linux had no fixed package, community ingress-nginx will never get one, and Kong and OpenResty had shipped nothing. Whether the bugs give reliable code execution is disputed (Rapid7's notes limit its public code to a fresh container, while Xint says its unreleased exploit works under normal traffic), and no exploitation has been reported. More public exploit code has appeared since Rapid7's, none of it verified. Don't wait for that argument. NCSC-NL expects large-scale exploitation once proof-of-concept code is out, and CIRCL's feed first saw a public proof of concept for CVE-2026-123007 at 17:04 UTC, about two hours after disclosure. A fix needs a restart, so a server stays exposed until it restarts.

Use the incident to fix four things:

1. Know every nginx instance you run, including containers, ingress controllers and gateways, and whether HTTP/2 is on for each
2. Know which protocol your CDNs and proxies speak to your origins
3. Retire community ingress-nginx and servers on branches with no fix, or isolate them
4. Treat the restart as part of patching, and check that the main process started after the update. A package on disk proves nothing on its own

### Remember

- Both fixes are public: nginx 1.31.9 and 1.30.7, 18 November 2026
- A patch only counts once the running process is the fixed one, and a reload doesn't replace the program
- Version strings mislead: distro packages backport fixes, and products that embed nginx and NGINX Plus carry their own numbers
- HTTP/2 off means not exposed to these two bugs, but take 1.31.9 or 1.30.7 anyway: the release fixes eight other bugs
- HTTP/2 off is not an F5 or nginx.org workaround, and it breaks anything that needs HTTP/2 end to end
- A CDN in front doesn't clear you: Cloudflare's HTTP/2 to Origin is on by default for Free, Pro and Business plans, and no source has tested whether any proxy blocks either bug
- Community ingress-nginx has no fix and none is coming
- Clean logs prove little: no indicators of compromise have been published
- Don't run the public repositories that claim to be proofs of concept
- Patch first, argue about 8.1 versus 9.2 later

Patch what has a fix today, turn HTTP/2 off where there is none, and restart every server today.

---

**Document Version:** 1.0
**Last Updated:** 19 November 2026
**Data cut-off:** 19 November 2026, 04:30 UTC
**Classification:** TLP:CLEAR, public distribution
**Prepared by:** 0xDTC (TheSecureLancer)

Facts in this document come from nginx.org and F5, the CVE records, distro and vendor advisories, CERT notices, research write-ups, tool documentation, and press coverage listed above. Where those sources disagree, the document says so.
