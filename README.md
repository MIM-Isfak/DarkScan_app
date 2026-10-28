# DarkScan

### A security analysis tool built with Java & Spring Boot

![Java](https://img.shields.io/badge/Java-17-orange?style=flat-square&logo=java)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.7-brightgreen?style=flat-square&logo=springboot)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
[![DarkScan CI](https://github.com/MIM-Isfak/DarkScan_app/actions/workflows/ci.yml/badge.svg)](https://github.com/MIM-Isfak/DarkScan_app/actions/workflows/ci.yml)

> Scan files and websites for common security vulnerabilities.

---

## Screenshots

![Home Page](docs/Screenshot%202026-07-05%20224559.png)

![File Scan Result](docs/Screenshot%202026-07-05%20224648.png)

![SSRF Protection](docs/Screenshot%202026-07-05%20224748.png)

## What it does

### File Scan

- Detects sensitive filenames (`.env`, `id_rsa`, `.pem`, `.key`, `config.php`)
- Scans file contents line-by-line for leaked secrets:
  - AWS Access Keys / Secret Keys
  - Hardcoded passwords
  - API keys & Bearer tokens
  - GitHub personal access tokens
  - Private key blocks

### Website Scan

- Checks for missing HTTP security headers:
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options`
- Warns if a site uses plain HTTP instead of HTTPS
- Detects `Server` header information leakage
- Includes SSRF protections that reject localhost, loopback, private network, link-local, and other restricted addresses before outbound requests

### Results and Reporting

- Every finding has a severity level (Critical, High, Medium, Low, Info), shown as a colour-coded badge
- A collapsible "Explain" section for each finding describes what the issue is, how an attacker could abuse it, and how to fix it
- Findings are mapped to a CWE identifier and an OWASP Top 10 (2021) category, with a reference link
- Scan results can be downloaded as a JSON report. The report is generated from the existing result; the scan is not re-run and nothing is stored on the server

---

## Security fixes included

| Issue | Fix |
|---|---|
| XSS via filename/URL in results | `th:text` auto-escaping with Thymeleaf |
| XSS via the embedded JSON report | `&`, `<` and `>` are Unicode-escaped before embedding; covered by a unit test |
| SSRF via user-supplied URL | URL validation, DNS resolution, restricted-address checks, and redirects disabled |
| SSRF via DNS rebinding | DNS is resolved once, all addresses are validated, and the connection is pinned to the validated IP (TLS verification still uses the original hostname) |
| Non-http(s) schemes | Rejected before any outbound request |
| ReDoS in hostname validation | Regex replaced with a simple loop; URL length (2048) and hostname length (253) limits added |
| Slow or hanging target sites | Overall 10-second scan deadline enforced by aborting the request |
| Binary files reported as "clean" | Binary files now produce a "not scanned" warning |
| Null filename crash | Null-safe check before processing |
| Container running as root | Docker image runs as a non-root user |
| Over-privileged CI token | GitHub Actions `GITHUB_TOKEN` restricted to `contents: read` |

---

## Testing & CI

DarkScan includes automated tests for its core scanning and security behavior.

- Finding metadata and JSON report tests (severity, CWE/OWASP mapping, safe JSON embedding)
- File scanner unit tests
- Web scanner SSRF/security tests
- Spring Boot application context test
- 51 automated tests currently passing
- GitHub Actions CI runs the test suite on pushes and pull requests to `main`
- Docker builds run the test suite before packaging the application

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Framework | Spring Boot 3.5.7 |
| Template Engine | Thymeleaf |
| Build Tool | Maven |
| Testing | JUnit 5 |
| CI | GitHub Actions |
| Containerization | Docker |
| Styling | Pure CSS |

---

## Run locally

```bash
git clone https://github.com/MIM-Isfak/DarkScan_app.git
cd DarkScan_app
./mvnw spring-boot:run
```

On Windows:

```powershell
.\mvnw.cmd spring-boot:run
```

Open → `http://localhost:8080`

---

## Run tests

```bash
./mvnw test
```

On Windows:

```powershell
.\mvnw.cmd test
```

---

## Run with Docker

```bash
docker build -t darkscan .
docker run --rm -p 8080:8080 darkscan
```

Open → `http://localhost:8080`

The container runs as a non-root user. The test suite runs during the image build.

---

## Architecture

```text
Browser
   │
HomeController (Spring MVC)
   │
   ├──────────────────┐
FileScanner      WebScanner
   └────────┬─────────┘
      ScanResult / Finding
             │
   Thymeleaf (result.html)
```

---

## Known limitations

- Secret detection is regex-based and may miss obfuscated secrets
- No persistent storage or user accounts
- Website scanning focuses on selected HTTP security checks and is not a full security audit
- Header checks do not consider context such as HSTS preload lists, so some findings may be informational for large sites
- SSRF protections use DNS pinning, but the DNS lookup itself is not covered by the 10-second scan deadline, and no network-level egress filtering is applied
- CWE and OWASP mappings are broad references and do not prove that a vulnerability is exploitable

---

## License

This project is licensed under the MIT License.