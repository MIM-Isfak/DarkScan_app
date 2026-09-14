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

---

## Security fixes included

| Issue | Fix |
|---|---|
| XSS via filename/URL in results | `th:text` auto-escaping with Thymeleaf |
| SSRF via user-supplied URL | URL validation, DNS resolution, restricted-address checks, and redirects disabled |
| Null filename crash | Null-safe check before processing |

---

## Testing & CI

DarkScan includes automated tests for its core scanning and security behavior.

- File scanner unit tests
- Web scanner SSRF/security tests
- Spring Boot application context test
- 15 automated tests currently passing
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

## Architecture

```text
Browser
   │
HomeController (Spring MVC)
   │
   ├──────────────────┐
FileScanner      WebScanner
   └────────┬─────────┘
         ScanResult
             │
   Thymeleaf (result.html)
```

---

## Known limitations

- Secret detection is regex-based and may miss obfuscated secrets
- No persistent storage or user accounts
- Website scanning focuses on selected HTTP security checks and is not a full security audit
- SSRF protections mitigate common restricted-address targets but are not intended to provide complete protection against every DNS-rebinding scenario

---

## License

This project is licensed under the MIT License.