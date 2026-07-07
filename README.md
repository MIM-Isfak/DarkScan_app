# [DarkScan]
### A security analysis tool built with Java & Spring Boot

![Java](https://img.shields.io/badge/Java-17-orange?style=flat-square&logo=java)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.7-brightgreen?style=flat-square&logo=springboot)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

> Scan files and websites for common security vulnerabilities.

---
## Screenshots

![Home Page](Screenshot%202026-07-05%20224559.png)

![File Scan Result](Screenshot%202026-07-05%20224648.png)

![SSRF Protection](Screenshot%202026-07-05%20224748.png)

## What it does

**File Scan**
- Detects sensitive filenames (`.env`, `id_rsa`, `.pem`, `.key`, `config.php`)
- Scans file contents line-by-line for leaked secrets:
  - AWS Access Keys / Secret Keys
  - Hardcoded passwords
  - API keys & Bearer tokens
  - GitHub personal access tokens
  - Private key blocks

**Website Scan**
- Checks for missing HTTP security headers:
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options`
- Warns if site uses plain HTTP instead of HTTPS
- Detects `Server` header information leakage
- **SSRF protection** — blocks scanning of localhost, loopback, private network, and cloud metadata addresses (`169.254.169.254`)

---

## Security fixes included

| Issue | Fix |
|-------|-----|
| XSS via filename/URL in results | `th:text` auto-escaping (Thymeleaf) |
| SSRF via user-supplied URL | Host resolved & checked before any HTTP request |
| Null filename crash | Null-safe check before processing |
| README claiming features that didn't exist | Rewrote README to match actual code |

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Java 17 |
| Framework | Spring Boot 3.5.7 |
| Template Engine | Thymeleaf |
| Build Tool | Maven |
| Styling | Pure CSS (dark theme, no frameworks) |

---

## Run locally

```bash
git clone https://github.com/MIM-Isfak/DarkScan.git
cd DarkScan_app
./mvnw spring-boot:run
```

Open → http://localhost:8080

---

## Architecture

```text
Browser
   │
   ▼
HomeController (Spring MVC)
   │
   ├──────────────────┐
   ▼                  ▼
FileScanner      WebScanner
   │                  │
   └────────┬─────────┘
            ▼
        ScanResult
            │
            ▼
   Thymeleaf (result.html)
```

---

## Known limitations

- Secret detection is regex-based — can miss obfuscated secrets
- No persistent storage or user accounts
- Website scan checks headers only, not full security audit

---

*Built by [@MIM-Isfak](https://github.com/MIM-Isfak)*
