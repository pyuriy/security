# Secure Coding Cheat-Sheet: OWASP Top 10 (2025 RC1) & SANS/CWE Top 25 (2024)

This cheat-sheet provides a concise overview of key secure coding practices based on the latest OWASP Top 10 (Release Candidate 1, November 2025) and the SANS Institute's CWE Top 25 Most Dangerous Software Weaknesses (2024 edition, based on MITRE CWE). It focuses on high-level descriptions, common consequences, and practical mitigations to guide developers in building resilient applications. Use this as a quick reference during code reviews, threat modeling, and training.

## OWASP Top 10: 2025 RC1
The OWASP Top 10 highlights the most critical web application security risks, derived from global data on CVEs and community surveys. Focus on prevention through secure design, implementation, and verification.

| Rank | Category | Description | Key Mitigations |
|------|----------|-------------|-----------------|
| A01 | Broken Access Control | Users can act outside intended permissions, accessing unauthorized data or functions (e.g., IDOR, SSRF). Leads to data breaches or privilege escalation. | - Enforce least privilege and deny-by-default.<br>- Use server-side checks; avoid client-side enforcement.<br>- Implement rate limiting and API gateways. |
| A02 | Security Misconfiguration | Improper setup of security settings, defaults, or cloud/IaC configs exposes apps (e.g., open S3 buckets). Causes unauthorized access or DoS. | - Automate secure configs with IaC (e.g., Terraform).<br>- Remove unnecessary features/services.<br>- Use security headers (CSP, HSTS) and audit regularly. |
| A03 | Software Supply Chain Failures | Compromises in dependencies, CI/CD pipelines, or distribution (e.g., malicious packages). Results in tampered code or backdoors. | - Maintain SBOMs; scan dependencies (e.g., Dependabot).<br>- Sign artifacts and use trusted registries.<br>- Monitor for anomalies in build pipelines. |
| A04 | Cryptographic Failures | Weak or misused crypto exposes sensitive data (e.g., weak TLS, exposed secrets). Leads to data leaks or MITM attacks. | - Use strong algorithms (AES-256, SHA-256); avoid deprecated ones.<br>- Manage keys securely (e.g., vaults like AWS KMS).<br>- Enforce TLS 1.3+ and certificate pinning. |
| A05 | Injection | Untrusted input executes unintended commands (e.g., SQLi, XSS, command injection). Enables data theft or RCE. | - Use parameterized queries/prepared statements.<br>- Sanitize/escape outputs (e.g., OWASP ESAPI).<br>- Validate inputs strictly; use WAFs for runtime protection. |
| A06 | Insecure Design | Flaws in architecture or threat modeling (e.g., missing controls). Allows systemic exploits. | - Conduct threat modeling (e.g., STRIDE).<br>- Apply secure design patterns/reference architectures.<br>- Integrate security in SDLC from requirements. |
| A07 | Authentication Failures | Weak session management or credential handling (e.g., brute-force, session fixation). Leads to account takeovers. | - Use multi-factor auth (MFA) and secure password hashing (bcrypt).<br>- Implement secure session tokens (e.g., HttpOnly, Secure flags).<br>- Rate-limit login attempts. |
| A08 | Software or Data Integrity Failures | Lack of integrity checks on code/data updates (e.g., unsigned updates). Causes supply chain attacks or tampering. | - Verify checksums/signatures for updates.<br>- Use CI/CD with integrity gates (e.g., sigstore).<br>- Enforce content integrity (e.g., SRI for JS). |
| A09 | Logging & Alerting Failures | Insufficient monitoring obscures attacks (e.g., no logs for anomalies). Delays detection. | - Log security events (auth, access denials) without sensitive data.<br>- Integrate SIEM; set alerts for thresholds.<br>- Ensure logs are tamper-proof and retained. |
| A10 | Mishandling of Exceptional Conditions | Poor error handling leaks info or causes DoS (e.g., stack traces exposed). Aids reconnaissance or crashes. | - Use generic error messages; log details internally.<br>- Implement graceful degradation and input validation.<br>- Test for edge cases in resilience testing. |

## SANS/CWE Top 25: 2024
The SANS Top 25 (powered by MITRE CWE) ranks software weaknesses by prevalence and impact in CVEs. Emphasizes root causes across languages; prioritize in static analysis and training.

| Rank | CWE-ID | Name | Description | Key Mitigations |
|------|--------|------|-------------|-----------------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | Untrusted input rendered in web pages executes malicious scripts. Steals sessions/data. | - Escape outputs contextually (HTML, JS).<br>- Use CSP headers.<br>- Sanitize inputs with libraries (e.g., DOMPurify). |
| 2 | CWE-787 | Out-of-bounds Write | Writing beyond buffer bounds corrupts memory. Enables RCE or crashes. | - Use safe functions (e.g., strncpy); bounds-check inputs.<br>- Employ memory-safe languages (Rust, Go).<br>- Static analysis tools (e.g., Coverity). |
| 3 | CWE-89 | SQL Injection | Unsanitized input alters SQL queries. Dumps/exposes DB data. | - Parameterized queries/ORMs (e.g., PDO).<br>- Least privilege DB accounts.<br>- Input validation and WAF. |
| 4 | CWE-352 | Cross-Site Request Forgery (CSRF) | Forged requests trick users into actions. Performs unauthorized ops. | - Anti-CSRF tokens.<br>- SameSite cookies.<br>- Check referer/origin headers. |
| 5 | CWE-22 | Path Traversal | Input manipulates file paths to access restricted files. Leaks sensitive data. | - Canonicalize paths; validate against allowlists.<br>- Use chroot/jail.<br>- Absolute paths in code. |
| 6 | CWE-125 | Out-of-bounds Read | Reading beyond buffer leaks memory. Exposes sensitive info. | - Bounds checking on reads.<br>- Memory-safe practices.<br>- Fuzz testing. |
| 7 | CWE-78 | OS Command Injection | Input executes arbitrary OS commands. Full system compromise. | - Avoid shell calls; use APIs/exec with args.<br>- Escape/validate inputs.<br>- Run in sandbox. |
| 8 | CWE-416 | Use After Free | Accessing freed memory causes corruption/crashes. RCE potential. | - Smart pointers (C++); ownership models.<br>- Static/dynamic analysis.<br>- Avoid manual free. |
| 9 | CWE-862 | Missing Authorization | No checks allow unauthorized access to resources. Data exposure. | - Enforce authz at every endpoint.<br>- Role-based access control (RBAC).<br>- Audit logs. |
| 10 | CWE-434 | Unrestricted Upload of File with Dangerous Type | Malicious files uploaded execute/arbitrary access. Server compromise. | - Validate/scan uploads (type, size).<br>- Store outside web root; rename files.<br>- Antivirus integration. |
| 11 | CWE-94 | Code Injection | Input alters code execution (e.g., eval). RCE. | - Avoid dynamic code eval.<br>- Sandbox execution.<br>- Input validation. |
| 12 | CWE-20 | Improper Input Validation | Unchecked inputs cause overflows/injections. Various exploits. | - Whitelist validation.<br>- Type coercion.<br>- Fuzzing. |
| 13 | CWE-77 | Command Injection | Similar to CWE-78; special chars in commands. RCE. | - Parameterized execution.<br>- Escape metachars. |
| 14 | CWE-287 | Improper Authentication | Weak/bypassed auth. Unauthorized access. | - Strong creds/MFA.<br>- Secure protocols (OAuth).<br>- Timeout sessions. |
| 15 | CWE-269 | Improper Privilege Management | Over-privileging leads to escalation. | - Least privilege principle.<br>- Just-in-time access. |
| 16 | CWE-502 | Deserialization of Untrusted Data | Malicious serialized objects execute code. RCE. | - Avoid deserializing untrusted data.<br>- Use safe formats (JSON).<br>- Sign payloads. |
| 17 | CWE-200 | Exposure of Sensitive Information | Leaks via errors/logs. Aids attacks. | - Generic errors; mask secrets.<br>- Data classification. |
| 18 | CWE-863 | Incorrect Authorization | Flawed checks allow improper access. | - Centralized authz logic.<br>- Model testing. |
| 19 | CWE-918 | Server-Side Request Forgery (SSRF) | App makes unauthorized requests. Internal scans/data access. | - Whitelist URLs.<br>- Network segmentation. |
| 20 | CWE-119 | Improper Restriction of Operations within Bounds of Memory Buffer | Buffer issues (general). Crashes/RCE. | - Bounds-checked ops.<br>- ASLR/DEP. |
| 21 | CWE-476 | NULL Pointer Dereference | Crashes on null refs. DoS. | - Null checks.<br>- Optional types (e.g., Rust Option). |
| 22 | CWE-798 | Use of Hard-coded Credentials | Exposed creds in code. Easy compromise. | - Env vars/secrets managers.<br>- Config files (encrypted). |
| 23 | CWE-190 | Integer Overflow or Wraparound | Math errors cause overflows. Buffer issues. | - Safe math libs (e.g., checked_add).<br>- Type limits. |
| 24 | CWE-400 | Uncontrolled Resource Consumption | Exhausts resources (DoS). | - Rate limiting/quotas.<br>- Resource pools. |
| 25 | CWE-306 | Missing Authentication for Critical Function | Unprotected sensitive ops. Unauthorized use. | - Always require auth.<br>- API keys/tokens. |

## Quick Tips for Implementation
- **Tools**: Integrate SAST (SonarQube), DAST (Burp), SCA (Snyk) in CI/CD.
- **Best Practices**: Adopt OWASP ASVS for verification; use CWE views in code reviews.
- **Training**: Focus on top 5 in both lists for 80% coverage of risks.
- **Metrics**: Track remediation time; aim for <30 days for criticals.

For deeper dives, visit [OWASP Top 10](https://owasp.org/Top10/) and [CWE Top 25](https://cwe.mitre.org/top25/). Stay updated as OWASP 2025 finalizes post-RC feedback.
