# Comprehensive Secure Coding Practice Lab: OWASP Top 10 (2025 RC1) & SANS/CWE Top 25 (2024)

This practice lab is designed for developers, security engineers, and students to hands-on explore, exploit, and remediate the most critical web and software weaknesses. It integrates exercises from both OWASP Top 10 (2025 Release Candidate 1) and SANS/CWE Top 25 (2024), highlighting overlaps (e.g., Injection covers CWE-89 SQL Injection and CWE-79 XSS). 

**Objectives:**
- Identify vulnerabilities in code and running apps.
- Exploit them safely in controlled environments.
- Implement and verify fixes.
- Measure impact via metrics like exploit success rate and remediation time.

**Estimated Time:** 20-30 hours (modular; 1-2 hours per exercise).
**Prerequisites:** Basic programming (Python/Java/JS), Docker, Burp Suite/ZAP (free community editions), and Git.
**Safety Note:** Run all labs in isolated VMs/Docker; never on production systems.

## Lab Setup
1. **Install Tools:**
   - Docker: For containerized vulnerable apps.
   - OWASP ZAP/Burp Suite: Proxy for scanning/exploiting.
   - Git: Clone repos.
   - IDE (VS Code): For code editing.

2. **Core Vulnerable Apps (Free/Open-Source):**
   - **OWASP Juice Shop** (covers ~80% OWASP Top 10): `docker run -p 3000:3000 bkimminich/juice-shop`
     - Access: http://localhost:3000
   - **Damn Vulnerable Web Application (DVWA)** (PHP-based, great for injections): 
     - Clone: `git clone https://github.com/digininja/DVWA.git`
     - Setup: Follow README (MySQL + Apache via XAMPP/Docker).
   - **WebGoat** (Java/Spring, OWASP-focused): `docker run -p 8080:8080 webgoat/webgoat`
     - Access: http://localhost:8080/WebGoat
   - **For CWE Low-Level (e.g., Buffer Overflows):** DVARC (Damn Vulnerable ARM Router) or VulnHub VMs.
   - **Integrated Platforms:**
     - TryHackMe OWASP Top 10 2025 Module: Free/paid rooms with browser-based labs (e.g., exploit Insecure Data Handling via SSTI).
     - Immersive Labs OWASP 2025 Collection: 11 quick labs (sign-up required; covers new categories like Software Supply Chain).
     - Veracode Security Labs: CWE-tagged exercises in Java/Node/Python (free trial).

3. **Tracking Progress:** Use a checklist table (copy to Markdown/Excel). Log exploits/fixes with screenshots.

| Category | Exercise Completed? | Exploit Success | Fix Verified | Notes |
|----------|---------------------|-----------------|--------------|-------|
| A01: Broken Access Control | ☐ | ☐ | ☐ | |

## Exercises: OWASP Top 10 (2025 RC1)
Each exercise includes: **Scenario**, **Vulnerable Code Snippet**, **Exploit Steps**, **Remediation**, **CWE Overlap**, and **Advanced Challenge**. Run in Juice Shop/DVWA/WebGoat unless noted.

### A01: Broken Access Control (CWE-862 Missing Authz, CWE-269 Improper Privilege Mgmt)
**Scenario:** User can view/edit others' profiles via ID manipulation (IDOR).
- **App:** Juice Shop > "Profile" endpoint.
- **Vulnerable Code (Node.js/Express):**
  ```javascript
  app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id; // No auth check
    res.json(users[userId]); // Returns any user's data
  });
  ```
- **Exploit Steps:**
  1. Login as user1 (ID=1).
  2. Intercept request in ZAP/Burp: Change `id=1` to `id=2`.
  3. View user2's sensitive data (e.g., email).
- **Remediation:**
  - Add server-side check: `if (req.user.id !== parseInt(userId)) return 403;`
  - Use RBAC libraries (e.g., express-rbac).
- **CWE Overlap:** #9 (CWE-862), #15 (CWE-269).
- **Advanced:** In WebGoat "Access Control Matrix," implement role-based fixes; test with OWASP ZAP active scan.

### A02: Security Misconfiguration (CWE-16 Config Data in Code, CWE-798 Hard-coded Creds)
**Scenario:** Exposed debug endpoints or default creds in cloud config.
- **App:** DVWA > Setup with default MySQL root/no-pass.
- **Vulnerable Code (PHP):**
  ```php
  $db = new PDO('mysql:host=localhost;dbname=dvwa', 'root', ''); // Empty password
  error_reporting(E_ALL); // Debug mode on prod
  ```
- **Exploit Steps:**
  1. Scan with ZAP: Detect open /phpinfo.php.
  2. Login as admin/root (default creds).
  3. Dump DB schema.
- **Remediation:**
  - Use env vars: `$pass = getenv('DB_PASS');`
  - Disable debug: `error_reporting(0);` in prod; add CSP headers.
- **CWE Overlap:** #22 (CWE-798).
- **Advanced:** Deploy misconfigured AWS S3 bucket via Terraform; exploit with boto3 Python script.

### A03: Software Supply Chain Failures (CWE-502 Deserialization, New in 2025)
**Scenario:** Malicious npm package injects backdoor.
- **App:** Custom Node project; install fake vuln package.
- **Vulnerable Code:**
  ```javascript
  const maliciousPkg = require('fake-vuln-package'); // From untrusted source
  maliciousPkg.exec('rm -rf /'); // Hidden in dep
  ```
- **Exploit Steps:**
  1. `npm install fake-vuln-package`
  2. Run app; observe RCE (simulate with echo command).
  3. Use Snyk to scan: `snyk test`.
- **Remediation:**
  - SBOM with `npm ls --json`; sign with npm audit.
  - Lock deps: `npm ci`; use verified registries.
- **CWE Overlap:** #16 (CWE-502).
- **Advanced:** In Immersive Labs, tamper a CI/CD pipeline; fix with sigstore.

### A04: Cryptographic Failures (CWE-327 Broken Crypto)
**Scenario:** Weak hashing exposes passwords.
- **App:** WebGoat > Crypto lessons.
- **Vulnerable Code (Java):**
  ```java
  MessageDigest md = MessageDigest.getInstance("MD5");
  byte[] hash = md.digest(password.getBytes()); // MD5 unsalted
  ```
- **Exploit Steps:**
  1. Capture login hash via MITM (Fiddler).
  2. Rainbow table crack (hashcat: `hashcat -m 0 hash.txt rockyou.txt`).
- **Remediation:**
  - Use PBKDF2/Argon2: `PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, 256);`
  - Enforce TLS 1.3.
- **CWE Overlap:** #4 (CWE-327 implied).
- **Advanced:** TryHackMe room: Brute-force weak key with Burp.

### A05: Injection (CWE-79 XSS, CWE-89 SQLi, CWE-78 Command Inj)
**Scenario:** Unsanitized search executes SQL/JS/commands.
- **App:** DVWA > SQL Injection (low security).
- **Vulnerable Code (PHP):**
  ```php
  $query = "SELECT * FROM users WHERE name = '$input'";
  $result = mysqli_query($conn, $query); // No params
  echo "<script>alert('$input')</script>"; // XSS
  ```
- **Exploit Steps:**
  1. SQLi: Input `' OR 1=1 --`; dump users.
  2. XSS: `<script>alert('XSS')</script>`.
  3. Command: `; ls -la` in ping tool.
- **Remediation:**
  - PDO params: `$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?"); $stmt->execute([$input]);`
  - Escape: `htmlspecialchars($input, ENT_QUOTES)`.
- **CWE Overlap:** #1 (79), #3 (89), #7 (78).
- **Advanced:** SSTI in TryHackMe: `{{7*7}}` on Jinja template.

### A06: Insecure Design (CWE-20 Input Validation)
**Scenario:** No threat model; missing MFA in auth flow.
- **App:** Juice Shop > Login bypass via logic flaw.
- **Vulnerable Code:**
  ```javascript
  if (email && password) { // No rate limit or MFA
    loginUser(email, password);
  }
  ```
- **Exploit Steps:**
  1. Brute-force with Hydra: `hydra -l admin -P rockyou.txt localhost http-post-form "/login:email=^USER^&password=^PASS^"`.
- **Remediation:**
  - STRIDE modeling; add MFA (e.g., speakeasy npm).
  - Input whitelist: `if (!validator.isEmail(input)) return 400;`.
- **CWE Overlap:** #12 (20).
- **Advanced:** Design a secure login in WebGoat; peer review.

### A07: Authentication Failures (CWE-287 Improper Auth)
**Scenario:** Session fixation post-login.
- **App:** DVWA > Weak Session IDs.
- **Vulnerable Code:**
  ```php
  session_id($_GET['sid']); // Fixates session
  session_start();
  ```
- **Exploit Steps:**
  1. Set sid=attacker_session pre-login.
  2. Login as victim; hijack session.
- **Remediation:**
  - Regenerate: `session_regenerate_id(true);`
  - Secure flags: `session_set_cookie_params(['secure'=>true, 'httponly'=>true]);`.
- **CWE Overlap:** #14 (287).
- **Advanced:** Implement OAuth2 in Spring Boot.

### A08: Software/Data Integrity Failures (CWE-345 Insufficient Verification)
**Scenario:** Unsigned JS updates tampered.
- **App:** Custom HTML with external script.
- **Vulnerable Code:**
  ```html
  <script src="https://untrusted.com/script.js"></script> <!-- No SRI -->
  ```
- **Exploit Steps:**
  1. Intercept and inject `alert('XSS')`.
- **Remediation:**
  - Subresource Integrity: `<script src="..." integrity="sha256-abc123" crossorigin="anonymous"></script>`.
- **CWE Overlap:** #8 (345).
- **Advanced:** Verify Docker images with cosign.

### A09: Logging & Alerting Failures
**Scenario:** No logs for failed logins; undetected brute-force.
- **App:** WebGoat > Audit lessons.
- **Vulnerable Code (Java):**
  ```java
  try {
    authenticate(user);
  } catch (Exception e) {
    // Silent fail; no log
  }
  ```
- **Exploit Steps:**
  1. Brute-force undetected.
  2. Check logs: Empty.
- **Remediation:**
  - Log4j: `logger.warn("Failed login for {}", user);`
  - Alert on >5 fails/min via ELK stack.
- **CWE Overlap:** #17 (200 Exposure via logs).
- **Advanced:** Integrate Splunk; simulate attack.

### A10: Mishandling Exceptional Conditions (CWE-476 NULL Dereference)
**Scenario:** Stack trace leaks DB info on error.
- **App:** Juice Shop > Error pages.
- **Vulnerable Code:**
  ```javascript
  try {
    db.query(sql);
  } catch (e) {
    res.send(e.stack); // Leaks paths
  }
  ```
- **Exploit Steps:**
  1. Trigger 500; read trace for recon.
- **Remediation:**
  - Generic: `res.status(500).send('Internal Error'); logger.error(e);`
- **CWE Overlap:** #21 (476).
- **Advanced:** Fuzz with ffuf for crashes.

## Exercises: SANS/CWE Top 25 (Unique/Deep Dives)
Focus on non-web (e.g., C/C++ for memory issues). Use DVWA for web overlaps.

| Rank | CWE | Exercise Summary | Tools/App | Key Steps |
|------|-----|------------------|-----------|-----------|
| 2 | CWE-787 Out-of-bounds Write | Buffer overflow in C app. | Damn Vulnerable C: `gcc vuln.c -o vuln -fno-stack-protector` | Input 1024 chars >100 buf; crash/overwrite return addr. Fix: `strncpy(buf, input, sizeof(buf)-1);`. |
| 4 | CWE-352 CSRF | Forged transfer form. | DVWA CSRF module. | Craft HTML: `<form action="transfer.php" method="post">...</form>`; clickjack. Fix: Token `<input name="csrf" value="<?php echo $_SESSION['token']; ?>">`. |
| 6 | CWE-125 Out-of-bounds Read | Leak via memcpy overrun. | Custom C: `memcpy(buf, src, size+10);` | Read secret after buf; hexdump. Fix: `memcpy(buf, src, min(size, sizeof(buf)));`. |
| 8 | CWE-416 Use After Free | Double-free in malloc. | Valgrind on vuln C code. | `free(ptr); *ptr=1;` segfault. Fix: `if (ptr) free(ptr); ptr=NULL;`. |
| 10 | CWE-434 Dangerous File Upload | Exec uploaded shell.php. | DVWA File Upload. | Upload `<?php system($_GET['cmd']); ?>`; access /hack.php?cmd=ls. Fix: `if (!in_array(pathinfo($file, PATHINFO_EXTENSION), ['jpg','png'])) reject;`. |
| 16 | CWE-502 Deserialization | Gadget chain RCE. | ysoserial + Java app. | Serialize payload: `java -jar ysoserial CommonsCollections1 "cmd /c calc.exe" > payload.ser`; deserialize. Fix: Use JSON/Gson. |
| 22 | CWE-798 Hard-coded Creds | Git commit leaks API key. | Scan repo with truffleHog. | `grep -r "password" .`; commit fix to .env. |
| 23 | CWE-190 Integer Overflow | Alloc too small buffer. | C: `size_t len = user_len + 10; char* buf = malloc(len);` (if user_len=UINT_MAX). | Input max int; overflow. Fix: `if (len > SIZE_MAX - 10) error;`. |

**Advanced CWE Challenges:** Use Veracode Labs for language-specific (e.g., Python Flask buffer in #20). Cybrary Secure Coding course has 12 modules with OWASP/CWE labs.

## Debrief & Best Practices
- **Metrics:** Time to exploit (<5 min goal), fix verification (re-scan passes).
- **Tools Integration:** CI/CD with SonarQube for SAST; OWASP Dependency-Check for SCA.
- **Extensions:** Port exercises to your codebase; conduct team CTFs.
- **Resources:** 
  - TryHackMe for guided walkthroughs.
  - Immersive Labs for rapid 2025 updates.
  - SANS Top 25 Resources: Courses & posters.

Repeat labs quarterly; contribute fixes to open-source vuln apps. For updates post-OWASP final release (expected Dec 2025), revisit A03/A08.
