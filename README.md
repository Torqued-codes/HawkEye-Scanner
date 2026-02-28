# 🛡️ HawkEye Scanner - Web Application Vulnerability Scanner 

A comprehensive educational tool for learning about web application security vulnerabilities.

## ⚠️ Disclaimer :

IMPORTANT: This tool is designed strictly for educational purposes and security awareness training.

- Always obtain proper written authorization before testing any web application
- Unauthorized security testing is illegal and unethical
- Use only on systems you own or have explicit permission to test
- The developers assume no liability for misuse of this software


<img width="1919" height="940" alt="image" src="https://github.com/user-attachments/assets/525abcae-0737-49ea-b28d-be774d3e57eb" />


<img width="1919" height="940" alt="image" src="https://github.com/user-attachments/assets/cfde2e94-d5a7-459c-a5b3-fb3e37676c5b" />



## How To Use :

-Enter a URL in the input field
-Click "Start Scan"
-View real-time scan progress
-Review detailed results with severity levels

Example URLs to test:
https://google.com
https://torqtoken.netlify.app/

### Safe URL 1 :

<img width="1905" height="906" alt="image" src="https://github.com/user-attachments/assets/a6bf0a98-9237-43ee-8520-03796da42d0e" />
<img width="1901" height="942" alt="image" src="https://github.com/user-attachments/assets/283a5743-9e3f-4458-83af-788b550f93d3" />
<img width="1902" height="940" alt="image" src="https://github.com/user-attachments/assets/8865e2ef-ae19-474d-a6e7-ac51ccce9aef" />
<img width="1903" height="637" alt="image" src="https://github.com/user-attachments/assets/12776fa9-a858-42fc-bb6b-00cd144971ab" />


### Safe URL 2 :

<img width="1903" height="905" alt="image" src="https://github.com/user-attachments/assets/c6db15a9-c887-425d-b2cf-4411d95ff931" />
<img width="1901" height="942" alt="image" src="https://github.com/user-attachments/assets/b11b418f-6545-4439-a119-faebc99a88ef" />
<img width="1902" height="940" alt="image" src="https://github.com/user-attachments/assets/089f0818-018f-43d1-b82d-9ee5608349d5" />
<img width="1903" height="637" alt="image" src="https://github.com/user-attachments/assets/231a2d84-c26b-4f4b-82f7-a22e9af0c564" />


### Malicious URL :

<img width="1887" height="908" alt="Image" src="https://github.com/user-attachments/assets/b5c21ff4-fc7c-42a3-9ce6-aeaf4d9f1515" />

<img width="1879" height="914" alt="Image" src="https://github.com/user-attachments/assets/e88acf8f-0fa9-489e-b7d8-7a5c662c4c3a" />


## 🚀 Features

- **35 real-time threat detection checks** across multiple attack categories
- Animated scan progress with per-check feedback
- Visual threat score meter with color-coded risk levels (CLEAN → LOW → MODERATE → HIGH → CRITICAL)
- Results table sorted by severity with per-check descriptions
- Hover popup on any link on the page for instant threat preview
- Fully offline — no API calls, no data sent anywhere
- Responsive design for desktop and mobile


## 🔍 Vulnerability Detection — All 35 Checks

### 🔴 Critical Severity

#### 1. SQL Injection
Searches for common SQL injection patterns in the URL.
- Patterns: `'`, `"`, `OR 1=1`, `UNION SELECT`
- Targets URL parameters carrying malicious SQL syntax

#### 2. XSS (Cross-Site Scripting)
Detects script injection and event handler patterns.
- Patterns: `<script`, `javascript:`, `onerror=`, `onload=`
- Identifies attempts to inject executable code into web pages

#### 3. Command Injection
Flags shell command characters that could enable remote code execution.
- Patterns: `&&`, `$(`, `%7C` (pipe)
- Detects OS-level command injection attempts

#### 4. Fake Domain
Matches known brand-name typosquats used to impersonate trusted services.
- Examples: `paypa1`, `g00gle`, `arnazon`, `micros0ft`, `faceb00k`
- Catches character-swap lookalike domains

#### 5. Phishing Keywords
Detects phishing-specific keywords designed to trick users into entering credentials.
- Patterns: `login-verify`, `account-suspended`, `verify-now`, `webscr`, `signin-`
- Common in credential harvesting pages

#### 6. Data Theft Patterns
Identifies query parameters that transmit sensitive personal data.
- Patterns: `password=`, `creditcard=`, `ssn=`, `cvv=`, `cardnumber=`, `pin=`
- Flags URLs designed to exfiltrate private information

#### 7. Number-Letter Substitution
Detects leet-speak character swaps used to impersonate brands.
- Substitutions: `0→o`, `1→l`, `3→e`, `4→a`, `5→s`
- Example: `paypa1.com` or `g00gle.net`

#### 8. Brand Name in Subdomain
Detects brand names placed in subdomains to appear legitimate.
- Brands monitored: PayPal, Amazon, Facebook, Microsoft, Apple, Netflix, and more
- Example: `paypal.verify-account.xyz`

#### 9. Suspicious File Extension
Links directly to executable or script files are flagged as high-risk downloads.
- Extensions: `.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.scr`, `.msi`, `.jar`


### 🟠 High Severity

#### 10. HTTPS Check
Verifies the URL uses HTTPS to ensure data is encrypted in transit.
- Flags any URL beginning with `http://` instead of `https://`

#### 11. Directory Traversal
Detects path traversal sequences that may expose server file system contents.
- Patterns: `../`, `..\`, `%2e%2e`
- Identifies attempts to access parent directories on a server

#### 12. IP Address URL
URLs using raw IP addresses instead of domain names are a common phishing indicator.
- Pattern: `http://192.168.x.x` or any numeric IP in place of a hostname

#### 13. Suspicious TLD
Flags top-level domains frequently abused in phishing and malware campaigns.
- TLDs: `.xyz`, `.top`, `.club`, `.work`, `.click`, `.loan`, `.tk`, `.ml`, `.cf`, `.gq`, `.pw`

#### 14. High URL Entropy
High Shannon entropy in the hostname suggests algorithmically generated or obfuscated domains.
- Threshold: entropy > 3.8 bits
- Common in DGA (Domain Generation Algorithm) malware

#### 15. Excessive Subdomains
Six or more subdomain levels are unusual and often indicate domain abuse.
- Example: `a.b.c.d.e.evil.com`

#### 16. @ Symbol Trick
The `@` symbol in a URL causes browsers to treat everything before it as credentials, hiding the true destination.
- Example: `https://google.com@evil.com`

#### 17. Excessive Dots in Domain
Five or more dots in a hostname is a strong indicator of subdomain abuse or evasion.

#### 18. Hex Encoded Characters
Multiple percent-encoded characters in the path are used to bypass security filters.
- Threshold: 5 or more `%XX` sequences

#### 19. Urgency Words
Social engineering keywords designed to pressure users into immediate action.
- Patterns: `action-required`, `act-now`, `final-notice`, `account-locked`

#### 20. Numeric Subdomain
Subdomains made of long numeric strings suggest auto-generated attack infrastructure.
- Pattern: subdomain matching `[a-z]{0,2}\d{5,}`

#### 21. Auto-Generated Domain
Domains with random-looking alphanumeric names are often registered by malware or botnets.
- Detected via numeric density and domain length heuristics

#### 22. Encoded Hidden URL
Double-encoded URL segments used to evade signature-based detection systems.
- Patterns: `-2F`, `-2B`, `-3D`, `-2C`, `-3A` (encoded `/`, `+`, `=`, `,`, `:`)

#### 23. Nested URL in Parameter
A full URL embedded within a query parameter — a classic open-redirect payload.
- Parameters: `upn=`, `url=`, `u=`, `link=` with value length > 50

#### 24. Multiple Redirects
Two or more redirect-style parameters in a single URL indicate a chained redirect attack.
- Parameters checked: `redirect=`, `url=`, `next=`, `dest=`, `goto=`, `link=`, `target=`

#### 25. Suspicious Redirect Parameter
Redirect parameters with unusually long values used to send victims to attacker-controlled pages.
- Parameters: `upn=`, `url=`, `dest=`, `goto=`, `redir=` with query string > 100 chars

#### 26. SendGrid Redirect Abuse
Combines an email-service tracking domain with a click-tracking path — a known phishing delivery vector.
- Domains: `sendgrid.net`, `mailchimp.com`, `list-manage.com`
- Paths: `/ls/click`, `/click`, `/track/click`


### 🟡 Medium Severity

#### 27. Open Redirect
Flags redirect parameters that attackers use to forward victims to malicious sites.
- Patterns: `redirect=`, `next=`, `return=`, `dest=`, `goto=`

#### 28. URL Shortener
Identifies known URL shortening services which can obscure the true destination.
- Services: `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `rb.gy`, `is.gd`, and more

#### 29. Excessive URL Length
URLs over 150 characters are commonly used to hide malicious payloads within noise.

#### 30. Special Characters
Multiple occurrences of `@`, `#`, or `~` in a URL can be used to confuse URL parsers.
- Threshold: 3 or more such characters

#### 31. Deep URL Path
Deeply nested URL paths (more than 8 levels) are sometimes used to hide malicious endpoints.

#### 32. Free Hosting Platform
Free hosting services are widely abused to host phishing pages at zero cost.
- Platforms: `000webhostapp.com`, `weebly.com`, `wixsite.com`, `glitch.me`, `firebaseapp.com`

#### 33. Email Tracking Abuse
Email tracking service domains used to mask the true destination of a link.
- Domains: `sendgrid.net`, `mailchimp.com`, `mandrillapp.com`, `emltrk.com`

#### 34. Click Tracking Path
Paths used by click-tracking systems that can redirect users without revealing the destination.
- Paths: `/ls/click`, `/track/click`, `/wf/click`, `/lt.php`, `/click.php`

#### 35. Long Query String
Query strings exceeding 200 characters often carry encoded payloads or deeply nested redirect targets.


## 🔧 How It Works

1. User enters a URL into the input field and clicks **INITIATE SCAN**
2. The URL is normalized (protocol auto-added if missing)
3. All 35 checks run sequentially with animated progress feedback
4. Results are rendered in a table — threats sorted to the top by severity
5. A threat score arc updates with a color from green (clean) to red (critical)
6. Additionally, hovering over **any link** on the page triggers an instant popup risk summary powered by the same engine


## 📝 License :

This project is licensed under the MIT License - see the LICENSE file for details.
MIT License

Copyright (c) 2025 HawkEye Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# THANK YOU
