# 🛡️ HawkEye Scanner - Web Application Vulnerability Scanner 

A comprehensive educational tool for learning about web application security vulnerabilities.

## ⚠️ Disclaimer :

IMPORTANT: This tool is designed strictly for educational purposes and security awareness training.

- Always obtain proper written authorization before testing any web application
- Unauthorized security testing is illegal and unethical
- Use only on systems you own or have explicit permission to test
- The developers assume no liability for misuse of this software


<img width="1919" height="943" alt="image" src="https://github.com/user-attachments/assets/0d27b0e6-bf47-4a08-9832-8dca33f98c76" />



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

<img width="1904" height="940" alt="image" src="https://github.com/user-attachments/assets/4fdaf269-2ff7-4e66-b52c-20e5965e9680" />

<img width="1901" height="945" alt="image" src="https://github.com/user-attachments/assets/d5a40e73-da50-41ea-8d7c-80dba580ffcb" />

<img width="1903" height="640" alt="image" src="https://github.com/user-attachments/assets/87687998-c26f-4cbd-a16d-de2d0ac25797" />


### Safe URL 2 :

<img width="1903" height="905" alt="image" src="https://github.com/user-attachments/assets/c6db15a9-c887-425d-b2cf-4411d95ff931" />
<img width="1887" height="915" alt="Image" src="https://github.com/user-attachments/assets/cc2830d9-6150-4caa-8ae6-651655858659" />


### Malicious URL :

<img width="1887" height="908" alt="Image" src="https://github.com/user-attachments/assets/b5c21ff4-fc7c-42a3-9ce6-aeaf4d9f1515" />

<img width="1879" height="914" alt="Image" src="https://github.com/user-attachments/assets/e88acf8f-0fa9-489e-b7d8-7a5c662c4c3a" />


## 🌟 Features :

6 Vulnerability Detection Tests:

- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- HTTPS/SSL verification
- Directory Traversal detection
- Command Injection detection
- Open Redirect detection

## 🔧 How It Works :

Vulnerability Detection Methods

### 1. SQL Injection

Searches for common SQL injection patterns: ', ", OR 1=1, UNION SELECT
Checks URL parameters for suspicious SQL syntax

### 2. Cross-Site Scripting (XSS)

Detects script tags, JavaScript protocols, event handlers
Patterns: <script>, javascript:, onerror=, onload=

### 3. HTTPS/SSL Check

Verifies if URL uses HTTPS protocol
Flags HTTP connections as medium severity

### 4. Directory Traversal

Looks for path traversal patterns: ../, ..\\, %2e%2e
Identifies attempts to access parent directories

### 5. Command Injection

Detects shell command characters: |, ;, &, `, $
Flags potential OS command injection attempts

### 6. Open Redirect

Searches for redirect parameters: redirect=, url=, next=
Identifies potential open redirect vulnerabilities


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
