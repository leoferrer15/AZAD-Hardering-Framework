# Security Policy

## 🛡️ Overview

**AZAD (Adaptive Zero-Trust Audit Defender)** is a defensive, read-only security auditor. It performs security assessments without making any system modifications. However, like any security tool, it's important to use it responsibly and report any security concerns.

---

## 🔐 Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.1.x   | ✅ Yes             | Current stable release |
| 1.0.x   | ⚠️ Limited support | Internal pre-release (deprecated) |
| < 1.0   | ❌ No              | Unsupported |

**Recommendation:** Always use the latest release from [GitHub Releases](https://github.com/leoferrer15/azad/releases).

---

## 🚨 Reporting a Vulnerability

### **⚠️ CRITICAL: DO NOT open a public GitHub issue for security vulnerabilities**

Public disclosure of security issues puts all users at risk. Instead:

### **Preferred Contact Method:**

📧 **Email:** [azad.endpoint@gmail.com]

**Subject Line Format:** `[SECURITY] AZAD - Brief Description`

**Example:** `[SECURITY] AZAD - Potential code injection in report generation`

---

### **What to Include in Your Report:**

Please provide as much information as possible:
```
1. DESCRIPTION
   - Clear description of the vulnerability
   - Type of issue (code injection, privilege escalation, data leak, etc.)

2. IMPACT
   - Who is affected? (all users, admin-only, specific Windows versions)
   - What can an attacker do?
   - Severity assessment (Critical/High/Medium/Low)

3. REPRODUCTION STEPS
   - Detailed steps to reproduce the issue
   - Test environment (Windows version, Python version, AZAD version)
   - Proof of concept code (if applicable)

4. SUGGESTED FIX (Optional)
   - Your recommendations for remediation
   - Code patches (if you have them)

5. DISCLOSURE TIMELINE
   - Your preferred disclosure timeline
   - Any constraints (conferences, publications, etc.)
```

---

### **What Happens Next:**

| Timeline | Action |
|----------|--------|
| **Within 48 hours** | We'll acknowledge receipt of your report |
| **Within 7 days** | Initial assessment and severity classification |
| **Within 30 days** | Fix developed and tested (for High/Critical issues) |
| **Within 90 days** | Public disclosure coordinated with you |

---

### **Responsible Disclosure:**

We follow **coordinated disclosure** principles:

- ✅ We will NOT publicly disclose the vulnerability until a fix is available
- ✅ We will credit you in `CHANGELOG.md` and release notes (unless you prefer anonymity)
- ✅ We will coordinate disclosure timing with you
- ✅ We will provide you with advance notice before public release

---

### **Bug Bounty:**

⚠️ **AZAD is an open-source project with no funding.** We currently do not offer monetary rewards, but we will:

- 🏆 Credit you prominently in release notes
- 🏆 Add you to our `CONTRIBUTORS.md` hall of fame
- 🏆 Publicly thank you (if you want)
- 🏆 Provide a detailed write-up of the fix for your portfolio

---

## 🔍 Security Best Practices for AZAD Users

### **1. Download Safety**

✅ **DO:**
- Download AZAD only from official GitHub releases
- Verify file integrity (checksums provided in releases)
- Review code before running (it's open-source!)

❌ **DON'T:**
- Download from third-party sites
- Run modified versions from unknown sources
- Disable antivirus to run AZAD (shouldn't be necessary)

---

### **2. Execution Safety**

✅ **DO:**
- Run AZAD as Administrator for complete checks (it's read-only)
- Review what AZAD is checking (see `docs/USAGE.md`)
- Understand that AZAD inspects LSASS (this is normal for security tools)

❌ **DON'T:**
- Run AZAD from untrusted sources
- Modify the code unless you understand the implications
- Share raw reports publicly (they contain sensitive system info)

---

### **3. Report Handling**

✅ **DO:**
- Review reports before sharing
- Redact sensitive information (hostnames, usernames, domain names)
- Store reports securely
- Delete reports after remediation

❌ **DON'T:**
- Upload reports to public paste sites
- Email reports over unencrypted channels
- Share reports with unauthorized personnel
- Commit reports to version control (`.gitignore` protects you)

---

### **4. EDR/Antivirus Considerations**

⚠️ **AZAD may trigger EDR/AV alerts due to:**

1. **LSASS Inspection:** AZAD checks if LSASS is running as PPL (Protected Process Light)
   - ✅ This is **read-only** inspection
   - ✅ AZAD does NOT dump credentials
   - ✅ False positive - AZAD is defensive-only

2. **Registry Enumeration:** AZAD queries security-related registry keys
   - ✅ This is standard for security auditors
   - ✅ Read-only access

3. **Process Enumeration:** AZAD lists running processes to detect EDR
   - ✅ Standard system monitoring
   - ✅ No injection or manipulation

**If your EDR blocks AZAD:**
- Review the alert details
- Whitelist `azad.py` if your security policy allows
- Contact your security team for approval
- Report false positives to your EDR vendor

---

## 🛠️ AZAD Security Architecture

### **Design Principles:**
```
✅ READ-ONLY: AZAD never modifies system configuration
✅ NO NETWORK: AZAD runs 100% offline (no data exfiltration)
✅ NO CREDENTIALS: AZAD never collects passwords or secrets
✅ TRANSPARENT: All source code is open for audit
✅ MINIMAL DEPS: Only pywin32 required (reduces attack surface)
```

---

### **What AZAD Does NOT Do:**

❌ Does NOT exploit vulnerabilities  
❌ Does NOT dump credentials from LSASS  
❌ Does NOT bypass security controls  
❌ Does NOT make registry changes  
❌ Does NOT disable security software  
❌ Does NOT send data over network  
❌ Does NOT require elevated privileges (but recommends it for complete checks)  

---

### **What AZAD DOES Do:**

✅ Reads registry keys (same as Group Policy Editor)  
✅ Queries Windows APIs (same as Task Manager)  
✅ Inspects process attributes (same as Process Explorer)  
✅ Enumerates services (same as `sc query`)  
✅ Checks firewall status (same as `netsh advfirewall`)  
✅ Generates local reports (JSON + HTML)  

---

## 🔬 Security Audit History

### **Known Issues (Fixed):**

| Issue | Severity | Fixed In | Details |
|-------|----------|----------|---------|
| None yet | - | - | First public release (v1.1.0) |

---

### **Third-Party Security Reviews:**

We welcome security audits! If you've reviewed AZAD:
- Contact us to be listed here
- We'll link to your public audit report
- Help make AZAD more secure for everyone

---

## 🧪 Security Testing

### **Testing Scope:**

If you're security testing AZAD, here are areas of interest:

1. **Code Injection:**
   - JSON report generation
   - HTML report generation
   - Session name handling

2. **Path Traversal:**
   - Report file naming
   - Log file creation

3. **Privilege Escalation:**
   - Admin checks
   - Registry access
   - Process inspection

4. **Information Disclosure:**
   - Error messages
   - Report content
   - Debug output

5. **Denial of Service:**
   - Resource exhaustion
   - Infinite loops
   - Memory leaks

---

## 📚 Additional Resources

- **Documentation:** [docs/](docs/)
- **FAQ:** [docs/FAQ.md](docs/FAQ.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Code of Conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

## 📞 Contact

- **Security Issues:** [azad.endpoint@gmail.com]
- **General Support:** [GitHub Issues](https://github.com/leoferrer15/azad/issues)
- **Discussions:** [GitHub Discussions](https://github.com/leoferrer15/azad/discussions)

---

## 🙏 Acknowledgments

We thank the following security researchers for responsible disclosure:

*(None yet - be the first!)*

---

## 📜 Legal

AZAD is provided "AS IS" without warranty. See [LICENSE](LICENSE) for details.

**This tool is intended for:**
- Security auditors
- System administrators
- Blue teams
- Compliance teams
- Security researchers

**This tool is NOT intended for:**
- Unauthorized system access
- Malicious activities
- Violation of terms of service
- Bypassing security controls

**By using AZAD, you agree to use it responsibly and ethically.**

---

**Last Updated:** 2025-01-15  
**Version:** 1.1.0
