<div align="center">

# 🛡️ AZAD v1.1 (Beta Release)

**Windows Contextual Hardening & Exposure Auditor**

*120+ security checks with context-aware intelligence*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6.svg)](https://github.com/leoferrer15/azad)
[![Checks](https://img.shields.io/badge/security_checks-120+-green.svg)](https://github.com/leoferrer15/azad)

[Quick Start](#-quick-start) • [Architecture](#-architecture) • [AZAD Score](#-azad-score) • [Use Cases](#-use-cases)

</div>

---

## 🎯 What is AZAD?

**AZAD** is an enterprise-grade security analyzer for Windows endpoints that combines:

- **150+ security checks** (memory, authentication, network, PowerShell, accounts, system)
- **Context Intelligence** (detects EDR, Azure AD, Intune, domain, form factor)
- **Adaptive scoring** (adjusts risk based on real compensating controls)
- **100% defensive** (read-only, offline, agentless)

Unlike traditional scanners, AZAD **understands your environment** and gives accurate risk assessment.

---

## 🚨 The Problem
```
Traditional Scanners:
Laptop with CrowdStrike + Intune?    Score: 65/100 ⚠️
Unmanaged desktop?                    Score: 65/100 ⚠️

❌ No context awareness
❌ False positives
❌ Can't prioritize

AZAD:
Laptop with CrowdStrike + Intune?    AZAD Score: 18/100 ✅
Unmanaged desktop?                    AZAD Score: 72/100 🔴

✅ Context-aware
✅ Accurate priorities
```

---

## 🏗️ Architecture

**5 Core Layers:**

### 1️⃣ Context Engine
Auto-detects:
- Form Factor (Laptop/Desktop/Server/VM)
- Domain (Workgroup/Domain/Azure AD)
- Management (Intune/MDM)
- EDR (15+ products: CrowdStrike, SentinelOne, Defender ATP...)
- GPO Lockdown Level (0-100)

### 2️⃣ Analyzer Engine
**120+ checks:**
- **Memory**: LSASS PPL, Credential Guard, VBS/HVCI, WDigest
- **Auth**: NTLM/LM, SMB signing, RDP NLA, ASR rules
- **Network**: Port exposure, SMBv1, LLMNR/NetBIOS
- **PowerShell**: AMSI, CLM, Script Block Logging
- **Accounts**: Local admins, password policies
- **System**: Secure Boot, BitLocker, audit policies

### 3️⃣ Scoring Engine
Adaptive risk calculation:
```
Base Risk + Context Adjustments = AZAD Score

Example:
Base: +35 (missing controls)
- EDR detected: -15
- Intune: -10
- Azure AD: -5
- GPO HIGH: -10
= AZAD Score: 0/100 ✅
```

### 4️⃣ Reporting Engine
- **JSON** for SIEM/SOAR
- **HTML** dashboard with MITRE mapping
- Executive summary

### 5️⃣ Hardening Engine *(v3.0)*
- Automated remediation
- Reversible changes
- Stealth/Safe/Hard modes

---

## 🎯 AZAD Score

**The first context-aware endpoint security metric**

| Score | Rating | Risk Level |
|-------|--------|-----------|
| **0-25** | 🟢 EXCELLENT | Enterprise-grade |
| **26-50** | 🟡 GOOD | Above average |
| **51-75** | 🟠 NEEDS WORK | Notable gaps |
| **76-100** | 🔴 CRITICAL | Severe exposure |
| **100+** | ⚫ EMERGENCY | Isolate immediately |

**Real Examples:**
```
Fortune 500 Laptop (Intune + CrowdStrike):   12/100 ✅
SMB Domain PC (basic GPO):                    45/100 🟡
Home PC (no management):                      78/100 🔴
```

---

## 🚀 Quick Start
```bash
git clone https://github.com/leoferrer15/AZAD
git clone 
cd azad
python azad.py
```

**Sample Output:**
```
🧠 Context: LAPTOP | AZURE_AD | Intune ✅ | CrowdStrike ✅
⚖️  AZAD Score: 18/100 ✅ EXCELLENT
🎯 Top Priority: Disable SMBv1
📊 Reports: azad_report.html + .json
```

---

## 💎 Why AZAD?

| Feature | AZAD | CrowdStrike | Tanium | Qualys |
|---------|------|-------------|--------|--------|
| **Context-Aware** | ✅ | ❌ | ❌ | ❌ |
| **Offline/Agentless** | ✅ | ❌ | ❌ | ❌ |
| **EDR Detection** | ✅ 15+ | ❌ | ❌ | ❌ |
| **Open Source** | ✅ | ❌ | ❌ | ❌ |
| **Cost** | **Free** | High | Very High | High |

**Perfect for:**
- Incident response triage
- Air-gapped/OT environments
- BYOD assessments
- Compliance audits (NIST, CIS)
- MSP client reporting

---

## 🎯 Use Cases

**Blue Teams**: Rapid triage, posture tracking  
**Auditors**: Compliance evidence, gap analysis  
**Sysadmins**: GPO validation, baseline verification  
**MSPs**: Client benchmarking, value demonstration

---

## 🗺️ Roadmap

**v2.1** (Q1 2025): PDF export, unified reports, 25+ EDR detections  
**v2.2** (Q2 2025): CIS/MSFT baselines, drift detection  
**v3.0** (Q3 2025): Auto-hardening, rollback, "Get to Score 25" mode  
**v4.0** (2026): Fleet dashboard, API, remote scanning

[Full roadmap →](https://github.com/leoferrer15/azad/wiki/Roadmap)

---

## 🤝 Contributing

- ⭐ **Star this repo** to support the project
- 🐛 **Report bugs** via [Issues](https://github.com/leoferrer15/azad/issues)
- 💡 **Suggest features** via [Discussions](https://github.com/leoferrer15/azad/discussions)
- 🤝 **Contribute code** via Pull Requests

---

## 📝 License

MIT License - see [LICENSE](LICENSE)

**Why MIT?** Maximum freedom, enterprise-friendly, encourages adoption

---

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/azad/issues)
- **Twitter**: [@AZADSecurity](https://twitter.com/azadsecurity) (#AZADScore)
- **Email**: Azad.endpoint@gmail.com

---

<div align="center">

**Our Mission: Make AZAD Score the industry standard for endpoint security posture**

*Just like CVSS for vulnerabilities*

⭐ **Star if AZAD helps you assess endpoints accurately** ⭐

[Documentation](https://github.com/leoferrer15/azad/wiki) • [Whitepaper](docs/WHITEPAPER.md) • [Benchmarks](https://github.com/leoferrer15/azad/wiki/Benchmarks)

---
