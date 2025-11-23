#!/usr/bin/env python3
# AZAD v1.1 - ENHANCED WITH SYSTEM CONTEXT INTELLIGENCE
# Windows Endpoint Hardening & Exposure Auditor
# leoferrer15 / AZAD
# License: MIT

import os
import sys
import platform
import subprocess
import json
import socket
import locale
import ctypes
from datetime import datetime, timezone

try:
    import winreg
except ImportError:
    winreg = None

try:
    import win32security
    import win32net
    import win32api
except ImportError:
    win32security = None
    win32net = None
    win32api = None

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

MITRE_BASE = "https://attack.mitre.org/techniques"

LANG_MAP = {
    'es': {
        "Inicio de sesión": "Logon",
        "Cierre de sesión": "Logoff"
    },
    'fr': {
        "Ouverture de session": "Logon",
        "Fermeture de session": "Logoff"
    },
    'de': {
        "Anmeldung": "Logon",
        "Abmeldung": "Logoff"
    },
    'pt': {
        "Início de sessão": "Logon",
        "Término de sessão": "Logoff"
    },
}

ADMIN_GROUP_BY_LANG = {
    'es': 'Administradores',
    'en': 'Administrators'
}

HIGH_RISK_PORTS = {135, 139, 445, 3389}

_device_guard_running_cache = None

# ============================================================================
# NEW: POLICY RULES FOR ADAPTIVE SCORING
# ============================================================================

DEFAULT_POLICIES = {
    "score_adjustments": {
        "laptop": {
            "bitlocker_missing": -5,
            "firewall_public_off": +10,
            "rdp_enabled": +5
        },
        "desktop": {
            "bitlocker_missing": -2,
            "firewall_domain_off": +5
        },
        "server": {
            "defender_disabled": +15,
            "audit_disabled": +10,
            "smb_signing_off": +10
        },
        "vm": {
            "secureboot_off": -3,
            "device_guard_missing": -5
        }
    },
    "context_bonuses": {
        "domain_joined": -5,
        "azuread_joined": -5,
        "intune_managed": -10,
        "edr_detected": -15,
        "credential_guard_enabled": -5,
        "lsass_ppl_enabled": -5
    }
}

# ============================================================================
# BANNER
# ============================================================================

def print_banner():
    print(r'''
      .o.        oooooooooooo       .o.       oooooooooo.        
     .888.      d'""""""d888'      .888.      `888'   `Y8b       
    .8"888.           .888P       .8"888.      888      888      
   .8' `888.         d888'       .8' `888.     888      888      
  .88ooo8888.      .888P        .88ooo8888.    888      888      
 .8'     `888.    d888'    .P  .8'     `888.   888     d88'      
o88o     o8888o .8888888888P  o88o     o8888o o888bood8P'
                                                                    
                                             v1.1 - Context Intelligence Edition
''')

# ============================================================================
# UTILITY HELPERS
# ============================================================================

def get_lang_code():
    try:
        loc = locale.getlocale()[0]
        if not loc:
            return "en"
        return loc[:2]
    except Exception:
        return "en"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "UNKNOWN_HOST"

def get_username():
    try:
        return os.getlogin()
    except Exception:
        return os.environ.get("USERNAME", "UNKNOWN_USER")

def run_cmd(cmd):
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False
        )
        return (completed.returncode == 0, completed.stdout.strip(), completed.stderr.strip())
    except Exception as e:
        return (False, "", str(e))

def safe_reg_query(root, path, value_name):
    if not winreg:
        return ("ERROR", None, "winreg not available (non-Windows)")

    try:
        key = winreg.OpenKey(root, path)
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return ("OK", value, None)
    except PermissionError as e:
        return ("PERMISSION", None, str(e))
    except FileNotFoundError:
        return ("NOT_FOUND", None, None)
    except Exception as e:
        return ("ERROR", None, str(e))

def get_windows_edition():
    if not winreg:
        return "UNKNOWN"
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        edition, _ = winreg.QueryValueEx(key, "EditionID")
        winreg.CloseKey(key)
        return edition
    except Exception:
        return "UNKNOWN"

def classify_edition(edition_id):
    if edition_id is None:
        return "UNKNOWN"
    eid = edition_id.lower()
    if "core" in eid or "home" in eid:
        return "HOME"
    if "pro" in eid or "enterprise" in eid or "education" in eid:
        return "PRO_ENT"
    return "UNKNOWN"

def get_domain_info():
    if not win32api:
        return (None, False)
    try:
        domain_name = win32api.GetDomainName()
        if not domain_name:
            return (None, False)
        host = get_hostname()
        if domain_name.strip().lower() != (host or "").strip().lower():
            return (domain_name, True)
        return (domain_name, False)
    except Exception:
        return (None, False)

def normalize_auditpol_output(raw):
    lang = get_lang_code()
    text = raw
    if lang in LANG_MAP:
        for local_str, en_str in LANG_MAP[lang].items():
            text = text.replace(local_str, en_str)
    return text, lang

def get_device_guard_running_services():
    global _device_guard_running_cache
    if _device_guard_running_cache is not None:
        return _device_guard_running_cache

    ok, out, err = run_cmd([
        "powershell",
        "-Command",
        "try { "
        "$dg = Get-CimInstance -ClassName Win32_DeviceGuard; "
        "$dg.SecurityServicesRunning "
        "} catch { '' }"
    ])
    services = set()
    if ok and out:
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                val = int(line)
                services.add(val)
            except ValueError:
                continue

    _device_guard_running_cache = services if services else set()
    return _device_guard_running_cache

def get_lsass_ppl_runtime():
    ps_script = r"""
$ErrorActionPreference = 'SilentlyContinue'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class LsassProtection
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PS_PROTECTION
    {
        public byte Type;
        public byte Audit;
        public byte Signer;
        public byte Reserved;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        out PS_PROTECTION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength
    );

    public static string GetLsassProtection()
    {
        var procs = System.Diagnostics.Process.GetProcessesByName("lsass");
        if (procs == null || procs.Length == 0)
            return "NO_LSASS";

        int pid = procs[0].Id;
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return "OPEN_FAIL_" + err.ToString();
        }

        PS_PROTECTION prot;
        int retLen;
        int status = NtQueryInformationProcess(
            hProc,
            61,
            out prot,
            Marshal.SizeOf(typeof(PS_PROTECTION)),
            out retLen
        );

        if (status != 0)
        {
            return "NTQUERY_FAIL_" + status.ToString("X");
        }

        return $"TYPE={prot.Type};SIGNER={prot.Signer}";
    }
}
"@ | Out-Null

[LsassProtection]::GetLsassProtection()
"""
    ok, out, err = run_cmd(["powershell", "-Command", ps_script])

    if not ok:
        return "UNKNOWN", f"Could not query LSASS PPL via NtQueryInformationProcess: {err or 'unknown error'}"

    if not out:
        return "UNKNOWN", "Empty response from LSASS PPL runtime check."

    line = out.strip().splitlines()[-1].strip()

    if line == "NO_LSASS":
        return "UNKNOWN", "LSASS process not found during PPL runtime check."
    if line.startswith("OPEN_FAIL_"):
        try:
            err_code = int(line.split("_", 2)[2])
        except Exception:
            err_code = None
        if err_code == 5:
            return "BLOCKED_BY_EDR", "OpenProcess on LSASS failed with ERROR_ACCESS_DENIED (5). Runtime protection is enforced by ACL/EDR."
        else:
            return "BLOCKED_BY_EDR", f"OpenProcess on LSASS failed with Win32 error {err_code}. Likely blocked by security policy or EDR."
    if line.startswith("NTQUERY_FAIL_"):
        code = line.split("_", 2)[2]
        if code.upper() in ("C0000022", "C0000001"):
            return "BLOCKED_BY_EDR", f"NtQueryInformationProcess on LSASS failed with status 0x{code}. This often indicates hooking or blocking by security software."
        else:
            return "UNKNOWN", f"NtQueryInformationProcess failed for LSASS with status 0x{code}."

    if line.startswith("TYPE="):
        try:
            parts = line.split(";")
            type_part = parts[0].split("=", 1)[1]
            signer_part = parts[1].split("=", 1)[1] if len(parts) > 1 else "0"
            t_val = int(type_part)
            s_val = int(signer_part)
        except Exception:
            return "UNKNOWN", f"Could not parse LSASS PPL runtime output: '{line}'"

        if t_val == 0:
            return "DISABLED", f"LSASS runtime protection: TYPE={t_val}, SIGNER={s_val} (no PPL)."

        if s_val >= 6:
            state = "ENABLED_STRONG"
            detail = "PPL enabled with strong signer (WinTcb/WinSystem or equivalent)."
        else:
            state = "ENABLED_WEAK"
            detail = "PPL enabled but signer is lower trust (non-system)."

        return state, f"LSASS runtime protection: TYPE={t_val}, SIGNER={s_val} ({detail})"

    return "UNKNOWN", f"Unexpected LSASS PPL runtime output: '{line}'"

def check_smbv1():
    if not winreg:
        return "UNKNOWN", "winreg not available (non-Windows)"

    path = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "SMB1")

    if status == "OK":
        try:
            if int(value) == 0:
                return "DISABLED", "SMBv1 registry flag present and set to 0 (disabled)."
            else:
                return "ENABLED", f"SMBv1 registry flag present and set to {value} (enabled)."
        except Exception:
            return "UNKNOWN", f"Could not interpret SMB1 value: {value!r}"
    elif status == "NOT_FOUND":
        return "DISABLED", "SMB1 registry value not found. On modern Windows this typically means SMBv1 is disabled or not installed by default."
    elif status == "PERMISSION":
        return "UNKNOWN", f"Admin required to query SMBv1 registry key: {err}"
    else:
        return "UNKNOWN", f"Error querying SMBv1 registry key: {err}"

def new_finding(fid, category, name, severity="LOW", requires_admin=False):
    return {
        "id": fid,
        "category": category,
        "name": name,
        "status": "UNKNOWN",
        "severity": severity,
        "risk_points": 0,
        "note": "",
        "recommendation": "",
        "mitre": [],
        "requires_admin": requires_admin
    }

def get_local_admin_members_sid():
    if not (win32security and win32net):
        return None, "pywin32 not available"

    try:
        admin_sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
        name, domain, acc_type = win32security.LookupAccountSid(None, admin_sid)
        group_name = name

        members = []
        resume = 0
        while True:
            data, total, resume = win32net.NetLocalGroupGetMembers(
                None,
                group_name,
                2,
                resume
            )
            for entry in data:
                dn = entry.get("domainandname") or entry.get("name")
                if dn:
                    members.append(dn)
            if not resume:
                break

        return members, None
    except Exception as e:
        return None, str(e)

# ============================================================================
# NEW FUNCTION 1: detect_form_factor()
# ============================================================================

def detect_form_factor():
    result = {
        'type': 'UNKNOWN',
        'confidence': 'LOW',
        'details': []
    }
    
    ps_vm_check = r"""
$isVM = $false
$vmIndicators = @()

$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.Model -match 'Virtual|VMware|VBox|Hyper-V|Xen|KVM') {
    $isVM = $true
    $vmIndicators += "Model: $($cs.Model)"
}

$bios = Get-CimInstance Win32_BIOS
if ($bios.Manufacturer -match 'VMware|Microsoft Corporation|Xen|innotek|Parallels') {
    $isVM = $true
    $vmIndicators += "BIOS: $($bios.Manufacturer)"
}

if ($isVM) {
    Write-Output "VM|$($vmIndicators -join ';')"
} else {
    Write-Output "PHYSICAL|"
}
"""
    ok, out, err = run_cmd(["powershell", "-Command", ps_vm_check])
    
    is_vm = False
    if ok and out:
        parts = out.split("|", 1)
        if parts[0] == "VM":
            is_vm = True
            result['type'] = 'VM'
            result['confidence'] = 'HIGH'
            result['details'].append(parts[1] if len(parts) > 1 else "VM detected")
    
    if not is_vm:
        ps_server_check = r"""
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 3) {
    Write-Output "SERVER|$($os.Caption)"
} else {
    Write-Output "CLIENT|$($os.Caption)"
}
"""
        ok, out, err = run_cmd(["powershell", "-Command", ps_server_check])
        
        if ok and out:
            parts = out.split("|", 1)
            if parts[0] == "SERVER":
                result['type'] = 'SERVER'
                result['confidence'] = 'HIGH'
                result['details'].append(parts[1] if len(parts) > 1 else "Server OS")
            else:
                ps_battery = r"""
$battery = Get-CimInstance Win32_Battery
if ($battery) {
    Write-Output "LAPTOP|Battery detected"
} else {
    Write-Output "DESKTOP|No battery"
}
"""
                ok, out, err = run_cmd(["powershell", "-Command", ps_battery])
                
                if ok and out:
                    parts = out.split("|", 1)
                    result['type'] = parts[0]
                    result['confidence'] = 'HIGH'
                    result['details'].append(parts[1] if len(parts) > 1 else "")
    
    return result

# ============================================================================
# NEW FUNCTION 2: detect_domain_context()
# ============================================================================

def detect_domain_context():
    result = {
        'status': 'UNKNOWN',
        'type': None,
        'name': None,
        'details': []
    }
    
    ps_domain = r"""
$cs = Get-CimInstance Win32_ComputerSystem
$partOfDomain = $cs.PartOfDomain
$domain = $cs.Domain
$workgroup = $cs.Workgroup

if ($partOfDomain) {
    Write-Output "DOMAIN|$domain"
} elseif ($workgroup) {
    Write-Output "WORKGROUP|$workgroup"
} else {
    Write-Output "UNKNOWN|"
}
"""
    ok, out, err = run_cmd(["powershell", "-Command", ps_domain])
    
    if ok and out:
        parts = out.split("|", 1)
        result['status'] = 'OK'
        result['type'] = parts[0]
        result['name'] = parts[1] if len(parts) > 1 else None
        result['details'].append(f"{parts[0]}: {parts[1] if len(parts) > 1 else 'N/A'}")
    
    return result

# ============================================================================
# NEW FUNCTION 3: detect_azuread()
# ============================================================================

def detect_azuread():
    result = {
        'joined': False,
        'tenant_id': None,
        'device_id': None,
        'details': []
    }
    
    ps_azuread = r"""
$dsreg = dsregcmd /status
$azureAdJoined = $false
$tenantId = $null
$deviceId = $null

foreach ($line in $dsreg) {
    if ($line -match 'AzureAdJoined\s*:\s*YES') {
        $azureAdJoined = $true
    }
    if ($line -match 'TenantId\s*:\s*([a-f0-9-]+)') {
        $tenantId = $matches[1]
    }
    if ($line -match 'DeviceId\s*:\s*([a-f0-9-]+)') {
        $deviceId = $matches[1]
    }
}

if ($azureAdJoined) {
    Write-Output "JOINED|$tenantId|$deviceId"
} else {
    Write-Output "NOT_JOINED||"
}
"""
    ok, out, err = run_cmd(["powershell", "-Command", ps_azuread])
    
    if ok and out:
        parts = out.split("|")
        if parts[0] == "JOINED":
            result['joined'] = True
            result['tenant_id'] = parts[1] if len(parts) > 1 and parts[1] else None
            result['device_id'] = parts[2] if len(parts) > 2 and parts[2] else None
            result['details'].append(f"Azure AD Joined (Tenant: {result['tenant_id']})")
        else:
            result['details'].append("Not Azure AD joined")
    
    return result

# ============================================================================
# NEW FUNCTION 4: detect_intune()
# ============================================================================

def detect_intune():
    result = {
        'enrolled': False,
        'mdm_url': None,
        'details': []
    }
    
    if not winreg:
        result['details'].append("winreg not available")
        return result
    
    paths_to_check = [
        r"SOFTWARE\Microsoft\Enrollments",
        r"SOFTWARE\Microsoft\PolicyManager\current\device"
    ]
    
    for path in paths_to_check:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            result['enrolled'] = True
            result['details'].append(f"MDM enrollment detected at {path}")
            winreg.CloseKey(key)
            break
        except FileNotFoundError:
            continue
        except Exception:
            continue
    
    ps_intune = r"""
$intuneService = Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
if ($intuneService) {
    Write-Output "SERVICE_FOUND|$($intuneService.Status)"
} else {
    Write-Output "SERVICE_NOT_FOUND|"
}
"""
    ok, out, err = run_cmd(["powershell", "-Command", ps_intune])
    
    if ok and out:
        parts = out.split("|")
        if parts[0] == "SERVICE_FOUND":
            result['enrolled'] = True
            result['details'].append(f"Intune Management Extension service: {parts[1]}")
    
    if not result['details']:
        result['details'].append("No Intune/MDM enrollment detected")
    
    return result

# ============================================================================
# NEW FUNCTION 5: detect_edr_from_system()
# ============================================================================

def detect_edr_from_system():
    result = {
        'detected': False,
        'products': [],
        'confidence': 'LOW',
        'details': []
    }
    
    edr_patterns = {
        'CrowdStrike': ['CSFalconService', 'CSFalconContainer'],
        'SentinelOne': ['SentinelAgent', 'SentinelStaticEngine'],
        'Defender ATP': ['MsSense', 'SenseIR', 'SenseCncProxy'],
        'Carbon Black': ['CbDefense', 'RepMgr'],
        'Cylance': ['CylanceSvc'],
        'Palo Alto Traps': ['tlaservice', 'cyserver'],
        'Trend Micro': ['TMBMServer', 'TMBMSRV'],
        'Symantec': ['SepMasterService', 'ccSvcHst'],
        'McAfee': ['masvc', 'mfemms'],
        'Sophos': ['SophosHealth', 'SophosFileScanner'],
        'Cisco AMP': ['immunetprotect'],
        'ESET': ['ekrn'],
        'Kaspersky': ['AVP', 'KAVFS']
    }
    
    ps_edr = r"""
$services = Get-Service | Select-Object -ExpandProperty Name
$processes = Get-Process | Select-Object -ExpandProperty Name
$allNames = $services + $processes | Sort-Object -Unique
Write-Output ($allNames -join '|')
"""
    ok, out, err = run_cmd(["powershell", "-Command", ps_edr])
    
    if ok and out:
        running_items = out.lower().split('|')
        
        for edr_name, patterns in edr_patterns.items():
            for pattern in patterns:
                if any(pattern.lower() in item for item in running_items):
                    result['detected'] = True
                    result['products'].append(edr_name)
                    result['confidence'] = 'HIGH'
                    result['details'].append(f"{edr_name} detected (pattern: {pattern})")
                    break
    
    ps_av = r"""
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty displayName
"""
    ok, out, err = run_cmd(["powershell", "-Command", ps_av])
    
    if ok and out:
        av_products = [line.strip() for line in out.splitlines() if line.strip()]
        for av in av_products:
            if av not in result['products']:
                result['detected'] = True
                result['products'].append(av)
                result['details'].append(f"AV/EDR product: {av}")
    
    if not result['details']:
        result['details'].append("No EDR/advanced AV detected")
    
    return result

# ============================================================================
# NEW FUNCTION 6: compute_gpo_lockdown_level()
# ============================================================================

def compute_gpo_lockdown_level():
    result = {
        'score': 0,
        'max_score': 100,
        'level': 'NONE',
        'policies_found': [],
        'details': []
    }
    
    checks = [
        ("LSASS Protection", r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 15),
        ("Credential Guard", r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard", "Enabled", 15),
        ("AMSI Enabled", r"SOFTWARE\Microsoft\Windows Script\Settings", "AmsiEnable", 10),
        ("Script Block Logging", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 10),
        ("LLMNR Disabled", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 10),
        ("WDigest Disabled", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 10),
        ("SMB Signing Required", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 10),
        ("RDP NLA Enabled", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 10),
        ("Audit Policy Configured", None, None, 10)
    ]
    
    if not winreg:
        result['details'].append("winreg not available")
        return result
    
    for check_name, path, value_name, points in checks:
        if path is None:
            continue
        
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, value_name)
        
        if status == "OK":
            try:
                val = int(value)
                if "Disabled" in check_name or "WDigest" in check_name:
                    if val == 0:
                        result['score'] += points
                        result['policies_found'].append(check_name)
                elif "LLMNR" in check_name:
                    if val == 0:
                        result['score'] += points
                        result['policies_found'].append(check_name)
                else:
                    if val == 1:
                        result['score'] += points
                        result['policies_found'].append(check_name)
            except:
                pass
    
    percentage = (result['score'] / result['max_score']) * 100
    if percentage >= 80:
        result['level'] = 'HIGH'
    elif percentage >= 50:
        result['level'] = 'MEDIUM'
    elif percentage >= 20:
        result['level'] = 'LOW'
    else:
        result['level'] = 'NONE'
    
    result['details'].append(f"GPO lockdown score: {result['score']}/{result['max_score']} ({percentage:.1f}%)")
    result['details'].append(f"Policies enforced: {len(result['policies_found'])}")
    
    return result

# ============================================================================
# NEW FUNCTION 7: load_policies()
# ============================================================================

def load_policies(policy_file=None):
    if policy_file and os.path.exists(policy_file):
        try:
            with open(policy_file, 'r', encoding='utf-8') as f:
                policies = json.load(f)
            return policies
        except Exception as e:
            print(f"Warning: Could not load policy file {policy_file}: {e}")
    
    return DEFAULT_POLICIES

# ============================================================================
# NEW FUNCTION 8: build_system_context()
# ============================================================================

def build_system_context(meta):
    context = {
        'form_factor': detect_form_factor(),
        'domain': detect_domain_context(),
        'azure_ad': detect_azuread(),
        'intune': detect_intune(),
        'edr': detect_edr_from_system(),
        'gpo_lockdown': compute_gpo_lockdown_level(),
        'baseline': {
            'hostname': meta.get('hostname'),
            'username': meta.get('username'),
            'os': meta.get('os'),
            'edition': meta.get('edition'),
            'is_admin': meta.get('is_admin', False)
        }
    }
    
    return context

# ============================================================================
# NEW FUNCTION 9: adaptive_score_with_context()
# ============================================================================

def adaptive_score_with_context(findings, context, policies):
    adjustments = []
    total_adjustment = 0
    
    form_factor = context['form_factor']['type']
    
    if form_factor in policies['score_adjustments']:
        factor_rules = policies['score_adjustments'][form_factor]
        
        for finding in findings:
            fid = finding.get('id', '')
            
            if 'BITLOCKER' in fid and finding['status'] in ('WARNING', 'UNKNOWN'):
                if 'bitlocker_missing' in factor_rules:
                    adj = factor_rules['bitlocker_missing']
                    finding['risk_points'] += adj
                    total_adjustment += adj
                    adjustments.append(f"BitLocker ({form_factor}): {adj:+d}")
            
            if 'FW_PUBLIC' in fid and finding['status'] == 'WARNING':
                if 'firewall_public_off' in factor_rules:
                    adj = factor_rules['firewall_public_off']
                    finding['risk_points'] += adj
                    total_adjustment += adj
                    adjustments.append(f"Firewall Public ({form_factor}): {adj:+d}")
            
            if 'NET_RDP' in fid and finding['status'] == 'WARNING':
                if 'rdp_enabled' in factor_rules:
                    adj = factor_rules['rdp_enabled']
                    finding['risk_points'] += adj
                    total_adjustment += adj
                    adjustments.append(f"RDP enabled ({form_factor}): {adj:+d}")
    
    bonuses = policies['context_bonuses']
    
    if context['domain']['type'] == 'DOMAIN':
        total_adjustment += bonuses.get('domain_joined', 0)
        adjustments.append(f"Domain-joined: {bonuses.get('domain_joined', 0):+d}")
    
    if context['azure_ad']['joined']:
        total_adjustment += bonuses.get('azuread_joined', 0)
        adjustments.append(f"Azure AD joined: {bonuses.get('azuread_joined', 0):+d}")
    
    if context['intune']['enrolled']:
        total_adjustment += bonuses.get('intune_managed', 0)
        adjustments.append(f"Intune managed: {bonuses.get('intune_managed', 0):+d}")
    
    if context['edr']['detected']:
        total_adjustment += bonuses.get('edr_detected', 0)
        adjustments.append(f"EDR detected: {bonuses.get('edr_detected', 0):+d}")
    
    for finding in findings:
        if finding['id'] == 'MEM_CRED_GUARD' and finding['status'] == 'OK':
            total_adjustment += bonuses.get('credential_guard_enabled', 0)
            adjustments.append(f"Credential Guard: {bonuses.get('credential_guard_enabled', 0):+d}")
            break
    
    for finding in findings:
        if finding['id'] == 'MEM_LSASS' and finding['status'] == 'OK':
            total_adjustment += bonuses.get('lsass_ppl_enabled', 0)
            adjustments.append(f"LSASS PPL: {bonuses.get('lsass_ppl_enabled', 0):+d}")
            break
    
    return {
        'total_adjustment': total_adjustment,
        'adjustments': adjustments
    }

# ============================================================================
# MODULES - COMPLETE IMPLEMENTATIONS
# ============================================================================

def context_module():
    findings = []

    f = new_finding("CTX_OVERVIEW", "Context", "System overview", severity="LOW")
    host = get_hostname()
    user = get_username()
    os_str = platform.platform()
    edition = get_windows_edition()
    domain_name, domain_joined = get_domain_info()

    if domain_joined:
        domain_str = f"Domain-joined: {domain_name}"
    elif domain_name:
        domain_str = f"Domain: {domain_name}"
    else:
        domain_str = "Domain: UNKNOWN/WORKGROUP"

    f["status"] = "OK"
    f["note"] = (
        f"Host: {host}, User: {user}, OS: {os_str}, "
        f"EditionID: {edition}, {domain_str}"
    )
    f["recommendation"] = "No action required. Baseline context only."
    findings.append(f)

    return findings, {
        "hostname": host,
        "username": user,
        "os": os_str,
        "edition": edition,
        "domain_name": domain_name,
        "domain_joined": domain_joined
    }

def memory_module(is_admin_flag):
    findings = []

    f_lsass = new_finding("MEM_LSASS", "Memory", "LSASS protection (RunAsPPL)", severity="MEDIUM", requires_admin=True)
    config_state = "UNKNOWN"
    config_note = ""

    if not winreg:
        f_lsass["status"] = "UNKNOWN"
        f_lsass["note"] = "winreg not available (non-Windows)."
        f_lsass["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SYSTEM\CurrentControlSet\Control\Lsa"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "RunAsPPL")
        if status == "OK":
            try:
                iv = int(value)
                if iv in (1, 2):
                    f_lsass["status"] = "OK"
                    f_lsass["note"] = f"LSASS RunAsPPL appears ENABLED (RunAsPPL={iv})."
                    f_lsass["recommendation"] = "No action required. This raises the bar for credential dumping (T1003.001)."
                    config_state = "ENABLED"
                    config_note = f"Registry RunAsPPL={iv}."
                else:
                    f_lsass["status"] = "WARNING"
                    f_lsass["risk_points"] = 5
                    f_lsass["note"] = f"LSASS RunAsPPL not configured securely (RunAsPPL={iv})."
                    f_lsass["recommendation"] = "Consider enabling LSASS RunAsPPL via GPO or registry to make LSASS dumping significantly harder."
                    config_state = "DISABLED"
                    config_note = f"Registry RunAsPPL={iv}."
            except Exception:
                f_lsass["status"] = "UNKNOWN"
                f_lsass["note"] = f"Could not interpret RunAsPPL value: {value!r}."
                f_lsass["recommendation"] = "Check LSASS protection manually. Harden per Microsoft guidance."
                config_state = "UNKNOWN"
        elif status == "NOT_FOUND":
            f_lsass["status"] = "UNKNOWN"
            f_lsass["note"] = "RunAsPPL registry value not found (default on many systems)."
            f_lsass["recommendation"] = "Review LSASS protection manually. In hardened enterprise environments, RunAsPPL is typically enabled via GPO or registry."
            config_state = "UNKNOWN"
        elif status == "PERMISSION":
            f_lsass["status"] = "UNKNOWN"
            f_lsass["note"] = "Admin required to query LSASS RunAsPPL registry key."
            f_lsass["recommendation"] = "Re-run AZAD as Administrator for full accuracy."
            config_state = "UNKNOWN"
        else:
            f_lsass["status"] = "UNKNOWN"
            f_lsass["note"] = f"Error querying LSASS RunAsPPL: {err}"
            f_lsass["recommendation"] = "Check registry manually or review security baselines."
            config_state = "UNKNOWN"

    runtime_state, runtime_note = get_lsass_ppl_runtime()
    if f_lsass["note"]:
        f_lsass["note"] += " "
    
    if runtime_state in ("ENABLED_STRONG", "ENABLED_WEAK"):
        f_lsass["note"] += f"Runtime check: {runtime_note}"
        if f_lsass["status"] in ("WARNING", "UNKNOWN"):
            f_lsass["status"] = "OK"
            f_lsass["risk_points"] = 0
            if config_state != "ENABLED":
                f_lsass["note"] += " (Config/runtime mismatch: registry does not clearly enforce RunAsPPL, but LSASS is protected as PPL at runtime. Review GPO/registry for consistency.)"
    elif runtime_state == "DISABLED":
        f_lsass["note"] += f"Runtime check: {runtime_note}"
        if f_lsass["status"] == "OK" and config_state == "ENABLED":
            f_lsass["status"] = "CRITICAL"
            f_lsass["risk_points"] = max(f_lsass["risk_points"], 15)
            f_lsass["note"] += " (Config/runtime mismatch: registry claims RunAsPPL enabled, but LSASS is not running as PPL. Protection is broken.)"
            f_lsass["recommendation"] = "Investigate why LSASS is not running as PPL despite RunAsPPL configuration. Check for incompatible drivers, early-boot errors, or conflicting security software, and validate against Microsoft security baselines."
        else:
            if f_lsass["status"] in ("WARNING", "UNKNOWN"):
                if "LSASS process is not protected as PPL" not in f_lsass["note"]:
                    f_lsass["note"] += " LSASS process is not protected as PPL at runtime."
                if f_lsass["risk_points"] < 10:
                    f_lsass["risk_points"] = max(f_lsass["risk_points"], 10)
                if f_lsass["status"] != "CRITICAL":
                    f_lsass["status"] = "WARNING"
    elif runtime_state == "BLOCKED_BY_EDR":
        f_lsass["note"] += f"Runtime check: {runtime_note} (LSASS handle/protection is blocked by security software or ACL; PPL state cannot be confirmed from userland.)"
        if f_lsass["status"] == "UNKNOWN":
            f_lsass["risk_points"] = min(f_lsass.get("risk_points", 0), 5)
    else:
        f_lsass["note"] += f"Runtime PPL state could not be determined: {runtime_note}"

    f_lsass["mitre"] = ["T1003.001"]
    findings.append(f_lsass)

    f_cg = new_finding("MEM_CRED_GUARD", "Memory", "Credential Guard", severity="MEDIUM", requires_admin=True)
    if not winreg:
        f_cg["status"] = "UNKNOWN"
        f_cg["note"] = "winreg not available (non-Windows)."
        f_cg["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "Enabled")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 1:
                    f_cg["status"] = "OK"
                    f_cg["note"] = "Credential Guard appears ENABLED (Enabled=1)."
                    f_cg["recommendation"] = "No action required. This reduces credential theft exposure."
                elif iv == 0:
                    f_cg["status"] = "WARNING"
                    f_cg["risk_points"] = 5
                    f_cg["note"] = "Credential Guard appears DISABLED (Enabled=0)."
                    f_cg["recommendation"] = "Evaluate enabling Credential Guard on supported hardware."
                else:
                    f_cg["status"] = "UNKNOWN"
                    f_cg["note"] = f"Credential Guard state non-standard (Enabled={iv})."
                    f_cg["recommendation"] = "Review Credential Guard configuration manually."
            except Exception:
                f_cg["status"] = "UNKNOWN"
                f_cg["note"] = f"Could not interpret Credential Guard Enabled value: {value!r}."
                f_cg["recommendation"] = "Review configuration manually via Group Policy / Windows Security."
        elif status == "NOT_FOUND":
            services = get_device_guard_running_services()
            if 1 in services:
                f_cg["status"] = "OK"
                f_cg["note"] = "Credential Guard registry key/value not found, but DeviceGuard reports SecurityServicesRunning includes 1 (Credential Guard)."
                f_cg["recommendation"] = "No action required. Credential Guard is running per DeviceGuard."
            else:
                f_cg["status"] = "UNKNOWN"
                f_cg["note"] = "Credential Guard registry key/value not found and DeviceGuard does not report it running."
                f_cg["recommendation"] = "Check Credential Guard support and status via Windows Security -> Device Security."
        elif status == "PERMISSION":
            f_cg["status"] = "UNKNOWN"
            f_cg["note"] = "Admin required to query Credential Guard registry keys."
            f_cg["recommendation"] = "Re-run AZAD as Administrator for full accuracy."
        else:
            f_cg["status"] = "UNKNOWN"
            f_cg["note"] = f"Error querying Credential Guard: {err}"
            f_cg["recommendation"] = "Review configuration manually and compare against baselines."

    f_cg["mitre"] = ["T1003", "T1556"]
    findings.append(f_cg)

    f_vbs = new_finding("MEM_VBS", "Memory", "Virtualization-Based Security (VBS)", severity="MEDIUM", requires_admin=True)
    if not winreg:
        f_vbs["status"] = "UNKNOWN"
        f_vbs["note"] = "winreg not available (non-Windows)."
        f_vbs["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "EnableVirtualizationBasedSecurity")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 1:
                    f_vbs["status"] = "OK"
                    f_vbs["note"] = "VBS appears ENABLED (EnableVirtualizationBasedSecurity=1)."
                    f_vbs["recommendation"] = "No action required. VBS strengthens isolation against credential theft."
                elif iv == 0:
                    f_vbs["status"] = "WARNING"
                    f_vbs["risk_points"] = 5
                    f_vbs["note"] = "VBS appears DISABLED (EnableVirtualizationBasedSecurity=0)."
                    f_vbs["recommendation"] = "Consider enabling VBS where supported to raise attacker cost."
                else:
                    f_vbs["status"] = "UNKNOWN"
                    f_vbs["note"] = f"Non-standard VBS configuration (EnableVirtualizationBasedSecurity={iv})."
                    f_vbs["recommendation"] = "Review DeviceGuard configuration against Microsoft baseline."
            except Exception:
                f_vbs["status"] = "UNKNOWN"
                f_vbs["note"] = f"Could not interpret VBS value: {value!r}."
                f_vbs["recommendation"] = "Review VBS configuration manually."
        elif status == "NOT_FOUND":
            services = get_device_guard_running_services()
            if 2 in services:
                f_vbs["status"] = "OK"
                f_vbs["note"] = "VBS registry value not found, but DeviceGuard reports SecurityServicesRunning includes 2 (VBS/HVCI)."
                f_vbs["recommendation"] = "No action required. VBS/HVCI is running per DeviceGuard."
            else:
                f_vbs["status"] = "UNKNOWN"
                f_vbs["note"] = "VBS registry value not found and DeviceGuard does not report it running."
                f_vbs["recommendation"] = "Check Device Security in Windows Security to confirm VBS status."
        elif status == "PERMISSION":
            f_vbs["status"] = "UNKNOWN"
            f_vbs["note"] = "Admin required to query VBS registry keys."
            f_vbs["recommendation"] = "Re-run AZAD as Administrator for full accuracy."
        else:
            f_vbs["status"] = "UNKNOWN"
            f_vbs["note"] = f"Error querying VBS: {err}"
            f_vbs["recommendation"] = "Review DeviceGuard configuration manually."

    f_vbs["mitre"] = ["T1003", "T1068"]
    findings.append(f_vbs)

    return findings

def auth_hardening_module():
    findings = []

    f_wdigest = new_finding("AUTH_WDIGEST", "Authentication", "WDigest cleartext credentials in LSASS", severity="HIGH", requires_admin=True)

    if not winreg:
        f_wdigest["status"] = "UNKNOWN"
        f_wdigest["note"] = "winreg not available (non-Windows)."
        f_wdigest["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "UseLogonCredential")

        if status == "OK":
            try:
                iv = int(value)
                if iv == 0:
                    f_wdigest["status"] = "OK"
                    f_wdigest["note"] = "WDigest 'UseLogonCredential' is 0 (LSASS should not store cleartext passwords for WDigest)."
                    f_wdigest["recommendation"] = "No action required. Keep WDigest disabled unless there is a legacy requirement."
                elif iv == 1:
                    f_wdigest["status"] = "WARNING"
                    f_wdigest["risk_points"] = 10
                    f_wdigest["note"] = "WDigest 'UseLogonCredential' is 1. LSASS may store cleartext credentials for WDigest, increasing risk of credential theft."
                    f_wdigest["recommendation"] = "Set 'UseLogonCredential' to 0 via Group Policy or registry to prevent LSASS from storing cleartext passwords for WDigest, unless strictly required for legacy systems."
                else:
                    f_wdigest["status"] = "UNKNOWN"
                    f_wdigest["note"] = f"WDigest 'UseLogonCredential' has non-standard value: {value!r}."
                    f_wdigest["recommendation"] = "Review WDigest configuration manually. Recommended value is 0 on modern systems."
            except Exception:
                f_wdigest["status"] = "UNKNOWN"
                f_wdigest["note"] = f"Could not interpret WDigest 'UseLogonCredential' value: {value!r}."
                f_wdigest["recommendation"] = "Check WDigest configuration manually and compare to Microsoft security baselines."
        elif status == "NOT_FOUND":
            f_wdigest["status"] = "OK"
            f_wdigest["note"] = "WDigest 'UseLogonCredential' value not found. On modern Windows this typically means WDigest does not store cleartext credentials by default."
            f_wdigest["recommendation"] = "No action required. Ensure WDigest remains disabled unless absolutely necessary."
        elif status == "PERMISSION":
            f_wdigest["status"] = "UNKNOWN"
            f_wdigest["note"] = "Admin rights required to query WDigest 'UseLogonCredential' registry value."
            f_wdigest["recommendation"] = "Re-run AZAD as Administrator for accurate WDigest status."
        else:
            f_wdigest["status"] = "UNKNOWN"
            f_wdigest["note"] = f"Error querying WDigest 'UseLogonCredential': {err}"
            f_wdigest["recommendation"] = "Review WDigest configuration manually."

    f_wdigest["mitre"] = ["T1003.001"]
    findings.append(f_wdigest)

    f_ntlm = new_finding("AUTH_NTLM", "Authentication", "NTLM / LM configuration (Lsa)", severity="HIGH", requires_admin=True)

    if not winreg:
        f_ntlm["status"] = "UNKNOWN"
        f_ntlm["note"] = "winreg not available (non-Windows)."
        f_ntlm["recommendation"] = "Run on Windows endpoint only."
    else:
        path_lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
        issues = []
        info = []

        s_lm, v_lm, e_lm = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_lsa, "LmCompatibilityLevel")
        if s_lm == "OK":
            try:
                lv = int(v_lm)
                info.append(f"LmCompatibilityLevel={lv}.")
                if lv < 3:
                    issues.append(f"LmCompatibilityLevel={lv} (allows older, weaker LM/NTLM protocols).")
            except Exception:
                issues.append(f"Could not interpret LmCompatibilityLevel value: {v_lm!r}.")
        elif s_lm == "NOT_FOUND":
            issues.append("LmCompatibilityLevel not defined (defaults may allow weaker compatibility on some builds).")
        elif s_lm == "PERMISSION":
            issues.append("Admin rights required to query LmCompatibilityLevel.")
        else:
            issues.append(f"Error querying LmCompatibilityLevel: {e_lm}.")

        s_nolm, v_nolm, e_nolm = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_lsa, "NoLMHash")
        if s_nolm == "OK":
            try:
                nlv = int(v_nolm)
                info.append(f"NoLMHash={nlv}.")
                if nlv != 1:
                    issues.append("NoLMHash is not 1 (LM hashes may be stored for local accounts).")
            except Exception:
                issues.append(f"Could not interpret NoLMHash value: {v_nolm!r}.")
        elif s_nolm == "NOT_FOUND":
            issues.append("NoLMHash not defined (ensure LM hashes are not stored for local accounts).")
        elif s_nolm == "PERMISSION":
            issues.append("Admin rights required to query NoLMHash.")
        else:
            issues.append(f"Error querying NoLMHash: {e_nolm}.")

        s_rntlm, v_rntlm, e_rntlm = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_lsa, "RestrictNTLM")
        if s_rntlm == "OK":
            try:
                rnv = int(v_rntlm)
                info.append(f"RestrictNTLM={rnv}.")
                if rnv == 0:
                    issues.append("RestrictNTLM=0 (NTLM not restricted; consider tightening according to baseline).")
            except Exception:
                issues.append(f"Could not interpret RestrictNTLM value: {v_rntlm!r}.")
        elif s_rntlm == "NOT_FOUND":
            issues.append("RestrictNTLM not defined (NTLM restrictions may not be enforced).")
        elif s_rntlm == "PERMISSION":
            issues.append("Admin rights required to query RestrictNTLM.")
        else:
            issues.append(f"Error querying RestrictNTLM: {e_rntlm}.")

        if not issues and info:
            f_ntlm["status"] = "OK"
            f_ntlm["note"] = "NTLM/LM configuration appears reasonably hardened. " + " ".join(info)
            f_ntlm["recommendation"] = "No action required, but regularly review LmCompatibilityLevel, NoLMHash and RestrictNTLM against current Microsoft and CIS baselines."
        elif issues:
            f_ntlm["status"] = "WARNING"
            f_ntlm["risk_points"] = 10
            f_ntlm["note"] = " ".join(issues + info)
            f_ntlm["recommendation"] = "Harden NTLM/LM configuration: set LmCompatibilityLevel to at least 3 (or higher per baseline), ensure NoLMHash=1 to avoid storing LM hashes, and configure RestrictNTLM to limit legacy NTLM usage."
        else:
            f_ntlm["status"] = "UNKNOWN"
            f_ntlm["note"] = "Could not determine NTLM/LM configuration from Lsa keys."
            f_ntlm["recommendation"] = "Review NTLM/LM configuration manually via Local Security Policy or Group Policy."

    f_ntlm["mitre"] = ["T1110", "T1558"]
    findings.append(f_ntlm)

    f_smb_sign = new_finding("AUTH_SMB_SIGNING", "Network", "SMB signing configuration (server/client)", severity="MEDIUM", requires_admin=True)

    if not winreg:
        f_smb_sign["status"] = "UNKNOWN"
        f_smb_sign["note"] = "winreg not available (non-Windows)."
        f_smb_sign["recommendation"] = "Run on Windows endpoint only."
    else:
        issues = []
        info = []

        path_srv = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        s_req_srv, v_req_srv, e_req_srv = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_srv, "RequireSecuritySignature")
        s_en_srv, v_en_srv, e_en_srv = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_srv, "EnableSecuritySignature")

        if s_req_srv == "OK":
            try:
                val = int(v_req_srv)
                info.append(f"Server RequireSecuritySignature={val}.")
                if val != 1:
                    issues.append("Server SMB signing is not required (RequireSecuritySignature != 1).")
            except Exception:
                issues.append(f"Could not interpret server RequireSecuritySignature value: {v_req_srv!r}.")
        elif s_req_srv == "NOT_FOUND":
            issues.append("Server RequireSecuritySignature not defined (SMB signing may not be enforced for server).")
        elif s_req_srv == "PERMISSION":
            issues.append("Admin rights required to query server RequireSecuritySignature.")
        else:
            issues.append(f"Error querying server RequireSecuritySignature: {e_req_srv}.")

        if s_en_srv == "OK":
            try:
                val = int(v_en_srv)
                info.append(f"Server EnableSecuritySignature={val}.")
            except Exception:
                issues.append(f"Could not interpret server EnableSecuritySignature value: {v_en_srv!r}.")

        path_cli = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        s_req_cli, v_req_cli, e_req_cli = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_cli, "RequireSecuritySignature")
        s_en_cli, v_en_cli, e_en_cli = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_cli, "EnableSecuritySignature")

        if s_req_cli == "OK":
            try:
                val = int(v_req_cli)
                info.append(f"Client RequireSecuritySignature={val}.")
                if val != 1:
                    issues.append("Client SMB signing is not required (client RequireSecuritySignature != 1).")
            except Exception:
                issues.append(f"Could not interpret client RequireSecuritySignature value: {v_req_cli!r}.")
        elif s_req_cli == "NOT_FOUND":
            issues.append("Client RequireSecuritySignature not defined (SMB signing may not be enforced for client).")
        elif s_req_cli == "PERMISSION":
            issues.append("Admin rights required to query client RequireSecuritySignature.")
        else:
            issues.append(f"Error querying client RequireSecuritySignature: {e_req_cli}.")

        if s_en_cli == "OK":
            try:
                val = int(v_en_cli)
                info.append(f"Client EnableSecuritySignature={val}.")
            except Exception:
                issues.append(f"Could not interpret client EnableSecuritySignature value: {v_en_cli!r}.")

        if not issues:
            f_smb_sign["status"] = "OK"
            f_smb_sign["note"] = "SMB signing configuration appears to require signing on server/client. " + " ".join(info)
            f_smb_sign["recommendation"] = "No action required. Keep SMB signing enforced to reduce risk of SMB relay and tampering."
        else:
            f_smb_sign["status"] = "WARNING"
            f_smb_sign["risk_points"] = 5
            f_smb_sign["note"] = " ".join(issues + info)
            f_smb_sign["recommendation"] = "Enable and require SMB signing on both server and client endpoints where supported, to mitigate SMB relay and man-in-the-middle attacks."

    f_smb_sign["mitre"] = ["T1557", "T1021.002"]
    findings.append(f_smb_sign)

    f_rdp_nla = new_finding("AUTH_RDP_NLA", "Network", "RDP Network Level Authentication (NLA)", severity="MEDIUM", requires_admin=True)

    if not winreg:
        f_rdp_nla["status"] = "UNKNOWN"
        f_rdp_nla["note"] = "winreg not available (non-Windows)."
        f_rdp_nla["recommendation"] = "Run on Windows endpoint only."
    else:
        path_rdp = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path_rdp, "UserAuthentication")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 1:
                    f_rdp_nla["status"] = "OK"
                    f_rdp_nla["note"] = "RDP Network Level Authentication (NLA) appears ENABLED (UserAuthentication=1)."
                    f_rdp_nla["recommendation"] = "No action required. Keep NLA enabled for all RDP endpoints."
                else:
                    f_rdp_nla["status"] = "WARNING"
                    f_rdp_nla["risk_points"] = 5
                    f_rdp_nla["note"] = f"RDP NLA appears DISABLED or misconfigured (UserAuthentication={iv})."
                    f_rdp_nla["recommendation"] = "Enable Network Level Authentication (NLA) for RDP to prevent pre-authentication interaction with the logon screen and reduce brute-force / credential harvesting risk."
            except Exception:
                f_rdp_nla["status"] = "UNKNOWN"
                f_rdp_nla["note"] = f"Could not interpret RDP 'UserAuthentication' value: {value!r}."
                f_rdp_nla["recommendation"] = "Review RDP NLA configuration manually."
        elif status == "NOT_FOUND":
            f_rdp_nla["status"] = "UNKNOWN"
            f_rdp_nla["note"] = "RDP 'UserAuthentication' value not found for RDP-Tcp."
            f_rdp_nla["recommendation"] = "Check RDP NLA setting in System Properties -> Remote."
        elif status == "PERMISSION":
            f_rdp_nla["status"] = "UNKNOWN"
            f_rdp_nla["note"] = "Admin rights required to query RDP 'UserAuthentication' registry value."
            f_rdp_nla["recommendation"] = "Re-run AZAD as Administrator for accurate RDP NLA status."
        else:
            f_rdp_nla["status"] = "UNKNOWN"
            f_rdp_nla["note"] = f"Error querying RDP NLA setting: {err}"
            f_rdp_nla["recommendation"] = "Review RDP configuration manually."

    f_rdp_nla["mitre"] = ["T1021.001"]
    findings.append(f_rdp_nla)

    asr_rules = {
        "AUTH_ASR_LSASS": ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Memory", "Defender ASR: Block credential stealing from LSASS"),
    }

    ps_script = r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
    $mp = Get-MpPreference
    if (-not $mp) {
        Write-Output 'NO_DEFENDER'
        exit
    }
    $ids = $mp.AttackSurfaceReductionRules_Ids
    $acts = $mp.AttackSurfaceReductionRules_Actions
    if (-not $ids -or -not $acts) {
        Write-Output 'NO_RULES'
        exit
    }
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $id = $ids[$i]
        $action = $acts[$i]
        Write-Output "$id;$action"
    }
} catch {
    Write-Output 'ASR_ERROR'
}
"""
    ok_asr, out_asr, err_asr = run_cmd(["powershell", "-Command", ps_script])

    asr_token = None
    asr_map = {}

    if not ok_asr:
        asr_token = "ERROR"
    else:
        lines = [l.strip() for l in (out_asr or "").splitlines() if l.strip()]
        if not lines:
            asr_token = "NO_OUTPUT"
        elif lines[-1] in ("NO_DEFENDER", "NO_RULES", "ASR_ERROR"):
            asr_token = lines[-1]
        else:
            for line in lines:
                if ";" not in line:
                    continue
                rid, ract = line.split(";", 1)
                rid_lower = rid.strip().lower()
                try:
                    act_val = int(ract.strip())
                except Exception:
                    act_val = -1
                asr_map[rid_lower] = act_val

    def build_asr_finding(fid, guid, category, name):
        f = new_finding(fid, category, name, severity="MEDIUM", requires_admin=False)

        if asr_token is not None and (not asr_map):
            if asr_token == "NO_DEFENDER":
                f["status"] = "UNKNOWN"
                f["note"] = "Get-MpPreference indicates Microsoft Defender is not managing ASR rules on this endpoint (another AV/EDR is likely in control)."
            elif asr_token == "NO_RULES":
                f["status"] = "UNKNOWN"
                f["note"] = "Get-MpPreference returned no ASR rules configured."
            elif asr_token == "ASR_ERROR":
                f["status"] = "UNKNOWN"
                f["note"] = "An error occurred while reading Defender ASR rules."
            elif asr_token == "NO_OUTPUT":
                f["status"] = "UNKNOWN"
                f["note"] = "Could not retrieve Defender ASR rules output."
            elif asr_token == "ERROR":
                f["status"] = "UNKNOWN"
                f["note"] = f"Could not query Defender ASR rules via Get-MpPreference: {err_asr}"
            else:
                f["status"] = "UNKNOWN"
                f["note"] = "Defender ASR rule state could not be determined."
            f["recommendation"] = "If Microsoft Defender is the primary AV/EDR, configure ASR rules according to the security baseline. If using third-party EDR, ensure equivalent protections are enforced."
            return f

        rule_guid = guid.lower()
        if rule_guid not in asr_map:
            f["status"] = "UNKNOWN"
            f["note"] = "Defender ASR rules are configured, but this specific rule GUID was not found among AttackSurfaceReductionRules_Ids."
            f["recommendation"] = f"Add and enable the ASR rule '{name}' (GUID {guid}) in Microsoft Defender, or configure an equivalent rule in your EDR."
            return f

        act_val = asr_map[rule_guid]
        if act_val == 1:
            f["status"] = "OK"
            f["note"] = f"ASR rule is configured in BLOCK mode (action={act_val})."
            f["recommendation"] = "No action required. Keep this ASR rule in Block mode."
        elif act_val in (2, 6):
            f["status"] = "WARNING"
            f["risk_points"] = 5
            f["note"] = f"ASR rule is present but not in full Block mode (action={act_val}, Audit/Warn)."
            f["recommendation"] = "Consider switching this ASR rule to Block mode for stronger protection, after testing in audit-only mode."
        elif act_val == 0:
            f["status"] = "WARNING"
            f["risk_points"] = 5
            f["note"] = f"ASR rule is configured but NotConfigured/Disabled (action={act_val})."
            f["recommendation"] = "Enable this ASR rule in Block mode to raise the cost of related attack techniques."
        else:
            f["status"] = "UNKNOWN"
            f["note"] = f"ASR rule found with unrecognized action value: {act_val!r}."
            f["recommendation"] = "Review ASR rule configuration manually in Defender and ensure it aligns with your security baseline."
        return f

    for fid, (guid, cat, name) in asr_rules.items():
        f_asr = build_asr_finding(fid, guid, cat, name)
        f_asr["mitre"] = ["T1003.001", "T1562.001"]
        findings.append(f_asr)

    return findings

def firewall_module():
    findings = []
    profiles = {
        "FW_DOMAIN": ("Domain Profile Settings - Firewall", "domainprofile"),
        "FW_PRIVATE": ("Private Profile Settings - Firewall", "privateprofile"),
        "FW_PUBLIC": ("Public Profile Settings - Firewall", "publicprofile"),
    }

    for fid, (desc, profile) in profiles.items():
        f = new_finding(fid, "Firewall", desc, severity="LOW", requires_admin=True)
        ok, out, err = run_cmd(["netsh", "advfirewall", "show", profile])
        if ok:
            if "State" in out and "ON" in out.upper():
                f["status"] = "OK"
                f["note"] = f"Windows Firewall for {profile} appears ON."
                f["recommendation"] = "No action required. Keep firewall rules reviewed and updated."
            else:
                f["status"] = "WARNING"
                f["risk_points"] = 5
                f["note"] = f"Firewall for {profile} may be OFF or misconfigured."
                f["recommendation"] = "Ensure firewall is enabled and configured according to security baseline."
        else:
            if "denied" in err.lower() or "access is denied" in err.lower():
                f["status"] = "UNKNOWN"
                f["note"] = "Admin required to query firewall profile with netsh."
                f["recommendation"] = "Re-run AZAD as Administrator for accurate firewall status."
            else:
                f["status"] = "UNKNOWN"
                f["note"] = f"Could not query firewall for {profile}: {err}"
                f["recommendation"] = "Check firewall status manually via Windows Defender Firewall UI."

        f["mitre"] = ["T1562"]
        findings.append(f)

    return findings

def network_module():
    findings = []

    f_ports = new_finding("NET_PORTS", "Network", "Listening ports", severity="MEDIUM", requires_admin=False)

    ok, out, err = run_cmd(["netstat", "-ano"])
    if ok:
        listening_any_addr = set()
        for line in out.splitlines():
            if "LISTENING" not in line.upper():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            local_addr = parts[1]
            if ":" not in local_addr:
                continue
            addr, port_str = local_addr.rsplit(":", 1)
            addr = addr.strip("[]")
            try:
                port = int(port_str)
            except ValueError:
                continue
            if port not in HIGH_RISK_PORTS:
                continue
            if addr in ("0.0.0.0", "::"):
                listening_any_addr.add(port)

        exposed_ports = set()
        fw_error = None
        if listening_any_addr:
            ps_script = r"""
$ports = 135,139,445,3389
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
    Get-NetFirewallPortFilter |
    Where-Object { $_.LocalPort -in $ports } |
    Select-Object -ExpandProperty LocalPort
"""
            ok_fw, fw_out, fw_err = run_cmd(["powershell", "-Command", ps_script])
            if ok_fw and fw_out:
                allowed_ports = set()
                for line in fw_out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        p = int(line)
                    except ValueError:
                        continue
                    if p in HIGH_RISK_PORTS:
                        allowed_ports.add(p)
                exposed_ports = listening_any_addr & allowed_ports
            else:
                fw_error = fw_err or "Could not query firewall port filters via PowerShell"
                exposed_ports = listening_any_addr

        if not listening_any_addr:
            f_ports["status"] = "OK"
            f_ports["note"] = "No high-risk listening ports detected on 0.0.0.0/::."
            f_ports["recommendation"] = "No action required."
        else:
            if exposed_ports:
                f_ports["status"] = "WARNING"
                f_ports["risk_points"] = 5
                f_ports["note"] = f"High-risk ports listening on any address and allowed by firewall: {sorted(exposed_ports)}."
                if fw_error:
                    f_ports["note"] += f" (Firewall query degraded: {fw_error})"
                f_ports["recommendation"] = "Review exposed services on ports 135/139/445/3389. Restrict exposure via firewall, segment networks and remove unnecessary services."
            else:
                f_ports["status"] = "OK"
                msg = "High-risk ports are either not listening on 0.0.0.0/:: or blocked by firewall."
                if fw_error:
                    msg += f" (Could not fully verify firewall rules: {fw_error})"
                f_ports["note"] = msg
                f_ports["recommendation"] = "No high-risk ports exposed externally based on current firewall and listening state."

    else:
        f_ports["status"] = "UNKNOWN"
        f_ports["note"] = f"Could not execute netstat: {err}"
        f_ports["recommendation"] = "Check listening ports manually with netstat or equivalent."

    f_ports["mitre"] = ["T1021", "T1046"]
    findings.append(f_ports)

    f_rdp = new_finding("NET_RDP", "Network", "Remote Desktop (RDP)", severity="LOW", requires_admin=True)
    if winreg:
        path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "fDenyTSConnections")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 1:
                    f_rdp["status"] = "OK"
                    f_rdp["note"] = "RDP appears DISABLED (fDenyTSConnections=1)."
                    f_rdp["recommendation"] = "No action required. RDP disabled reduces attack surface."
                else:
                    f_rdp["status"] = "WARNING"
                    f_rdp["risk_points"] = 5
                    f_rdp["note"] = "RDP appears ENABLED (fDenyTSConnections=0)."
                    f_rdp["recommendation"] = "Ensure RDP is restricted (VPN-only, MFA, network-level authentication) if required, or disable if not needed."
            except Exception:
                f_rdp["status"] = "UNKNOWN"
                f_rdp["note"] = f"Could not interpret fDenyTSConnections value: {value!r}."
                f_rdp["recommendation"] = "Review RDP configuration manually."
        elif status == "NOT_FOUND":
            f_rdp["status"] = "UNKNOWN"
            f_rdp["note"] = "RDP registry key/value not found."
            f_rdp["recommendation"] = "Check RDP status in System Properties -> Remote."
        elif status == "PERMISSION":
            f_rdp["status"] = "UNKNOWN"
            f_rdp["note"] = "Admin required to query RDP registry key."
            f_rdp["recommendation"] = "Re-run AZAD as Administrator for accurate RDP status."
        else:
            f_rdp["status"] = "UNKNOWN"
            f_rdp["note"] = f"Error querying RDP setting: {err}"
            f_rdp["recommendation"] = "Check RDP configuration manually."
    else:
        f_rdp["status"] = "UNKNOWN"
        f_rdp["note"] = "winreg not available (non-Windows)."
        f_rdp["recommendation"] = "Run on Windows endpoint only."

    f_rdp["mitre"] = ["T1021.001"]
    findings.append(f_rdp)

    f_smb1 = new_finding("NET_SMBV1", "Network", "SMBv1 configuration", severity="HIGH", requires_admin=True)
    smb_status, smb_note = check_smbv1()

    if smb_status == "ENABLED":
        f_smb1["status"] = "WARNING"
        f_smb1["risk_points"] = 10
        f_smb1["note"] = smb_note
        f_smb1["recommendation"] = "Disable SMBv1 unless absolutely required. SMBv1 is associated with legacy exploits like EternalBlue and multiple ransomware families that pivot via SMBv1."
    elif smb_status == "DISABLED":
        f_smb1["status"] = "OK"
        f_smb1["risk_points"] = 0
        f_smb1["note"] = smb_note
        f_smb1["recommendation"] = "No action required. SMBv1 appears disabled or not installed by default on this system."
    else:
        f_smb1["status"] = "UNKNOWN"
        f_smb1["note"] = smb_note
        f_smb1["recommendation"] = "Confirm SMBv1 status manually via Windows Features and registry. In hardened environments SMBv1 should be fully removed."

    f_smb1["mitre"] = ["T1021.002", "T1210"]
    findings.append(f_smb1)

    return findings

def llmnr_netbios_module():
    findings = []

    f_llmnr = new_finding("NET_LLMNR", "Network", "LLMNR status", severity="MEDIUM", requires_admin=True)

    if not winreg:
        f_llmnr["status"] = "UNKNOWN"
        f_llmnr["note"] = "winreg not available (non-Windows)."
        f_llmnr["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "EnableMulticast")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 0:
                    f_llmnr["status"] = "OK"
                    f_llmnr["note"] = "LLMNR appears DISABLED (EnableMulticast=0)."
                    f_llmnr["recommendation"] = "No action required. Keeping LLMNR disabled reduces spoofing risk."
                else:
                    f_llmnr["status"] = "WARNING"
                    f_llmnr["risk_points"] = 5
                    f_llmnr["note"] = f"LLMNR appears ENABLED or not hardened (EnableMulticast={iv})."
                    f_llmnr["recommendation"] = "Disable LLMNR via Group Policy (Turn off multicast name resolution) to reduce credential theft via responder/relay attacks."
            except Exception:
                f_llmnr["status"] = "UNKNOWN"
                f_llmnr["note"] = f"Could not interpret EnableMulticast value: {value!r}."
                f_llmnr["recommendation"] = "Review LLMNR configuration manually."
        elif status == "NOT_FOUND":
            f_llmnr["status"] = "UNKNOWN"
            f_llmnr["note"] = "LLMNR policy key/value not found (system likely using default behavior)."
            f_llmnr["recommendation"] = "Explicitly disable LLMNR via Group Policy on hardened enterprise endpoints."
        elif status == "PERMISSION":
            f_llmnr["status"] = "UNKNOWN"
            f_llmnr["note"] = "Admin rights required to query LLMNR policy registry keys."
            f_llmnr["recommendation"] = "Re-run AZAD as Administrator or verify via gpresult /rsop."
        else:
            f_llmnr["status"] = "UNKNOWN"
            f_llmnr["note"] = f"Error querying LLMNR policy: {err}"
            f_llmnr["recommendation"] = "Review LLMNR configuration manually."

    f_llmnr["mitre"] = ["T1557", "T1187"]
    findings.append(f_llmnr)

    f_netbios = new_finding("NET_NETBIOS", "Network", "NetBIOS over TCP/IP status", severity="MEDIUM", requires_admin=True)

    if not winreg:
        f_netbios["status"] = "UNKNOWN"
        f_netbios["note"] = "winreg not available (non-Windows)."
        f_netbios["recommendation"] = "Run on Windows endpoint only."
    else:
        try:
            base_path = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path)
            index = 0
            any_enabled = False
            any_disabled = False
            interfaces_info = []
            while True:
                try:
                    sub_name = winreg.EnumKey(key, index)
                    index += 1
                except OSError:
                    break
                try:
                    sub_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path + "\\" + sub_name)
                    try:
                        val, _ = winreg.QueryValueEx(sub_key, "NetbiosOptions")
                        nb = int(val)
                        interfaces_info.append(f"{sub_name}=NetbiosOptions:{nb}")
                        if nb == 2:
                            any_disabled = True
                        else:
                            any_enabled = True
                    except FileNotFoundError:
                        interfaces_info.append(f"{sub_name}=NetbiosOptions:DEFAULT")
                        any_enabled = True
                    finally:
                        winreg.CloseKey(sub_key)
                except OSError:
                    continue

            winreg.CloseKey(key)

            if not interfaces_info:
                f_netbios["status"] = "UNKNOWN"
                f_netbios["note"] = "No NetBT interfaces found under registry."
                f_netbios["recommendation"] = "Review NetBIOS over TCP/IP status via adapter advanced settings."
            else:
                info_str = "; ".join(interfaces_info)
                if any_enabled and not any_disabled:
                    f_netbios["status"] = "WARNING"
                    f_netbios["risk_points"] = 5
                    f_netbios["note"] = "NetBIOS over TCP/IP appears ENABLED on one or more interfaces: " + info_str
                    f_netbios["recommendation"] = "Disable NetBIOS over TCP/IP on all interfaces where not explicitly required to reduce legacy name-resolution/relay attack surface."
                elif any_enabled and any_disabled:
                    f_netbios["status"] = "WARNING"
                    f_netbios["risk_points"] = 5
                    f_netbios["note"] = "Mixed NetBIOS configuration across interfaces: " + info_str
                    f_netbios["recommendation"] = "Standardize NetBIOS over TCP/IP configuration, preferably disabling it on all non-legacy network segments."
                else:
                    f_netbios["status"] = "OK"
                    f_netbios["note"] = "NetBIOS over TCP/IP appears DISABLED (NetbiosOptions=2) on all interfaces: " + info_str
                    f_netbios["recommendation"] = "No action required."
        except Exception as e:
            f_netbios["status"] = "UNKNOWN"
            f_netbios["note"] = f"Error enumerating NetBIOS over TCP/IP interfaces: {e}"
            f_netbios["recommendation"] = "Review NetBIOS configuration manually in adapter advanced settings."

    f_netbios["mitre"] = ["T1557"]
    findings.append(f_netbios)

    return findings

def accounts_module():
    findings = []

    f_admins = new_finding("ACC_ADMINS", "Accounts", "Local Administrators group", severity="MEDIUM", requires_admin=True)

    members = None
    sid_error = None
    if win32security and win32net:
        members, sid_error = get_local_admin_members_sid()

    if members is not None:
        if members:
            f_admins["status"] = "OK"
            f_admins["note"] = f"Local Administrators (SID S-1-5-32-544) members: {members}"
            if len(members) > 3:
                f_admins["status"] = "WARNING"
                f_admins["risk_points"] = 5
                f_admins["note"] = f"Local Administrators group (S-1-5-32-544) has multiple members: {members}"
                f_admins["recommendation"] = "Review local Administrators membership. Limit to strictly necessary accounts and prefer domain groups over local accounts."
            else:
                f_admins["recommendation"] = "No action required, but regularly review membership."
        else:
            f_admins["status"] = "OK"
            f_admins["note"] = "Local Administrators group (S-1-5-32-544) has no members listed."
            f_admins["recommendation"] = "Ensure only approved accounts are added when required."
    else:
        lang = get_lang_code()
        admin_group_name = ADMIN_GROUP_BY_LANG.get(lang, "Administrators")
        ok, out, err = run_cmd(["net", "localgroup", admin_group_name])
        if ok and out:
            members = []
            for line in out.splitlines():
                line = line.strip()
                if line and not line.lower().startswith("alias name") \
                   and not line.lower().startswith("comment") \
                   and not line.lower().startswith("members") \
                   and not line.startswith("-") \
                   and not line.lower().startswith("the command completed"):
                    members.append(line)
            if members:
                f_admins["status"] = "OK"
                f_admins["note"] = f"Local '{admin_group_name}' group members: {members}"
                if len(members) > 3:
                    f_admins["status"] = "WARNING"
                    f_admins["risk_points"] = 5
                    f_admins["note"] = f"Local '{admin_group_name}' group has multiple members: {members}"
                    f_admins["recommendation"] = "Review local Administrators membership. Limit to strictly necessary accounts and prefer domain groups over local accounts."
                else:
                    f_admins["recommendation"] = "No action required, but regularly review membership."
            else:
                f_admins["status"] = "OK"
                f_admins["note"] = f"Local '{admin_group_name}' group has no members listed."
                f_admins["recommendation"] = "Ensure only approved accounts are added when required."
        else:
            if sid_error:
                base_err = f"SID-based enumeration failed: {sid_error}. "
            else:
                base_err = ""
            if "1376" in (err or "") or "does not exist" in (err or "").lower():
                f_admins["status"] = "UNKNOWN"
                f_admins["note"] = base_err + f"Local group '{admin_group_name}' not found: {err}"
                f_admins["recommendation"] = "Check local Administrators group manually via 'lusrmgr.msc' or Computer Management. Ensure only approved accounts are present."
            elif "access is denied" in (err or "").lower() or "error 5" in (err or ""):
                f_admins["status"] = "UNKNOWN"
                f_admins["note"] = base_err + "Admin rights required to enumerate local Administrators group."
                f_admins["recommendation"] = "Re-run AZAD as Administrator for accurate account enumeration."
            else:
                f_admins["status"] = "UNKNOWN"
                f_admins["note"] = base_err + f"Error querying local Administrators group '{admin_group_name}': {err}"
                f_admins["recommendation"] = "Review group membership manually."

    f_admins["mitre"] = ["T1078"]
    findings.append(f_admins)

    f_guest = new_finding("ACC_GUEST", "Accounts", "Guest account status", severity="LOW", requires_admin=True)
    ok, out, err = run_cmd(["net", "user", "Guest"])
    if ok and out:
        if "Account active" in out and "No" in out:
            f_guest["status"] = "OK"
            f_guest["note"] = "Guest account appears DISABLED."
            f_guest["recommendation"] = "No action required."
        else:
            f_guest["status"] = "WARNING"
            f_guest["risk_points"] = 5
            f_guest["note"] = "Guest account may be ENABLED or misconfigured."
            f_guest["recommendation"] = "Ensure Guest account is disabled in security-sensitive environments."
    else:
        if "2221" in (err or "") or "could not be found" in (err or "").lower():
            f_guest["status"] = "OK"
            f_guest["note"] = "Guest account not found (likely removed or never created)."
            f_guest["recommendation"] = "No action required."
        elif "access is denied" in (err or "").lower() or "error 5" in (err or ""):
            f_guest["status"] = "UNKNOWN"
            f_guest["note"] = "Admin rights required to query Guest account."
            f_guest["recommendation"] = "Re-run AZAD as Administrator or confirm manually."
        else:
            f_guest["status"] = "UNKNOWN"
            f_guest["note"] = f"Error querying Guest account: {err}"
            f_guest["recommendation"] = "Check Guest account status manually."

    f_guest["mitre"] = ["T1078"]
    findings.append(f_guest)

    f_builtin = new_finding("ACC_ADMIN_BUILTIN", "Accounts", "Built-in Administrator status", severity="MEDIUM", requires_admin=True)

    ps_script = r"""
$acc = Get-CimInstance Win32_UserAccount -Filter "LocalAccount = True" |
    Where-Object { $_.SID -like '*-500' } |
    Select-Object Name,Disabled | Format-Table -HideTableHeaders
$acc
"""
    ok_ba, ba_out, ba_err = run_cmd(["powershell", "-Command", ps_script])

    if ok_ba and ba_out.strip():
        lines = [l.strip() for l in ba_out.splitlines() if l.strip()]
        line = lines[0]
        parts = line.split()
        name = parts[0]
        disabled_token = parts[-1].lower()
        disabled = disabled_token in ("true", "1", "yes")

        if disabled:
            f_builtin["status"] = "OK"
            f_builtin["note"] = f"Built-in Administrator account (RID 500, name '{name}') appears DISABLED."
            f_builtin["recommendation"] = "No action required."
        else:
            f_builtin["status"] = "WARNING"
            f_builtin["risk_points"] = 5
            f_builtin["note"] = f"Built-in Administrator account (RID 500, name '{name}') appears ENABLED."
            f_builtin["recommendation"] = "Consider disabling or renaming the built-in Administrator account, and enforce strong authentication if it must remain enabled."
    else:
        ok, out, err = run_cmd(["net", "user", "Administrator"])
        if ok and out:
            if "Account active" in out and "No" in out:
                f_builtin["status"] = "OK"
                f_builtin["note"] = "Built-in Administrator account appears DISABLED (via 'net user Administrator')."
                f_builtin["recommendation"] = "No action required."
            else:
                f_builtin["status"] = "WARNING"
                f_builtin["risk_points"] = 5
                f_builtin["note"] = "Built-in Administrator account appears ENABLED (via 'net user Administrator')."
                f_builtin["recommendation"] = "Consider disabling or renaming the built-in Administrator account, and enforce strong authentication if it must remain enabled."
        else:
            if "2221" in (err or "") or "could not be found" in (err or "").lower():
                f_builtin["status"] = "UNKNOWN"
                f_builtin["note"] = "Built-in Administrator account not found by name 'Administrator' and SID-based WMI query did not return RID 500."
                f_builtin["recommendation"] = "Confirm built-in admin status manually (SAM or local users and groups)."
            elif "access is denied" in (err or "").lower() or "error 5" in (err or ""):
                f_builtin["status"] = "UNKNOWN"
                f_builtin["note"] = "Admin rights required to query built-in Administrator account."
                f_builtin["recommendation"] = "Re-run AZAD as Administrator or verify manually."
            else:
                f_builtin["status"] = "UNKNOWN"
                f_builtin["note"] = f"Error querying built-in Administrator account: {ba_err or err}"
                f_builtin["recommendation"] = "Review account configuration manually."

    f_builtin["mitre"] = ["T1078", "T1136"]
    findings.append(f_builtin)

    return findings

def password_policy_module(domain_joined=False):
    findings = []

    f_pwd = new_finding("PWD_POLICY", "Accounts", "Password policy", severity="HIGH", requires_admin=True)
    ok, out, err = run_cmd(["net", "accounts"])
    if ok and out:
        min_len = None
        lockout = None
        for line in out.splitlines():
            if "Minimum password length" in line:
                try:
                    min_len = int(line.split()[-1])
                except Exception:
                    pass
            if "Lockout threshold" in line:
                try:
                    lockout = int(line.split()[-1])
                except Exception:
                    pass

        issues = []
        if min_len is None or min_len < 8:
            issues.append(f"Minimum password length={min_len} (weak or undefined).")
        if lockout is None or lockout == 0:
            issues.append("Lockout threshold is 0 or undefined (no lockout).")

        if not issues:
            f_pwd["status"] = "OK"
            f_pwd["note"] = "Password policy appears reasonably strong."
            f_pwd["recommendation"] = "No action required, but regularly review password policies."
        else:
            f_pwd["status"] = "WARNING"
            f_pwd["risk_points"] = 10
            f_pwd["note"] = " ".join(issues)
            f_pwd["recommendation"] = "Enforce a minimum password length of at least 8–12 characters and configure an account lockout threshold to mitigate password spraying and brute-force attacks."
    else:
        f_pwd["status"] = "UNKNOWN"
        if "access is denied" in (err or "").lower() or "error 5" in (err or "").lower():
            f_pwd["note"] = "Admin rights likely required to query password policy via 'net accounts'."
        else:
            f_pwd["note"] = f"Could not query password policy: {err}"
        f_pwd["recommendation"] = "Review password policy manually via Local Security Policy or GPO."

    if domain_joined:
        extra_note = "Domain-joined → local policy likely overridden by GPO."
        if f_pwd["note"]:
            f_pwd["note"] += " " + extra_note
        else:
            f_pwd["note"] = extra_note

        if f_pwd["status"] == "WARNING" and f_pwd["risk_points"] > 0:
            reduced = max(1, f_pwd["risk_points"] // 3)
            f_pwd["risk_points"] = min(reduced, 2)

        f_pwd["recommendation"] += " Validate effective settings via domain Group Policy (GPMC) instead of relying only on local policy."

    f_pwd["mitre"] = ["T1110"]
    findings.append(f_pwd)

    return findings

def antivirus_module():
    findings = []

    f_av = new_finding("AV_STATUS", "Security", "Antivirus / EDR presence", severity="MEDIUM", requires_admin=False)
    ok, out, err = run_cmd([
        "powershell",
        "-Command",
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState"
    ])
    if ok and out:
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if len(lines) <= 1:
            f_av["status"] = "WARNING"
            f_av["risk_points"] = 10
            f_av["note"] = "No antivirus/EDR products detected via SecurityCenter2."
            f_av["recommendation"] = "Ensure at least one modern AV/EDR solution is installed and active (e.g., Microsoft Defender, CrowdStrike, SentinelOne, etc.)."
        else:
            f_av["status"] = "OK"
            f_av["note"] = "Detected AV/EDR products:\n" + "\n".join(lines[1:])
            f_av["recommendation"] = "No action required. Verify that AV/EDR policies are enforced and up to date."
    else:
        f_av["status"] = "UNKNOWN"
        f_av["note"] = f"Could not query AV/EDR via PowerShell CIM: {err}"
        f_av["recommendation"] = "Check AV/EDR status manually via Windows Security or vendor console."

    f_av["mitre"] = ["T1562"]
    findings.append(f_av)

    return findings

def powershell_hardening_module():
    findings = []

    f_amsi_cfg = new_finding("PS_AMSI_CONFIG", "PowerShell", "AMSI configuration (registry)", severity="MEDIUM", requires_admin=True)

    if not winreg:
        f_amsi_cfg["status"] = "UNKNOWN"
        f_amsi_cfg["note"] = "winreg not available (non-Windows)."
        f_amsi_cfg["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SOFTWARE\Microsoft\Windows Script\Settings"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "AmsiEnable")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 1:
                    f_amsi_cfg["status"] = "OK"
                    f_amsi_cfg["note"] = "AmsiEnable=1 (AMSI enabled for Windows Script Host / engines that honor this setting)."
                    f_amsi_cfg["recommendation"] = "No action required. Keep AMSI enabled."
                elif iv == 0:
                    f_amsi_cfg["status"] = "WARNING"
                    f_amsi_cfg["risk_points"] = 5
                    f_amsi_cfg["note"] = "AmsiEnable=0 (AMSI explicitly disabled at registry level)."
                    f_amsi_cfg["recommendation"] = "Set AmsiEnable=1 (or remove the override) to ensure AMSI participates in script and content scanning, unless a strict legacy requirement exists."
                else:
                    f_amsi_cfg["status"] = "UNKNOWN"
                    f_amsi_cfg["note"] = f"AmsiEnable has non-standard value: {value!r}."
                    f_amsi_cfg["recommendation"] = "Review AMSI-related configuration manually."
            except Exception:
                f_amsi_cfg["status"] = "UNKNOWN"
                f_amsi_cfg["note"] = f"Could not interpret AmsiEnable value: {value!r}."
                f_amsi_cfg["recommendation"] = "Review AMSI configuration manually."
        elif status == "NOT_FOUND":
            f_amsi_cfg["status"] = "OK"
            f_amsi_cfg["note"] = "AmsiEnable registry value not found. On modern Windows, AMSI is typically enabled by default."
            f_amsi_cfg["recommendation"] = "No action required. Ensure AMSI is not disabled by unsupported tweaks."
        elif status == "PERMISSION":
            f_amsi_cfg["status"] = "UNKNOWN"
            f_amsi_cfg["note"] = "Admin rights required to query AmsiEnable registry value."
            f_amsi_cfg["recommendation"] = "Re-run AZAD as Administrator or review AMSI configuration manually."
        else:
            f_amsi_cfg["status"] = "UNKNOWN"
            f_amsi_cfg["note"] = f"Error querying AmsiEnable: {err}"
            f_amsi_cfg["recommendation"] = "Review AMSI configuration manually."

    f_amsi_cfg["mitre"] = ["T1059.001", "T1562.001"]
    findings.append(f_amsi_cfg)

    f_amsi_rt = new_finding("PS_AMSI_RUNTIME", "PowerShell", "AMSI runtime status (AmsiUtils)", severity="HIGH", requires_admin=False)

    ps_amsi = r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
    $t = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if (-not $t) {
        Write-Output 'NO_TYPE'
        exit
    }
    $f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
    if (-not $f) {
        Write-Output 'NO_FIELD'
        exit
    }
    $v = $f.GetValue($null)
    if ($v) {
        Write-Output 'INIT_FAILED_TRUE'
    } else {
        Write-Output 'INIT_FAILED_FALSE'
    }
} catch {
    Write-Output 'ERROR'
}
"""
    ok_rt, out_rt, err_rt = run_cmd(["powershell", "-Command", ps_amsi])

    if not ok_rt:
        f_amsi_rt["status"] = "UNKNOWN"
        f_amsi_rt["note"] = f"Could not query AMSI runtime state from PowerShell: {err_rt}"
        f_amsi_rt["recommendation"] = "Verify that AMSI is not being patched/bypassed at runtime. Use EDR telemetry or compare against a known-good baseline."
    else:
        token = (out_rt or "").strip().splitlines()[-1].strip() if out_rt else "NO_OUTPUT"
        if token == "INIT_FAILED_FALSE":
            f_amsi_rt["status"] = "OK"
            f_amsi_rt["note"] = "AmsiUtils.amsiInitFailed = False (AMSI initialized successfully for this PowerShell runspace)."
            f_amsi_rt["recommendation"] = "No action required."
        elif token == "INIT_FAILED_TRUE":
            f_amsi_rt["status"] = "WARNING"
            f_amsi_rt["risk_points"] = 10
            f_amsi_rt["note"] = "AmsiUtils.amsiInitFailed = True. This commonly indicates AMSI initialization failed or has been patched/bypassed for the current PowerShell process."
            f_amsi_rt["recommendation"] = "Investigate why AMSI failed to initialize. Check for offensive tooling, in-memory patches or conflicting security software. Consider enforcing PowerShell CLM and hardened logging."
        elif token in ("NO_TYPE", "NO_FIELD", "NO_OUTPUT", "ERROR"):
            f_amsi_rt["status"] = "UNKNOWN"
            if token == "NO_TYPE":
                f_amsi_rt["note"] = "AmsiUtils type not found in current PowerShell runspace (older engine or restricted environment)."
            elif token == "NO_FIELD":
                f_amsi_rt["note"] = "AmsiUtils.amsiInitFailed field not found (engine version/implementation difference)."
            elif token == "NO_OUTPUT":
                f_amsi_rt["note"] = "No output from AMSI runtime check."
            else:
                f_amsi_rt["note"] = "Error while querying AMSI runtime state."
            f_amsi_rt["recommendation"] = "Validate AMSI functionality using Defender/EDR telemetry and ensure PowerShell engines are up to date."
        else:
            f_amsi_rt["status"] = "UNKNOWN"
            f_amsi_rt["note"] = f"Unexpected AMSI runtime token: {token!r}."
            f_amsi_rt["recommendation"] = "Review AMSI behavior manually or via EDR."

    f_amsi_rt["mitre"] = ["T1059.001", "T1562.001"]
    findings.append(f_amsi_rt)

    f_clm = new_finding("PS_CLM", "PowerShell", "PowerShell Language Mode (CLM)", severity="MEDIUM", requires_admin=False)

    ps_clm = r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
    $mode = $ExecutionContext.SessionState.LanguageMode
    Write-Output $mode
} catch {
    Write-Output 'ERROR'
}
"""
    ok_clm, out_clm, err_clm = run_cmd(["powershell", "-Command", ps_clm])

    if not ok_clm:
        f_clm["status"] = "UNKNOWN"
        f_clm["note"] = f"Could not query PowerShell LanguageMode: {err_clm}"
        f_clm["recommendation"] = "Check effective PowerShell LanguageMode via constrained endpoints (e.g. AppLocker/DeviceGuard) and consider enforcing ConstrainedLanguage where appropriate."
    else:
        token = (out_clm or "").strip().splitlines()[-1].strip() if out_clm else "NO_OUTPUT"
        if token in ("ConstrainedLanguage", "NoLanguage", "RestrictedLanguage"):
            f_clm["status"] = "OK"
            f_clm["note"] = f"PowerShell LanguageMode is {token} for the queried runspace."
            f_clm["recommendation"] = "No action required. Maintain CLM enforcement for untrusted contexts and standard users."
        elif token == "FullLanguage":
            f_clm["status"] = "WARNING"
            f_clm["risk_points"] = 5
            f_clm["note"] = "PowerShell LanguageMode is FullLanguage (no CLM restrictions)."
            f_clm["recommendation"] = "Consider enforcing ConstrainedLanguageMode for standard users via DeviceGuard/Applocker/Defender Application Control, leaving FullLanguage only for highly trusted admin contexts."
        elif token in ("ERROR", "NO_OUTPUT", ""):
            f_clm["status"] = "UNKNOWN"
            f_clm["note"] = "Could not reliably determine PowerShell LanguageMode."
            f_clm["recommendation"] = "Review PowerShell LanguageMode using an interactive session and Group Policy / WDAC configuration."
        else:
            f_clm["status"] = "UNKNOWN"
            f_clm["note"] = f"Unexpected LanguageMode value: {token!r}."
            f_clm["recommendation"] = "Check LanguageMode from an admin PowerShell session."

    f_clm["mitre"] = ["T1059.001", "T1204"]
    findings.append(f_clm)

    f_sblog = new_finding("PS_SCRIPTBLOCK", "Logging", "PowerShell Script Block Logging", severity="MEDIUM", requires_admin=True)

    if not winreg:
        f_sblog["status"] = "UNKNOWN"
        f_sblog["note"] = "winreg not available (non-Windows)."
        f_sblog["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "EnableScriptBlockLogging")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 1:
                    f_sblog["status"] = "OK"
                    f_sblog["note"] = "PowerShell Script Block Logging appears ENABLED (EnableScriptBlockLogging=1)."
                    f_sblog["recommendation"] = "No action required. Ensure logs are forwarded to SIEM."
                else:
                    f_sblog["status"] = "WARNING"
                    f_sblog["risk_points"] = 5
                    f_sblog["note"] = f"Script Block Logging not fully enabled (EnableScriptBlockLogging={iv})."
                    f_sblog["recommendation"] = "Enable PowerShell Script Block Logging via Group Policy to capture full de-obfuscated scripts for detection and forensics."
            except Exception:
                f_sblog["status"] = "UNKNOWN"
                f_sblog["note"] = f"Could not interpret EnableScriptBlockLogging value: {value!r}."
                f_sblog["recommendation"] = "Review Script Block Logging configuration manually."
        elif status == "NOT_FOUND":
            f_sblog["status"] = "WARNING"
            f_sblog["risk_points"] = 5
            f_sblog["note"] = "Script Block Logging policy key/value not found (likely disabled / default)."
            f_sblog["recommendation"] = "Enable PowerShell Script Block Logging via Group Policy (Turn on PowerShell Script Block Logging)."
        elif status == "PERMISSION":
            f_sblog["status"] = "UNKNOWN"
            f_sblog["note"] = "Admin rights required to query Script Block Logging registry keys."
            f_sblog["recommendation"] = "Re-run AZAD as Administrator or review logging policy manually."
        else:
            f_sblog["status"] = "UNKNOWN"
            f_sblog["note"] = f"Error querying Script Block Logging policy: {err}"
            f_sblog["recommendation"] = "Check PowerShell logging configuration via Group Policy."

    f_sblog["mitre"] = ["T1059.001", "T1562"]
    findings.append(f_sblog)

    f_mlog = new_finding("PS_MODULELOG", "Logging", "PowerShell Module Logging", severity="MEDIUM", requires_admin=True)

    if not winreg:
        f_mlog["status"] = "UNKNOWN"
        f_mlog["note"] = "winreg not available (non-Windows)."
        f_mlog["recommendation"] = "Run on Windows endpoint only."
    else:
        path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        status, value, err = safe_reg_query(winreg.HKEY_LOCAL_MACHINE, path, "EnableModuleLogging")
        if status == "OK":
            try:
                iv = int(value)
                if iv == 1:
                    modules_note = ""
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path + "\\ModuleNames")
                        names = []
                        index = 0
                        while True:
                            try:
                                val_name, val_data, _ = winreg.EnumValue(key, index)
                                index += 1
                                if isinstance(val_data, str):
                                    names.append(f"{val_name}={val_data}")
                                else:
                                    names.append(f"{val_name}")
                            except OSError:
                                break
                        winreg.CloseKey(key)
                        if names:
                            modules_note = " Modules with logging enabled: " + ", ".join(names)
                    except FileNotFoundError:
                        modules_note = " ModuleNames list not configured (logging will apply to generic scope)."
                    except Exception as e:
                        modules_note = f" Could not enumerate ModuleNames: {e}"

                    f_mlog["status"] = "OK"
                    f_mlog["note"] = "PowerShell Module Logging appears ENABLED (EnableModuleLogging=1)." + modules_note
                    f_mlog["recommendation"] = "No action required. Ensure module logging scope (ModuleNames) is aligned with your hunting use-cases."
                else:
                    f_mlog["status"] = "WARNING"
                    f_mlog["risk_points"] = 5
                    f_mlog["note"] = f"PowerShell Module Logging not fully enabled (EnableModuleLogging={iv})."
                    f_mlog["recommendation"] = "Enable PowerShell Module Logging via Group Policy and configure ModuleNames to cover security-relevant modules (e.g., *)."
            except Exception:
                f_mlog["status"] = "UNKNOWN"
                f_mlog["note"] = f"Could not interpret EnableModuleLogging value: {value!r}."
                f_mlog["recommendation"] = "Review Module Logging configuration manually."
        elif status == "NOT_FOUND":
            f_mlog["status"] = "WARNING"
            f_mlog["risk_points"] = 5
            f_mlog["note"] = "PowerShell Module Logging policy key/value not found (likely disabled / default)."
            f_mlog["recommendation"] = "Enable PowerShell Module Logging via Group Policy (Turn on Module Logging) and configure ModuleNames."
        elif status == "PERMISSION":
            f_mlog["status"] = "UNKNOWN"
            f_mlog["note"] = "Admin rights required to query Module Logging registry keys."
            f_mlog["recommendation"] = "Re-run AZAD as Administrator or review logging policy manually."
        else:
            f_mlog["status"] = "UNKNOWN"
            f_mlog["note"] = f"Error querying Module Logging policy: {err}"
            f_mlog["recommendation"] = "Check PowerShell logging configuration via Group Policy."

    f_mlog["mitre"] = ["T1059.001", "T1562"]
    findings.append(f_mlog)

    return findings

def secureboot_bitlocker_module():
    findings = []

    f_sb = new_finding("SECURE_BOOT", "Security", "Secure Boot status", severity="MEDIUM", requires_admin=False)
    ok, out, err = run_cmd(["powershell", "-Command", "Confirm-SecureBootUEFI"])
    if ok and out:
        if "True" in out:
            f_sb["status"] = "OK"
            f_sb["note"] = "Secure Boot appears ENABLED."
            f_sb["recommendation"] = "No action required."
        elif "False" in out:
            f_sb["status"] = "WARNING"
            f_sb["risk_points"] = 5
            f_sb["note"] = "Secure Boot appears DISABLED."
            f_sb["recommendation"] = "Consider enabling Secure Boot to prevent boot-level tampering."
        else:
            f_sb["status"] = "UNKNOWN"
            f_sb["note"] = f"Unexpected output from Confirm-SecureBootUEFI: {out}"
            f_sb["recommendation"] = "Review Secure Boot status manually in firmware settings."
    else:
        f_sb["status"] = "UNKNOWN"
        f_sb["note"] = f"Could not query Secure Boot via PowerShell: {err}"
        f_sb["recommendation"] = "Check Secure Boot status manually in firmware / BIOS."

    f_sb["mitre"] = ["T1542"]
    findings.append(f_sb)

    f_bl = new_finding("BITLOCKER", "Security", "BitLocker status (OS volume)", severity="MEDIUM", requires_admin=False)
    ok, out, err = run_cmd([
        "powershell",
        "-Command",
        "Get-BitLockerVolume | Where-Object {$_.MountPoint -eq 'C:'} | Select-Object MountPoint,ProtectionStatus"
    ])
    if ok and out:
        if "ProtectionStatus" in out and "On" in out:
            f_bl["status"] = "OK"
            f_bl["note"] = "BitLocker appears ENABLED on C:."
            f_bl["recommendation"] = "No action required."
        else:
            f_bl["status"] = "WARNING"
            f_bl["risk_points"] = 5
            f_bl["note"] = "BitLocker may be DISABLED or not protecting C:."
            f_bl["recommendation"] = "Consider enabling BitLocker on OS volume to protect at-rest data."
    else:
        f_bl["status"] = "UNKNOWN"
        f_bl["note"] = f"Could not query BitLocker via PowerShell: {err}"
        f_bl["recommendation"] = "Check BitLocker status manually via Control Panel or manage-bde."

    f_bl["mitre"] = ["T1485", "T1490"]
    findings.append(f_bl)

    return findings

def audit_policy_module():
    findings = []

    f_audit = new_finding("AUDIT_LOGON", "Audit", "Logon/Logoff audit policy", severity="MEDIUM", requires_admin=True)
    ok, out, err = run_cmd(["auditpol", "/get", "/category:*"])
    if ok and out:
        normalized, lang = normalize_auditpol_output(out)
        normalized_lower = normalized.lower()
        local_logon_key = LANG_MAP.get(lang, {}).get("Inicio de sesión", "Logon")
        if "logon" in normalized_lower or local_logon_key.lower() in out.lower():
            f_audit["status"] = "OK"
            f_audit["note"] = f"Audit policy output retrieved successfully (lang={lang}). Logon category detected."
            f_audit["recommendation"] = "Verify that logon/logoff events are audited for both success and failure according to your organization's baseline."
        else:
            f_audit["status"] = "UNKNOWN"
            f_audit["note"] = f"auditpol output retrieved, but could not confirm 'Logon' category after normalization. Detected UI language code: {lang}."
            f_audit["recommendation"] = "Review Advanced Audit Policy Configuration manually. Ensure logon/logoff events are audited."
    else:
        if "0x00000057" in (err or "") or "parameter is incorrect" in (err or "").lower():
            f_audit["status"] = "UNKNOWN"
            f_audit["note"] = "Could not query audit policy via 'auditpol': parameter error."
            f_audit["recommendation"] = "Review Advanced Audit Policy Configuration manually (Local Security Policy or Group Policy). Ensure logon/logoff events are audited."
        elif "access is denied" in (err or "").lower() or "error 5" in (err or "").lower():
            f_audit["status"] = "UNKNOWN"
            f_audit["note"] = "Admin rights likely required to query audit policy via 'auditpol'."
            f_audit["recommendation"] = "Re-run AZAD as Administrator or confirm policy manually."
        else:
            f_audit["status"] = "UNKNOWN"
            f_audit["note"] = f"Could not query audit policy: {err}"
            f_audit["recommendation"] = "Check audit policy manually."

    f_audit["mitre"] = ["T1078", "T1110", "TA0002"]
    findings.append(f_audit)

    return findings

def assign_base_points(findings):
    for f in findings:
        if f["status"] == "CRITICAL":
            if f["risk_points"] == 0:
                f["risk_points"] = 15
        elif f["status"] == "WARNING":
            if f["risk_points"] == 0:
                f["risk_points"] = 5
        elif f["status"] == "UNKNOWN":
            if f["risk_points"] == 0:
                f["risk_points"] = 5

def adjust_points_by_edition(findings, edition_id):
    cls = classify_edition(edition_id)
    if cls == "HOME":
        for f in findings:
            if f["status"] == "UNKNOWN" and f["category"] in ("Memory", "Firewall", "Audit"):
                if f["risk_points"] > 0:
                    f["note"] += " [Scoring adjustment: HOME edition, UNKNOWN not penalized.]"
                    f["risk_points"] = 0

def compute_exposure_score(findings):
    total = sum(max(0, f.get("risk_points", 0)) for f in findings)
    if total <= 25:
        level = "LOW"
    elif total <= 50:
        level = "MEDIUM"
    elif total <= 75:
        level = "HIGH"
    else:
        level = "CRITICAL"
    return total, level

def build_unknown_summary(findings):
    lines = []
    for f in findings:
        if f["status"] == "UNKNOWN":
            line = (
                f" - {f['category']} - {f['name']}: {f['note']} | "
                f"Recommended: {f['recommendation']}"
            )
            lines.append(line)
    return lines

def save_json_report(filename, session_name, meta, findings, score, level, admin_flag, context, adjustments):
    data = {
        "tool": "AZAD",
        "version": "1.1",
        "scan_metadata": {
            "session": session_name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "endpoint": meta.get("hostname"),
            "user": meta.get("username"),
            "os": meta.get("os"),
            "edition": meta.get("edition"),
            "domain_name": meta.get("domain_name"),
            "domain_joined": meta.get("domain_joined"),
            "is_admin": admin_flag
        },
        "system_context": {
            "form_factor": context['form_factor'],
            "domain": context['domain'],
            "azure_ad": context['azure_ad'],
            "intune": context['intune'],
            "edr": context['edr'],
            "gpo_lockdown": context['gpo_lockdown'],
            "baseline": context['baseline']
        },
        "scoring": {
            "base_score": score - adjustments['total_adjustment'],
            "adjusted_score": score,
            "risk_level": level,
            "adjustments": {
                "total_adjustment": adjustments['total_adjustment'],
                "details": adjustments['adjustments']
            }
        },
        "findings": findings,
        "summary": {
            "total_checks": len(findings),
            "ok": sum(1 for f in findings if f["status"] == "OK"),
            "warning": sum(1 for f in findings if f["status"] == "WARNING"),
            "critical": sum(1 for f in findings if f["status"] == "CRITICAL"),
            "unknown": sum(1 for f in findings if f["status"] == "UNKNOWN")
        }
    }
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def esc_html(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def format_mitre_html(tech_list):
    if not tech_list:
        return ""
    parts = []
    for t in tech_list:
        t = t.strip()
        if not t:
            continue
        if "." in t:
            main, sub = t.split(".", 1)
            url = f"{MITRE_BASE}/{main}/{sub}"
        else:
            url = f"{MITRE_BASE}/{t}"
        parts.append(f'<a href="{url}" target="_blank" style="color:#38bdf8;text-decoration:none;">{t}</a>')
    return "; ".join(parts)

def save_html_report_with_context(filename, session_name, meta, findings, score, level, 
                                   admin_flag, unknown_items, context, adjustments):
    ts_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    level_upper = (level or "").upper()
    if level_upper == "LOW":
        risk_class = "badge-low"
        risk_label = "LOW"
    elif level_upper == "MEDIUM":
        risk_class = "badge-medium"
        risk_label = "MEDIUM"
    elif level_upper == "HIGH":
        risk_class = "badge-high"
        risk_label = "HIGH"
    else:
        risk_class = "badge-critical"
        risk_label = "CRITICAL"
    
    html_parts = []
    html_parts.append("<!doctype html>")
    html_parts.append("<html lang=\"en\">")
    html_parts.append("<head>")
    html_parts.append("<meta charset=\"utf-8\">")
    html_parts.append(f"<title>AZAD v1.1 Report - {esc_html(session_name)}</title>")
    html_parts.append("""
<style>
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background-color: #020617;
  color: #e5e7eb;
  padding: 20px;
  max-width: 1400px;
  margin: 0 auto;
}
h1, h2, h3 {
  color: #f9fafb;
}
.card {
  background: #0f172a;
  border-radius: 16px;
  padding: 24px;
  border: 1px solid #1e293b;
  box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
  margin-bottom: 24px;
}
.context-card {
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  border-left: 4px solid #3b82f6;
}
.badge-risk {
  padding: 6px 12px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  display: inline-block;
}
.badge-low { background:#022c22; color:#6ee7b7; }
.badge-medium { background:#1f2937; color:#facc15; }
.badge-high { background:#450a0a; color:#fca5a5; }
.badge-critical { background:#7f1d1d; color:#fecaca; }
.context-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
  margin-top: 16px;
}
.context-item {
  background: #1e293b;
  padding: 16px;
  border-radius: 8px;
  border-left: 3px solid #3b82f6;
}
.context-item h4 {
  margin: 0 0 8px 0;
  color: #60a5fa;
  font-size: 14px;
}
.context-item p {
  margin: 4px 0;
  font-size: 13px;
  color: #cbd5e1;
}
.adjustment-list {
  background: #1e293b;
  padding: 16px;
  border-radius: 8px;
  margin-top: 12px;
}
.adjustment-item {
  padding: 8px 0;
  border-bottom: 1px solid #334155;
  font-size: 13px;
}
.adjustment-item:last-child {
  border-bottom: none;
}
.positive-adj {
  color: #6ee7b7;
}
.negative-adj {
  color: #fca5a5;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 16px;
  font-size: 13px;
}
th, td {
  border-bottom: 1px solid #1e293b;
  padding: 10px;
  text-align: left;
  vertical-align: top;
}
th {
  background: #0f172a;
  color: #94a3b8;
  position: sticky;
  top: 0;
  font-weight: 600;
}
tr:hover {
  background: #1e293b;
}
small {
  color: #94a3b8;
}
.status-ok {
  background:#16a34a;
  color:white;
  padding:3px 8px;
  border-radius:4px;
  font-size:11px;
  font-weight:600;
}
.status-warning {
  background:#f97316;
  color:white;
  padding:3px 8px;
  border-radius:4px;
  font-size:11px;
  font-weight:600;
}
.status-critical {
  background:#b91c1c;
  color:white;
  padding:3px 8px;
  border-radius:4px;
  font-size:11px;
  font-weight:600;
}
.status-unknown {
  background:#eab308;
  color:white;
  padding:3px 8px;
  border-radius:4px;
  font-size:11px;
  font-weight:600;
}
.score-display {
  font-size: 48px;
  font-weight: 700;
  background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin: 16px 0;
}
</style>
</head>
<body>
""")
    
    html_parts.append("<div class=\"card\">")
    html_parts.append("<h1>🛡️ AZAD v1.1 Enhanced Report</h1>")
    html_parts.append("<p style=\"color:#94a3b8;font-size:14px;\">Windows Endpoint Hardening & Exposure Auditor with Context Intelligence</p>")
    html_parts.append(
        f"<p><small>Session: <strong>{esc_html(session_name)}</strong> &mdash; "
        f"Endpoint: <strong>{esc_html(meta.get('hostname'))}</strong> &mdash; "
        f"User: <strong>{esc_html(meta.get('username'))}</strong></small></p>"
    )
    html_parts.append(
        f"<p><small>OS: <strong>{esc_html(meta.get('os'))}</strong> &mdash; "
        f"Edition: <strong>{esc_html(meta.get('edition'))}</strong> &mdash; "
        f"Domain: <strong>{context['domain']['name'] or 'WORKGROUP'}</strong></small></p>"
    )
    html_parts.append(f"<p><small>Timestamp (UTC): {esc_html(ts_utc)}</small></p>")
    html_parts.append("</div>")
    
    html_parts.append("<div class=\"card context-card\">")
    html_parts.append("<h2>🧠 System Context Intelligence</h2>")
    html_parts.append("<p style=\"color:#cbd5e1;\">Adaptive scoring based on detected system characteristics</p>")
    
    html_parts.append("<div class=\"context-grid\">")
    
    ff = context['form_factor']
    html_parts.append("<div class=\"context-item\">")
    html_parts.append("<h4>💻 Form Factor</h4>")
    html_parts.append(f"<p><strong>{ff['type']}</strong> (Confidence: {ff['confidence']})</p>")
    for detail in ff['details']:
        html_parts.append(f"<p style=\"font-size:12px;color:#94a3b8;\">{esc_html(detail)}</p>")
    html_parts.append("</div>")
    
    dc = context['domain']
    html_parts.append("<div class=\"context-item\">")
    html_parts.append("<h4>🏢 Domain Context</h4>")
    html_parts.append(f"<p><strong>{dc['type'] or 'UNKNOWN'}</strong></p>")
    if dc['name']:
        html_parts.append(f"<p>{esc_html(dc['name'])}</p>")
    html_parts.append("</div>")
    
    aad = context['azure_ad']
    html_parts.append("<div class=\"context-item\">")
    html_parts.append("<h4>☁️ Azure AD Status</h4>")
    if aad['joined']:
        html_parts.append("<p><strong style=\"color:#6ee7b7;\">Joined</strong></p>")
        if aad['tenant_id']:
            html_parts.append(f"<p style=\"font-size:11px;color:#94a3b8;\">Tenant: {esc_html(aad['tenant_id'][:16])}...</p>")
    else:
        html_parts.append("<p>Not joined</p>")
    html_parts.append("</div>")
    
    intune = context['intune']
    html_parts.append("<div class=\"context-item\">")
    html_parts.append("<h4>📱 Intune/MDM</h4>")
    if intune['enrolled']:
        html_parts.append("<p><strong style=\"color:#6ee7b7;\">Enrolled</strong></p>")
    else:
        html_parts.append("<p>Not enrolled</p>")
    html_parts.append("</div>")
    
    edr = context['edr']
    html_parts.append("<div class=\"context-item\">")
    html_parts.append("<h4>🛡️ EDR Detection</h4>")
    if edr['detected']:
        html_parts.append(f"<p><strong style=\"color:#6ee7b7;\">{len(edr['products'])} product(s) detected</strong></p>")
        for prod in edr['products'][:3]:
            html_parts.append(f"<p style=\"font-size:12px;color:#cbd5e1;\">• {esc_html(prod)}</p>")
    else:
        html_parts.append("<p>No EDR detected</p>")
    html_parts.append("</div>")
    
    gpo = context['gpo_lockdown']
    html_parts.append("<div class=\"context-item\">")
    html_parts.append("<h4>🔐 GPO Lockdown Level</h4>")
    html_parts.append(f"<p><strong>{gpo['level']}</strong> ({gpo['score']}/{gpo['max_score']})</p>")
    html_parts.append(f"<p style=\"font-size:12px;color:#94a3b8;\">{len(gpo['policies_found'])} policies enforced</p>")
    html_parts.append("</div>")
    
    html_parts.append("</div>")
    
    if adjustments and adjustments['adjustments']:
        html_parts.append("<div class=\"adjustment-list\">")
        html_parts.append("<h3 style=\"margin-top:0;font-size:16px;color:#60a5fa;\">⚖️ Scoring Adjustments Applied</h3>")
        for adj in adjustments['adjustments']:
            adj_class = "positive-adj" if "-" in adj else "negative-adj"
            html_parts.append(f"<div class=\"adjustment-item {adj_class}\">{esc_html(adj)}</div>")
        html_parts.append(f"<div class=\"adjustment-item\" style=\"font-weight:600;border-top:2px solid #334155;padding-top:12px;margin-top:8px;\">")
        html_parts.append(f"Total Adjustment: {adjustments['total_adjustment']:+d} points</div>")
        html_parts.append("</div>")
    
    html_parts.append("</div>")
    
    html_parts.append("<div class=\"card\">")
    html_parts.append("<h2>📊 Exposure Score</h2>")
    html_parts.append(f"<div class=\"score-display\">{score}/100</div>")
    html_parts.append(f"<p><span class=\"badge-risk {risk_class}\">Risk Level: {risk_label}</span></p>")
    html_parts.append("</div>")
    
    html_parts.append("<div class=\"card\">")
    html_parts.append("<h2>🔍 Security Checks</h2>")
    html_parts.append("<table>")
    html_parts.append("""
    <thead>
      <tr>
        <th>Category</th>
        <th>Check</th>
        <th>Status</th>
        <th>Severity</th>
        <th>Risk Points</th>
        <th>MITRE ATT&CK</th>
        <th>Details</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
""")
    
    for f in findings:
        status = f.get("status", "UNKNOWN")
        sev = f.get("severity", "")
        risk_points = f.get("risk_points", 0)
        mitre_html = format_mitre_html(f.get("mitre", []))
        note = f.get("note", "")
        rec = f.get("recommendation", "")
        
        if status == "OK":
            status_class = "status-ok"
        elif status == "CRITICAL":
            status_class = "status-critical"
        elif status == "WARNING":
            status_class = "status-warning"
        else:
            status_class = "status-unknown"
        
        html_parts.append("      <tr>")
        html_parts.append(f"        <td>{esc_html(f.get('category'))}</td>")
        html_parts.append(f"        <td>{esc_html(f.get('name'))}</td>")
        html_parts.append(f"        <td><span class=\"{status_class}\">{esc_html(status)}</span></td>")
        html_parts.append(f"        <td>{esc_html(sev)}</td>")
        html_parts.append(f"        <td>{int(risk_points)}</td>")
        html_parts.append(f"        <td>{mitre_html}</td>")
        html_parts.append(f"        <td style=\"max-width:300px;\">{esc_html(note)}</td>")
        html_parts.append(f"        <td style=\"max-width:300px;\">{esc_html(rec)}</td>")
        html_parts.append("      </tr>")
    
    html_parts.append("    </tbody>")
    html_parts.append("  </table>")
    html_parts.append("</div>")
    
    if unknown_items:
        html_parts.append("<div class=\"card\">")
        html_parts.append("<h2>⚠️ Manual Review Required</h2>")
        html_parts.append("<ul style=\"color:#cbd5e1;\">")
        for line in unknown_items:
            html_parts.append(f"<li>{esc_html(line)}</li>")
        html_parts.append("</ul>")
        html_parts.append("</div>")
    
    html_parts.append("<div class=\"card\">")
    html_parts.append("<h3>About AZAD v1.1</h3>")
    html_parts.append(
        "<p style=\"color:#cbd5e1;\"><strong>AZAD v1.1</strong> is an enhanced defensive-only Windows endpoint "
        "hardening and exposure auditor with <strong>System Context Intelligence</strong>. "
        "It performs adaptive scoring based on detected system characteristics (form factor, domain status, "
        "Azure AD, Intune/MDM, EDR presence, and GPO lockdown level).</p>"
    )
    html_parts.append("<p style=\"color:#94a3b8;font-size:13px;\">This tool performs read-only checks and is designed for blue teams, "
        "security auditors, and system administrators to quickly identify weak configurations.</p>")
    html_parts.append("</div>")
    
    html_parts.append("</body></html>")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("".join(html_parts))

def main():
    if os.name != "nt":
        print("AZAD is intended to run on Windows endpoints.")
        return

    print_banner()
    print("   Windows Endpoint Hardening & Exposure Auditor v1.1")
    print("   Enhanced with System Context Intelligence")
    print("   leoferrer15 / AZAD")
    print("")

    admin_flag = is_admin()
    print(f"Running as administrator: {'YES' if admin_flag else 'NO (limited visibility)'}")
    print("This tool is defensive-only and performs read-only checks.")
    print("")

    session_name = input("Enter session / endpoint label (e.g., 'laptop_audit_2025'): ").strip()
    if not session_name:
        session_name = "default_session"

    print("\n🔍 Running local, defensive-only checks... Please wait.\n")

    all_findings = []

    ctx_findings, meta = context_module()
    meta['is_admin'] = admin_flag
    all_findings.extend(ctx_findings)

    print("🧠 Building system context intelligence...")
    context = build_system_context(meta)
    
    print(f"   Form Factor: {context['form_factor']['type']}")
    print(f"   Domain: {context['domain']['type']} - {context['domain']['name'] or 'N/A'}")
    print(f"   Azure AD: {'Joined' if context['azure_ad']['joined'] else 'Not joined'}")
    print(f"   Intune/MDM: {'Enrolled' if context['intune']['enrolled'] else 'Not enrolled'}")
    print(f"   EDR: {len(context['edr']['products'])} product(s) detected")
    print(f"   GPO Lockdown: {context['gpo_lockdown']['level']} ({context['gpo_lockdown']['score']}/100)")
    print("")

    policies = load_policies()

    all_findings.extend(memory_module(admin_flag))
    all_findings.extend(auth_hardening_module())
    all_findings.extend(firewall_module())
    all_findings.extend(network_module())
    all_findings.extend(llmnr_netbios_module())
    all_findings.extend(accounts_module())
    all_findings.extend(password_policy_module(meta.get("domain_joined", False)))
    all_findings.extend(antivirus_module())
    all_findings.extend(secureboot_bitlocker_module())
    all_findings.extend(audit_policy_module())
    all_findings.extend(powershell_hardening_module())

    assign_base_points(all_findings)
    edition = meta.get("edition")
    adjust_points_by_edition(all_findings, edition)
    
    print("⚖️  Applying adaptive scoring based on system context...")
    adjustments = adaptive_score_with_context(all_findings, context, policies)
    
    score, level = compute_exposure_score(all_findings)
    unknown_items = build_unknown_summary(all_findings)

    print("\n" + "="*70)
    print("=== SUMMARY ===")
    print("="*70)
    print(f"Exposure Score: {score}/100  (Risk Level: {level})")
    if adjustments['adjustments']:
        print(f"\nContext-based adjustments applied:")
        for adj in adjustments['adjustments']:
            print(f"  {adj}")
        print(f"  Total adjustment: {adjustments['total_adjustment']:+d} points")
    
    print("\n=== FINDINGS (Short view) ===")
    for f in all_findings:
        icon = "✅" if f["status"] == "OK" else ("⚠️" if f["status"] in ("WARNING", "CRITICAL") else "❓")
        print(f"{icon} [{f['category']}] {f['name']} -> {f['status']} ({f['severity']})")

    if unknown_items:
        print("\n⚠️  Manual review required for UNKNOWN items:")
        for line in unknown_items:
            print("  " + line)

    base_name = f"azad_report_{session_name}"
    json_file = base_name + ".json"
    html_file = base_name + ".html"
    
    save_json_report(json_file, session_name, meta, all_findings, score, level, admin_flag, context, adjustments)
    save_html_report_with_context(html_file, session_name, meta, all_findings, score, level, 
                                   admin_flag, unknown_items, context, adjustments)

    print(f"\n✅ Reports generated:")
    print(f"   📄 JSON report: {json_file}")
    print(f"   🌐 HTML report: {html_file}")
    print("\nDone. This tool is defensive-only and performs read-only checks.")

if __name__ == "__main__":
    main()  