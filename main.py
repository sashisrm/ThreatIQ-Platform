#!/usr/bin/env python3
"""
ThreatIQ — Threat Intelligence Platform
Full-stack SOC platform with 7 architectural layers.
Run: uvicorn main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import random
import json
import uuid
from datetime import datetime, timedelta
from typing import List, Set, Optional
from collections import deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
import uvicorn

app = FastAPI(title="ThreatIQ Platform", version="2.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# ⚠️  Change SECRET_KEY to a random 32+ character string in production.
#     Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY             = "threatiq-dev-secret-key-change-this-in-production-min-32-chars"
ALGORITHM              = "HS256"
TOKEN_EXPIRE_MINUTES   = 480   # 8-hour session

pwd_context   = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Role hierarchy — higher number = broader access
ROLE_HIERARCHY: dict = {
    "tier1":   1,   # Tier 1 Analyst   — view only
    "tier2":   2,   # Tier 2 Analyst   — triage & respond
    "tier3":   3,   # Tier 3 / Hunter  — advanced investigation
    "manager": 4,   # SOC Manager      — governance & metrics
    "admin":   5,   # Administrator    — full access
}

ROLE_META: dict = {
    "tier1":   {"label": "Tier 1 Analyst",        "tier": "T1",      "color": "#1890ff"},
    "tier2":   {"label": "Tier 2 Analyst",         "tier": "T2",      "color": "#fa8c16"},
    "tier3":   {"label": "Tier 3 / Threat Hunter", "tier": "T3",      "color": "#a855f7"},
    "manager": {"label": "SOC Manager",            "tier": "Manager", "color": "#52c41a"},
    "admin":   {"label": "Administrator",           "tier": "Admin",   "color": "#ff4d4f"},
}

# Demo user store — populated at startup with bcrypt-hashed passwords.
# In production replace with a real database query.
DEMO_USERS: dict = {}

def init_users():
    """Hash demo passwords and populate the user store at startup."""
    raw = [
        ("analyst1", "Tier1@SOC",    "J. Smith",      "tier1"),
        ("analyst2", "Tier2@SOC",    "M. Rodriguez",  "tier2"),
        ("hunter",   "Tier3@SOC",    "S. Patel",      "tier3"),
        ("manager",  "Manager@SOC",  "K. Thompson",   "manager"),
        ("admin",    "Admin@SOC",    "L. Nguyen",     "admin"),
    ]
    for username, password, name, role in raw:
        DEMO_USERS[username] = {
            "name":            name,
            "role":            role,
            "hashed_password": pwd_context.hash(password),
        }

# ── JWT helpers ────────────────────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ── Role-based dependency factory ──────────────────────────────────────────

def require_role(minimum_role: str):
    """
    FastAPI dependency that validates the JWT token and enforces a minimum role.
    Usage:  Depends(require_role("tier2"))
    """
    async def _dep(token: str = Depends(oauth2_scheme)) -> dict:
        credentials_exc = HTTPException(
            status_code=401,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username or username not in DEMO_USERS:
                raise credentials_exc
        except JWTError:
            raise credentials_exc

        user = DEMO_USERS[username]
        if ROLE_HIERARCHY.get(user["role"], 0) < ROLE_HIERARCHY[minimum_role]:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. '{user['role']}' cannot access this resource. "
                       f"Minimum required role: '{minimum_role}'.",
            )
        return {"username": username, **user}
    return _dep

# ── Pydantic auth models ───────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str
    user:         dict

# ── Auth endpoints ─────────────────────────────────────────────────────────

@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate with username + password. Returns a Bearer JWT token."""
    user = DEMO_USERS.get(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token({"sub": form_data.username, "role": user["role"]})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user={
            "username": form_data.username,
            "name":     user["name"],
            "role":     user["role"],
            **ROLE_META[user["role"]],
        },
    )

@app.get("/auth/me", tags=["Auth"])
async def get_me(current_user: dict = Depends(require_role("tier1"))):
    """Return the currently authenticated user's profile."""
    role = current_user["role"]
    return {
        "username": current_user["username"],
        "name":     current_user["name"],
        "role":     role,
        **ROLE_META[role],
    }

@app.get("/auth/users", tags=["Auth"])
async def list_users(current_user: dict = Depends(require_role("admin"))):
    """Admin only — list all user accounts."""
    return [
        {
            "username": uname,
            "name":     u["name"],
            "role":     u["role"],
            **ROLE_META[u["role"]],
        }
        for uname, u in DEMO_USERS.items()
    ]

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & MOCK DATA DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

SEVERITIES   = ["info", "low", "medium", "high", "critical"]
SEV_WEIGHTS  = [40, 25, 20, 10, 5]

SOURCE_TYPES = {
    "endpoint":    ["WIN-WS-001", "WIN-WS-042", "WIN-WS-107", "LINUX-SRV-01", "LINUX-SRV-03", "MAC-DEV-007", "WIN-WS-099"],
    "firewall":    ["PA-FW-CORE", "PA-FW-DMZ", "ASA-EDGE-01", "FORTIGATE-02"],
    "network":     ["CISCO-SW-01", "CISCO-SW-04", "NEXUS-CORE", "JUNIPER-RTR"],
    "cloud":       ["AWS-CloudTrail", "AWS-GuardDuty", "Azure-Monitor", "GCP-Audit", "Azure-Sentinel"],
    "identity":    ["AD-DC-01", "AD-DC-02", "OKTA-SSO", "AZURE-AD", "CyberArk-PAM"],
    "application": ["NGINX-WEB-01", "NGINX-WEB-02", "MSSQL-DB-01", "TOMCAT-APP", "REDIS-CACHE"],
    "email":       ["EXCHANGE-01", "O365-MAIL", "ProofPoint-GW"],
    "ot_iot":      ["SCADA-01", "PLC-LINE-A", "PLC-LINE-B", "CAMERA-NVR", "BMS-HVAC"],
}

EVENT_TYPES = {
    "endpoint":    ["ProcessCreate", "NetworkConnect", "FileCreate", "RegModify", "UserLogon", "UserLogoff", "DllLoad", "ServiceInstall"],
    "firewall":    ["ALLOW", "DENY", "THREAT_DETECTED", "VPN_AUTH", "NAT_TRANSLATE", "SESSION_END"],
    "network":     ["PORT_SCAN", "ARP_FLOOD", "DHCP_REQUEST", "VLAN_CHANGE", "LINK_DOWN", "SNMP_TRAP"],
    "cloud":       ["AssumeRole", "CreateUser", "DeleteBucket", "ModifySecGroup", "StartInstance", "StopInstance", "LoginEvent"],
    "identity":    ["AuthSuccess", "AuthFailed", "PasswordChange", "GroupModify", "MFABypass", "TokenIssued", "AccountLocked"],
    "application": ["SQLQuery", "HTTPRequest", "AppError", "DBConnection", "FileUpload", "APICall"],
    "email":       ["EmailReceived", "LinkClicked", "AttachmentOpened", "PhishingDetected", "SPAMBlocked", "EmailForwarded"],
    "ot_iot":      ["SensorReading", "CommandSent", "FirmwareUpdate", "AnomalyDetected", "DeviceOffline"],
}

ALERT_RULES = [
    ("Brute Force Login Attempt",        "high",     "Initial Access",      "T1110.001", "Multiple failed authentication attempts from single source"),
    ("Lateral Movement Detected",        "critical", "Lateral Movement",    "T1021.002", "Unusual SMB connections between internal hosts detected"),
    ("Data Exfiltration Suspected",      "critical", "Exfiltration",        "T1041",     "Large outbound data transfer to external IP detected"),
    ("C2 Beaconing Activity",            "high",     "Command & Control",   "T1071.001", "Periodic outbound HTTP connections matching C2 pattern"),
    ("Privilege Escalation Attempt",     "high",     "Privilege Escalation","T1548.002", "Process running with elevated privileges unexpectedly"),
    ("Ransomware Behavior Detected",     "critical", "Impact",              "T1486",     "Mass file modification with known ransomware extension"),
    ("SQL Injection Attempt",            "medium",   "Initial Access",      "T1190",     "SQL injection payload detected in web application request"),
    ("Phishing Link Clicked",            "high",     "Initial Access",      "T1566.002", "User clicked known phishing URL from email"),
    ("Suspicious PowerShell Execution",  "high",     "Execution",           "T1059.001", "Encoded PowerShell command execution detected on endpoint"),
    ("Account Created Outside Hours",    "medium",   "Persistence",         "T1136.001", "New user account created outside business hours"),
    ("Outbound DNS Tunneling",           "high",     "Exfiltration",        "T1048.003", "Abnormal DNS query volume suggesting data tunneling"),
    ("Mimikatz Credential Dump",         "critical", "Credential Access",   "T1003.001", "Credential dumping tool signature detected in memory"),
    ("Port Scan Detected",               "low",      "Discovery",           "T1046",     "Sequential port scan detected from internal host"),
    ("Firewall Rule Modified",           "medium",   "Defense Evasion",     "T1562.004", "Critical firewall rule disabled or modified"),
    ("Cloud Storage Bucket Exposed",     "high",     "Initial Access",      "T1530",     "S3 bucket ACL changed to public read access"),
    ("Kerberoasting Attack",             "critical", "Credential Access",   "T1558.003", "Service ticket request for multiple SPNs detected"),
    ("Pass-the-Hash Activity",           "critical", "Lateral Movement",    "T1550.002", "NTLM authentication with hash reuse detected"),
    ("Suspicious Scheduled Task",        "medium",   "Persistence",         "T1053.005", "New scheduled task created by non-admin user"),
]

IOC_FEEDS    = ["AlienVault OTX", "VirusTotal", "Abuse.ch", "MISP Community", "EmergingThreats", "Cisco Talos", "Shodan Intel"]
THREAT_TYPES = ["malware", "c2", "phishing", "botnet", "scanner", "ransomware", "apt", "cryptominer"]

PLAYBOOKS = [
    ("Phishing Response",       6,  ["Quarantine Email",      "Block Sender Domain",  "Detonate Link in Sandbox", "Notify User",       "Hunt Similar Emails",   "Update Email Filter"]),
    ("Malware Containment",     6,  ["Isolate Host",          "Capture Memory Dump",  "Kill Malicious Process",  "Remove Persistence","Scan Network Shares",   "Restore from Backup"]),
    ("Account Compromise",      6,  ["Disable Account",       "Reset Password",       "Revoke Active Sessions",  "Review Activity",   "Enable MFA",            "Notify User & HR"]),
    ("DDoS Mitigation",         6,  ["Enable Rate Limiting",  "Activate Scrubbing",   "Block Attacking IPs",     "Notify ISP",        "Monitor Bandwidth",     "Document Attack"]),
    ("Ransomware Response",     6,  ["Isolate Affected Hosts","Identify Patient Zero","Disable Network Shares",  "Notify Management", "Assess Backup Integrity","Engage IR Team"]),
    ("Insider Threat",          6,  ["Capture Evidence",      "Restrict Access",      "Review Data Transfers",   "Notify HR & Legal", "Preserve Logs",         "Escalate"]),
    ("Cloud Misconfiguration",  6,  ["Remediate Exposure",    "Review IAM Policies",  "Enable Logging",          "Check Data Access", "Apply SCPs",            "Update Runbook"]),
    ("Credential Stuffing",     6,  ["Block Source IPs",      "Enforce MFA",          "Reset Compromised Accounts","Alert Users",     "Review Auth Logs",      "Update WAF Rules"]),
    ("Kerberoasting Defense",   5,  ["Identify Targeted SPNs","Reset Service Accounts","Enable AES Encryption",  "Alert Tier-3",      "Hunt Lateral Movement"]),
    ("Zero-Day Response",       5,  ["Identify Affected Systems","Apply Virtual Patch","Increase Monitoring",    "Notify Vendor",     "Prepare Remediation"]),
]

ANALYSTS = ["A.Chen", "M.Rodriguez", "S.Patel", "K.Thompson", "L.Nguyen", "J.Williams", "R.Kumar", "D.Okonkwo"]

FAKE_IPS_EXT = [
    "185.220.101.45", "91.108.4.1", "45.33.32.156", "198.51.100.23",
    "203.0.113.47", "104.21.234.67", "77.88.55.60", "94.140.14.14",
    "185.156.73.54", "212.102.35.140", "89.44.9.243", "46.148.26.86",
    "193.32.162.88", "51.77.134.95", "45.142.212.100", "178.128.23.9",
]
FAKE_DOMAINS = [
    "evil-malware.ru", "phish-update.com", "c2-beacon.net", "data-exfil.xyz",
    "update-secure.info", "cdn-tracking.pw", "api-service.cc", "logins-verify.tk",
]
FAKE_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e", "a87ff679a2f3e71d9181a67b7542122c",
    "e4da3b7fbbce2345d7772b0674a318d5", "1679091c5a880faf6fb5e6087eb1b2dc",
    "8f14e45fceea167a5a36dedd4bea2543", "c4ca4238a0b923820dcc509a6f75849b",
]
FAKE_USERS = ["jsmith", "mwilson", "admin", "svc_backup", "dba_user", "webmaster",
              "a.chen", "m.rodriguez", "readonly", "svc_monitor", "ldap_sync", "n.patel"]

INCIDENT_TITLES = [
    "Suspected Ransomware Infection on Finance Workstation",
    "Active C2 Communication from Engineering Network",
    "Credential Stuffing Campaign Targeting Employee Portal",
    "Insider Data Exfiltration via USB Device",
    "Cloud Misconfiguration — S3 Bucket Publicly Exposed",
    "Phishing Campaign Targeting HR Department",
    "Lateral Movement Across DMZ Segment",
    "Brute Force Attack on VPN Gateway",
    "SCADA System Anomaly — Unauthorized Command Sequence",
    "Supply Chain Indicator of Compromise Detected",
    "Zero-Day Exploit Attempt on Web Application",
    "Domain Admin Account Compromise Suspected",
    "Mass Mailbox Access by Service Account",
    "Network Segmentation Bypass Attempt",
    "Critical Asset Under Active Attack — IR Required",
    "Kerberoasting Attack Detected in AD Environment",
    "Pass-the-Hash Lateral Movement Chain",
]

GEO_COUNTRIES = ["US", "RU", "CN", "DE", "BR", "UA", "IN", "KR", "IR", "NL", "FR", "GB"]

# ══════════════════════════════════════════════════════════════════════════════
# IN-MEMORY STORES
# ══════════════════════════════════════════════════════════════════════════════

logs_store:      deque       = deque(maxlen=500)
alerts_store:    List[dict]  = []
iocs_store:      List[dict]  = []
incidents_store: List[dict]  = []
playbook_runs:   List[dict]  = []
sources_store:   List[dict]  = []
rules_store:     List[dict]  = []

stats: dict = {
    "logs_today":       0,
    "alerts_today":     0,
    "incidents_open":   0,
    "threats_blocked":  0,
    "logs_per_min":     0,
    "mttd_minutes":     12.4,
    "mttr_minutes":     47.8,
    "sources_active":   0,
    "iocs_total":       0,
    "sources_total":    0,
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.utcnow().microsecond // 1000:03d}Z"

def ts_ago(hours: int = 0, minutes: int = 0) -> str:
    dt = datetime.utcnow() - timedelta(hours=hours, minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def rand_ip(external: bool = False) -> str:
    if external:
        return random.choice(FAKE_IPS_EXT)
    return f"10.{random.randint(0,10)}.{random.randint(1,20)}.{random.randint(1,254)}"

def rand_user() -> str:
    return random.choice(FAKE_USERS)

def generate_log_message(src_type: str, evt_type: str, severity: str) -> str:
    user = rand_user()
    src  = rand_ip(external=random.random() > 0.6)
    dst  = rand_ip()
    port = random.randint(1, 65535)
    templates = {
        "ProcessCreate":    f"Process spawned: {'powershell.exe -enc JABjAG0AZAAgAA==' if severity in ('high','critical') else 'notepad.exe'} | parent=explorer.exe | user={user} | pid={random.randint(1000,9999)}",
        "NetworkConnect":   f"Outbound connection: {src}:{random.randint(1024,65535)} → {dst}:{port} | proto=TCP | bytes={random.randint(100,500000)}",
        "FileCreate":       f"File created: {'C:\\Windows\\Temp\\svch0st.exe' if severity in ('critical','high') else 'C:\\Users\\'+user+'\\Downloads\\report.docx'} | size={random.randint(1,50000)}KB",
        "RegModify":        f"Registry key modified: {'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' if severity in ('high','critical') else 'HKCU\\Software\\App\\Prefs'} | user={user}",
        "UserLogon":        f"User logon: {user} | type={'RemoteInteractive' if severity == 'critical' else 'Interactive'} | src={src} | workstation=WIN-WS-{random.randint(1,200):03d}",
        "DllLoad":          f"DLL loaded: {'C:\\Windows\\Temp\\payload.dll' if severity == 'critical' else 'C:\\Windows\\System32\\ntdll.dll'} | proc=lsass.exe | signed={str(severity not in ('high','critical')).lower()}",
        "ALLOW":            f"FW ALLOW: {src} → {dst}:{port}/TCP | rule=OUTBOUND-GENERAL | bytes={random.randint(500,1000000)}",
        "DENY":             f"FW BLOCK: {src} → {dst}:{port}/TCP | reason={random.choice(['GEO-BLOCK','THREAT-INTEL','POLICY-DENY','IPS-SIGNATURE'])} | sig_id={random.randint(1000,9999)}",
        "THREAT_DETECTED":  f"IPS ALERT: sig={random.choice(['ET.MALWARE.C2','GPL.SCAN.NMAP','ET.EXPLOIT.MS17010'])} src={src} dst={dst} | severity={severity.upper()}",
        "VPN_AUTH":         f"VPN {'AUTH-FAILED' if severity in ('high','critical') else 'AUTH-SUCCESS'}: user={user} | src={rand_ip(True)} | method=IPSEC | attempts={random.randint(1,50)}",
        "PORT_SCAN":        f"Port scan: {src} scanned {random.randint(50,2000)} ports on {dst} | duration={random.randint(1,120)}s | open_ports={random.randint(0,20)}",
        "AuthFailed":       f"AUTH FAILURE: user={user} | src={rand_ip(True)} | attempts={random.randint(1,200)} | method={random.choice(['password','kerberos','ntlm'])}",
        "AuthSuccess":      f"AUTH SUCCESS: user={user} | src={src} | method={random.choice(['password+MFA','kerberos','smartcard'])} | device=WIN-WS-{random.randint(1,200):03d}",
        "AssumeRole":       f"IAM AssumeRole: principal={user} | role={'OrganizationAccountAccessRole' if severity == 'critical' else 'ReadOnlyAccess'} | src={rand_ip(True)} | region={random.choice(['us-east-1','eu-west-1','ap-southeast-1'])}",
        "DeleteBucket":     f"S3 DeleteBucket: bucket=prod-data-{random.randint(1,20)} | user={user} | src={rand_ip(True)} | mfa_used={str(random.random() > 0.5).lower()}",
        "ModifySecGroup":   f"EC2 ModifySecurityGroup: sg-{uuid.uuid4().hex[:8]} | change=ALLOW_0.0.0.0/0:{port} | user={user}",
        "SQLQuery":         f"SQL: {'SELECT * FROM users WHERE id=1 OR 1=1--' if severity in ('high','critical') else 'SELECT id,name FROM products WHERE category=?'} | user={user} | rows={random.randint(0,10000)}",
        "HTTPRequest":      f"HTTP {random.choice(['GET','POST','PUT']) if severity == 'info' else 'POST'} {rand_ip(True)} → /{'admin/users' if severity == 'critical' else 'api/products'} | status={random.choice([200,403,500,404])} | size={random.randint(100,50000)}B",
        "PhishingDetected": f"Phishing blocked: from=attacker@{random.choice(FAKE_DOMAINS)} | to={user}@company.com | subject='Urgent: Password Reset Required' | action=QUARANTINE",
        "LinkClicked":      f"Malicious URL clicked: {user}@company.com clicked http://{random.choice(FAKE_DOMAINS)}/login | src={src} | mail_id={uuid.uuid4().hex[:8]}",
        "AnomalyDetected":  f"OT anomaly: device={random.choice(['PLC-LINE-A','SCADA-01','BMS-HVAC'])} | unexpected command sequence | baseline_deviation={random.randint(30,200)}%",
        "ServiceInstall":   f"Service installed: name={'WindowsUpdate' if severity == 'critical' else 'PrintSpooler'}_svc | path={'C:\\Temp\\update.exe' if severity in ('high','critical') else 'C:\\Windows\\System32\\spoolsv.exe'} | user={user}",
    }
    return templates.get(evt_type, f"[{src_type.upper()}] {evt_type}: src={src} dst={dst} user={user} sev={severity.upper()}")

# ══════════════════════════════════════════════════════════════════════════════
# DATA INITIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

def init_sources():
    for stype, names in SOURCE_TYPES.items():
        for name in names:
            sources_store.append({
                "id":           str(uuid.uuid4())[:8],
                "name":         name,
                "type":         stype,
                "status":       random.choices(["active","active","active","warning","offline"], weights=[70,70,70,15,5])[0],
                "logs_per_min": random.randint(15, 600),
                "last_seen":    ts_ago(minutes=random.randint(0, 5)),
                "ip":           rand_ip(),
                "location":     random.choice(["HQ-DC1","HQ-DC2","Cloud-AWS","Cloud-Azure","Branch-NY","Branch-LON","Branch-SG"]),
                "tags":         [stype],
                "os":           random.choice(["Windows Server 2022","Ubuntu 22.04","CentOS 8","N/A","Cloud"]),
                "version":      f"{random.randint(8,12)}.{random.randint(0,9)}.{random.randint(0,99)}",
            })
    stats["sources_active"] = len([s for s in sources_store if s["status"] == "active"])
    stats["sources_total"]  = len(sources_store)

def init_iocs(n: int = 130):
    for _ in range(n):
        ioc_type = random.choice(["ip","domain","hash","url","email"])
        if ioc_type == "ip":           value = random.choice(FAKE_IPS_EXT)
        elif ioc_type == "domain":     value = random.choice(FAKE_DOMAINS)
        elif ioc_type == "hash":       value = random.choice(FAKE_HASHES)
        elif ioc_type == "url":        value = f"http://{random.choice(FAKE_DOMAINS)}/{uuid.uuid4().hex[:8]}"
        else:                          value = f"attacker_{uuid.uuid4().hex[:6]}@{random.choice(FAKE_DOMAINS)}"
        days_ago = random.randint(0, 30)
        iocs_store.append({
            "id":          str(uuid.uuid4())[:8],
            "type":        ioc_type,
            "value":       value,
            "confidence":  random.randint(60, 99),
            "source":      random.choice(IOC_FEEDS),
            "tags":        random.sample(THREAT_TYPES, k=random.randint(1, 2)),
            "threat_type": random.choice(THREAT_TYPES),
            "first_seen":  ts_ago(hours=days_ago * 24 + 5),
            "last_seen":   ts_ago(hours=days_ago * 24),
            "hits":        random.randint(0, 200),
            "active":      True,
        })
    stats["iocs_total"] = len(iocs_store)

def init_rules():
    for i, (name, sev, tactic, tech, desc) in enumerate(ALERT_RULES):
        rules_store.append({
            "id":             f"RULE-{i+1:04d}",
            "name":           name,
            "severity":       sev,
            "mitre_tactic":   tactic,
            "mitre_technique":tech,
            "description":    desc,
            "enabled":        True,
            "hits_today":     random.randint(0, 80),
            "last_triggered": ts_ago(minutes=random.randint(1, 480)) if random.random() > 0.2 else None,
            "category":       random.choice(["Network","Endpoint","Identity","Cloud","Email"]),
        })

def init_alerts(n: int = 70):
    for _ in range(n):
        rule = random.choice(ALERT_RULES)
        dt   = datetime.utcnow() - timedelta(hours=random.randint(0, 48))
        status = random.choices(
            ["new","investigating","escalated","resolved","false_positive"],
            weights=[30, 25, 10, 25, 10]
        )[0]
        alerts_store.append({
            "id":             f"ALERT-{uuid.uuid4().hex[:6].upper()}",
            "timestamp":      dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rule_name":      rule[0],
            "severity":       rule[1],
            "source_ip":      rand_ip(external=random.random() > 0.45),
            "dest_ip":        rand_ip(),
            "user":           rand_user() if random.random() > 0.3 else None,
            "description":    rule[4],
            "status":         status,
            "mitre_tactic":   rule[2],
            "mitre_technique":rule[3],
            "log_count":      random.randint(1, 80),
            "enrichment": {
                "geo":              random.choice(GEO_COUNTRIES),
                "asn":              f"AS{random.randint(1000, 65000)}",
                "reputation":       random.choice(["Malicious","Suspicious","Unknown","Clean"]),
                "threat_intel_hits":random.randint(0, 8),
                "isp":              random.choice(["Cloudflare","Amazon AWS","Google","DigitalOcean","Hetzner","OVH"]),
            }
        })
    stats["alerts_today"] = len([a for a in alerts_store if a["severity"] in ("high","critical")])

def init_incidents(n: int = 17):
    for i in range(n):
        sev    = random.choice(["medium","high","critical"])
        status = random.choice(["open","investigating","contained","resolved"])
        pb     = random.choice(PLAYBOOKS)
        dt     = datetime.utcnow() - timedelta(hours=random.randint(0, 72))
        steps_done = random.randint(0, pb[0 + 1])  # pb[1] = total_steps
        incidents_store.append({
            "id":             f"INC-{1000 + i}",
            "title":          INCIDENT_TITLES[i % len(INCIDENT_TITLES)],
            "severity":       sev,
            "status":         status,
            "assigned_to":    random.choice(ANALYSTS),
            "created_at":     dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updated_at":     (dt + timedelta(minutes=random.randint(5, 200))).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "alert_ids":      [f"ALERT-{uuid.uuid4().hex[:6].upper()}" for _ in range(random.randint(1, 10))],
            "playbook":       pb[0],
            "playbook_steps": pb[2],
            "steps_completed":steps_done,
            "total_steps":    pb[1],
            "description":    f"Incident detected via SIEM correlation. Severity: {sev.upper()}. Immediate investigation required.",
            "analyst_notes":  "",
            "timeline": [
                {"time": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),                                      "action": "Incident created",          "actor": "SIEM Automation"},
                {"time": (dt + timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),              "action": "Playbook triggered",        "actor": "SOAR Engine"},
                {"time": (dt + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),              "action": f"Assigned to {random.choice(ANALYSTS)}", "actor": "SOAR Engine"},
            ],
        })
    stats["incidents_open"] = len([i for i in incidents_store if i["status"] in ("open","investigating")])

def init_playbook_runs(n: int = 12):
    for _ in range(n):
        pb       = random.choice(PLAYBOOKS)
        done     = random.randint(0, pb[1])
        is_done  = done == pb[1]
        status   = "completed" if is_done else ("running" if done > 0 else "queued")
        inc      = random.choice(incidents_store) if incidents_store else None
        playbook_runs.append({
            "id":             f"PBR-{uuid.uuid4().hex[:6].upper()}",
            "playbook_name":  pb[0],
            "trigger":        random.choice(["Auto-triggered by SIEM","Manual execution","Scheduled run","API trigger"]),
            "started_at":     ts_ago(minutes=random.randint(0, 180)),
            "status":         status,
            "steps":          pb[2],
            "steps_completed":done,
            "total_steps":    pb[1],
            "actions_taken":  pb[2][:done],
            "incident_id":    inc["id"] if inc else None,
        })

def init_logs(n: int = 250):
    for _ in range(n):
        src_type = random.choice(list(SOURCE_TYPES.keys()))
        src_name = random.choice(SOURCE_TYPES[src_type])
        evt_type = random.choice(EVENT_TYPES[src_type])
        sev      = random.choices(SEVERITIES, weights=SEV_WEIGHTS)[0]
        dt       = datetime.utcnow() - timedelta(minutes=random.randint(0, 90))
        logs_store.append({
            "id":          str(uuid.uuid4())[:8],
            "timestamp":   dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z",
            "source_type": src_type,
            "source_name": src_name,
            "event_type":  evt_type,
            "severity":    sev,
            "message":     generate_log_message(src_type, evt_type, sev),
            "src_ip":      rand_ip(external=random.random() > 0.6),
            "dst_ip":      rand_ip(),
            "user":        rand_user() if random.random() > 0.4 else None,
            "enriched":    random.random() > 0.5,
            "tags":        [src_type],
        })
    stats["logs_today"]   = random.randint(280000, 520000)
    stats["logs_per_min"] = random.randint(900, 2800)

def init_data():
    init_sources()
    init_iocs()
    init_rules()
    init_alerts()
    init_incidents()
    init_playbook_runs()
    init_logs()
    stats["threats_blocked"] = random.randint(800, 3500)

# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET CONNECTION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, msg: dict):
        if not self.active:
            return
        text = json.dumps(msg)
        dead: Set[WebSocket] = set()
        for ws in self.active:
            try:
                await ws.send_text(text)
            except Exception:
                dead.add(ws)
        self.active -= dead

manager = ConnectionManager()

# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND DATA GENERATOR  (simulates live security telemetry)
# ══════════════════════════════════════════════════════════════════════════════

async def data_generator():
    counter = 0
    while True:
        try:
            await asyncio.sleep(random.uniform(0.6, 2.2))
            counter += 1

            # ── New Log Entry ──────────────────────────────────────────────
            src_type = random.choice(list(SOURCE_TYPES.keys()))
            src_name = random.choice(SOURCE_TYPES[src_type])
            evt_type = random.choice(EVENT_TYPES[src_type])
            sev      = random.choices(SEVERITIES, weights=SEV_WEIGHTS)[0]

            new_log = {
                "id":          str(uuid.uuid4())[:8],
                "timestamp":   now_iso(),
                "source_type": src_type,
                "source_name": src_name,
                "event_type":  evt_type,
                "severity":    sev,
                "message":     generate_log_message(src_type, evt_type, sev),
                "src_ip":      rand_ip(external=random.random() > 0.6),
                "dst_ip":      rand_ip(),
                "user":        rand_user() if random.random() > 0.4 else None,
                "enriched":    random.random() > 0.6,
                "tags":        [src_type],
            }
            logs_store.appendleft(new_log)
            stats["logs_today"] += 1
            await manager.broadcast({"type": "new_log", "data": new_log})

            # ── New Alert (every 4th cycle or on high-sev events) ──────────
            if counter % 4 == 0 or sev in ("high", "critical"):
                rule = random.choice(ALERT_RULES)
                new_alert = {
                    "id":             f"ALERT-{uuid.uuid4().hex[:6].upper()}",
                    "timestamp":      now_iso(),
                    "rule_name":      rule[0],
                    "severity":       rule[1],
                    "source_ip":      new_log["src_ip"],
                    "dest_ip":        new_log["dst_ip"],
                    "user":           new_log.get("user"),
                    "description":    rule[4],
                    "status":         "new",
                    "mitre_tactic":   rule[2],
                    "mitre_technique":rule[3],
                    "log_count":      random.randint(1, 30),
                    "enrichment": {
                        "geo":              random.choice(GEO_COUNTRIES),
                        "asn":              f"AS{random.randint(1000, 65000)}",
                        "reputation":       random.choice(["Malicious","Suspicious","Unknown"]),
                        "threat_intel_hits":random.randint(0, 6),
                        "isp":              random.choice(["Cloudflare","Amazon AWS","Google","DigitalOcean","Hetzner"]),
                    }
                }
                alerts_store.insert(0, new_alert)
                if len(alerts_store) > 300:
                    alerts_store.pop()
                stats["alerts_today"] += 1
                await manager.broadcast({"type": "new_alert", "data": new_alert})

                # Auto-create incident on critical alerts
                if rule[1] == "critical" and random.random() > 0.55:
                    pb  = random.choice(PLAYBOOKS)
                    inc = {
                        "id":             f"INC-{1000 + len(incidents_store) + counter}",
                        "title":          f"Auto-Escalated: {rule[0]}",
                        "severity":       "critical",
                        "status":         "open",
                        "assigned_to":    random.choice(ANALYSTS),
                        "created_at":     now_iso(),
                        "updated_at":     now_iso(),
                        "alert_ids":      [new_alert["id"]],
                        "playbook":       pb[0],
                        "playbook_steps": pb[2],
                        "steps_completed":0,
                        "total_steps":    pb[1],
                        "description":    f"Auto-created from critical detection: {rule[0]}.",
                        "analyst_notes":  "",
                        "timeline":       [{"time": now_iso(), "action": "Auto-created by SOAR", "actor": "SOAR Engine"}],
                    }
                    incidents_store.insert(0, inc)
                    stats["incidents_open"] += 1
                    await manager.broadcast({"type": "new_incident", "data": inc})

            # ── New IOC (every 7th cycle) ──────────────────────────────────
            if counter % 7 == 0:
                ioc_type = random.choice(["ip","domain","hash"])
                value    = new_log["src_ip"] if ioc_type == "ip" else (
                           random.choice(FAKE_DOMAINS) if ioc_type == "domain" else random.choice(FAKE_HASHES))
                new_ioc  = {
                    "id":          str(uuid.uuid4())[:8],
                    "type":        ioc_type,
                    "value":       value,
                    "confidence":  random.randint(65, 99),
                    "source":      random.choice(IOC_FEEDS),
                    "tags":        random.sample(THREAT_TYPES, k=random.randint(1, 2)),
                    "threat_type": random.choice(THREAT_TYPES),
                    "first_seen":  now_iso(),
                    "last_seen":   now_iso(),
                    "hits":        random.randint(1, 30),
                    "active":      True,
                }
                iocs_store.insert(0, new_ioc)
                if len(iocs_store) > 600:
                    iocs_store.pop()
                stats["iocs_total"] = len(iocs_store)
                await manager.broadcast({"type": "new_ioc", "data": new_ioc})

            # ── Stats refresh (every 12th cycle) ──────────────────────────
            if counter % 12 == 0:
                stats["logs_per_min"]   = random.randint(900, 2800)
                stats["threats_blocked"] += random.randint(0, 8)
                stats["mttd_minutes"]   = round(random.uniform(8.0, 20.0), 1)
                stats["mttr_minutes"]   = round(random.uniform(32.0, 70.0), 1)
                stats["sources_active"] = len([s for s in sources_store if s["status"] == "active"])
                await manager.broadcast({"type": "stats_update", "data": dict(stats)})

            # ── Playbook step progress (every 15th cycle) ──────────────────
            if counter % 15 == 0 and playbook_runs:
                run = random.choice([r for r in playbook_runs if r["status"] == "running"] or playbook_runs)
                if run["steps_completed"] < run["total_steps"]:
                    run["steps_completed"] += 1
                    run["actions_taken"].append(run["steps"][run["steps_completed"] - 1])
                    if run["steps_completed"] == run["total_steps"]:
                        run["status"] = "completed"
                    await manager.broadcast({"type": "playbook_update", "data": run})

        except Exception as e:
            print(f"[Generator Error] {e}")
            await asyncio.sleep(2)

# ══════════════════════════════════════════════════════════════════════════════
# API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

# ── Permission map (documented) ────────────────────────────────────────────
# tier1   : read alerts, sources, logs, incidents, feeds
# tier2   : + update alert/incident status, view IOCs, playbooks
# tier3   : + view correlation rules
# manager : + view SOC metrics
# admin   : + list users, full access
# ───────────────────────────────────────────────────────────────────────────

@app.get("/api/stats", tags=["Platform"])
def get_stats(_: dict = Depends(require_role("tier1"))):
    return stats

@app.get("/api/sources", tags=["Layer 1"])
def get_sources(status: Optional[str] = None, _: dict = Depends(require_role("tier1"))):
    if status:
        return [s for s in sources_store if s["status"] == status]
    return sources_store

@app.get("/api/logs", tags=["Layer 2"])
def get_logs(
    limit: int = Query(100, le=500),
    severity: Optional[str] = None,
    source_type: Optional[str] = None,
    _: dict = Depends(require_role("tier1")),
):
    data = list(logs_store)
    if severity:    data = [l for l in data if l["severity"]    == severity]
    if source_type: data = [l for l in data if l["source_type"] == source_type]
    return data[:limit]

@app.get("/api/alerts", tags=["Layer 3"])
def get_alerts(
    limit: int = Query(60, le=300),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    _: dict = Depends(require_role("tier1")),
):
    data = alerts_store
    if severity: data = [a for a in data if a["severity"] == severity]
    if status:   data = [a for a in data if a["status"]   == status]
    return data[:limit]

@app.get("/api/alerts/{alert_id}", tags=["Layer 3"])
def get_alert(alert_id: str, _: dict = Depends(require_role("tier1"))):
    alert = next((a for a in alerts_store if a["id"] == alert_id), None)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert

@app.put("/api/alerts/{alert_id}/status", tags=["Layer 3"])
def update_alert_status(
    alert_id: str,
    status: str,
    current_user: dict = Depends(require_role("tier2")),
):
    alert = next((a for a in alerts_store if a["id"] == alert_id), None)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert["status"] = status
    alert["updated_by"] = current_user["username"]
    return alert

@app.get("/api/threats/iocs", tags=["Layer 4"])
def get_iocs(
    limit: int = Query(60, le=300),
    ioc_type: Optional[str] = None,
    threat_type: Optional[str] = None,
    _: dict = Depends(require_role("tier2")),
):
    data = iocs_store
    if ioc_type:    data = [i for i in data if i["type"]        == ioc_type]
    if threat_type: data = [i for i in data if i["threat_type"] == threat_type]
    return data[:limit]

@app.get("/api/threats/feeds", tags=["Layer 4"])
def get_feeds(_: dict = Depends(require_role("tier1"))):
    return [{
        "name":        feed,
        "status":      random.choice(["active","active","active","degraded"]),
        "last_update": ts_ago(minutes=random.randint(1, 45)),
        "iocs_today":  random.randint(80, 800),
        "total_iocs":  random.randint(8000, 150000),
        "confidence":  random.randint(75, 99),
    } for feed in IOC_FEEDS]

@app.get("/api/incidents", tags=["Layer 5"])
def get_incidents(status: Optional[str] = None, _: dict = Depends(require_role("tier1"))):
    if status:
        return [i for i in incidents_store if i["status"] == status]
    return incidents_store

@app.get("/api/incidents/{inc_id}", tags=["Layer 5"])
def get_incident(inc_id: str, _: dict = Depends(require_role("tier1"))):
    inc = next((i for i in incidents_store if i["id"] == inc_id), None)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc

@app.put("/api/incidents/{inc_id}/status", tags=["Layer 5"])
def update_incident_status(
    inc_id: str,
    status: str,
    current_user: dict = Depends(require_role("tier2")),
):
    inc = next((i for i in incidents_store if i["id"] == inc_id), None)
    if not inc:
        raise HTTPException(404, "Incident not found")
    inc["status"]     = status
    inc["updated_at"] = now_iso()
    inc["timeline"].append({
        "time":   now_iso(),
        "action": f"Status → {status}",
        "actor":  current_user["username"],
    })
    stats["incidents_open"] = len([i for i in incidents_store if i["status"] in ("open","investigating")])
    return inc

@app.get("/api/playbooks", tags=["Layer 5"])
def get_playbooks(_: dict = Depends(require_role("tier2"))):
    return [{
        "id":              f"PB-{i+1:03d}",
        "name":            pb[0],
        "steps":           pb[2],
        "total_steps":     pb[1],
        "enabled":         True,
        "last_executed":   ts_ago(hours=random.randint(1, 72)),
        "executions_total":random.randint(5, 300),
        "success_rate":    random.randint(85, 100),
        "avg_duration_min":random.randint(5, 45),
        "category":        random.choice(["Endpoint","Network","Cloud","Email","Identity"]),
    } for i, pb in enumerate(PLAYBOOKS)]

@app.get("/api/playbook-runs", tags=["Layer 5"])
def get_playbook_runs(_: dict = Depends(require_role("tier2"))):
    return playbook_runs

@app.get("/api/rules", tags=["Layer 3"])
def get_rules(_: dict = Depends(require_role("tier3"))):
    return rules_store

@app.get("/api/metrics", tags=["Layer 7"])
def get_metrics(current_user: dict = Depends(require_role("manager"))):
    return {
        "mttd_minutes":     stats["mttd_minutes"],
        "mttr_minutes":     stats["mttr_minutes"],
        "logs_today":       stats["logs_today"],
        "alerts_today":     stats["alerts_today"],
        "incidents_open":   stats["incidents_open"],
        "threats_blocked":  stats["threats_blocked"],
        "false_positive_rate":   round(random.uniform(3, 12), 1),
        "analyst_utilization":   random.randint(60, 96),
        "coverage_score":        random.randint(78, 99),
        "sources_active":        stats["sources_active"],
        "alert_severity_breakdown": {
            "critical": len([a for a in alerts_store if a["severity"] == "critical"]),
            "high":     len([a for a in alerts_store if a["severity"] == "high"]),
            "medium":   len([a for a in alerts_store if a["severity"] == "medium"]),
            "low":      len([a for a in alerts_store if a["severity"] == "low"]),
        },
        "incident_status_breakdown": {
            "open":          len([i for i in incidents_store if i["status"] == "open"]),
            "investigating": len([i for i in incidents_store if i["status"] == "investigating"]),
            "contained":     len([i for i in incidents_store if i["status"] == "contained"]),
            "resolved":      len([i for i in incidents_store if i["status"] == "resolved"]),
        },
        "ingestion_history": [random.randint(600, 3200) for _ in range(30)],
        "analysts": [{
            "name":               a,
            "alerts_handled":     random.randint(5, 60),
            "incidents_resolved": random.randint(0, 15),
            "avg_response_min":   random.randint(12, 95),
            "tier":               random.choice(["T1","T2","T3"]),
        } for a in ANALYSTS],
    }

# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    # Validate JWT before accepting the connection
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username or username not in DEMO_USERS:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except JWTError:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    await manager.connect(websocket)
    try:
        await websocket.send_text(json.dumps({
            "type": "initial_state",
            "data": {
                "stats":         stats,
                "recent_alerts": alerts_store[:15],
                "recent_logs":   list(logs_store)[:30],
                "recent_iocs":   iocs_store[:10],
            }
        }))
        while True:
            await asyncio.sleep(25)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except (WebSocketDisconnect, Exception):
        manager.disconnect(websocket)

# ══════════════════════════════════════════════════════════════════════════════
# STATIC FILES & STARTUP
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return FileResponse("frontend/index.html")

@app.on_event("startup")
async def startup():
    print("⚡ ThreatIQ Platform starting up...")
    init_users()
    print(f"   ✓ {len(DEMO_USERS)} user accounts initialized (auth enabled)")
    init_data()
    print(f"   ✓ {len(sources_store)} data sources loaded")
    print(f"   ✓ {len(alerts_store)} alerts initialized")
    print(f"   ✓ {len(incidents_store)} incidents loaded")
    print(f"   ✓ {len(iocs_store)} IOCs in threat intel db")
    asyncio.create_task(data_generator())
    print("   ✓ Real-time data generator running")
    print("   ✓ Platform ready → http://localhost:8000")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, reload=False)
