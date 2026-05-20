import re
import json
import os
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional
from ai_model import predict_secret_with_confidence

with open("patterns.json") as f:
    PATTERNS = json.load(f)

SEVERITY_MAP = {
    "AWS Access Key": "critical",
    "AWS Secret Key": "critical",
    "GitHub Token": "critical",
    "GitHub OAuth Token": "critical",
    "Slack Token": "high",
    "Stripe Secret Key": "critical",
    "Stripe Publishable Key": "medium",
    "Google API Key": "high",
    "Twilio API Key": "high",
    "SendGrid API Key": "high",
    "Private Key Block": "critical",
    "SSH Private Key": "critical",
    "JWT Token": "high",
    "Password in Config": "high",
    "Database URL": "critical",
    "Bearer Token": "high",
    "Generic Secret": "medium",
    "Email Address": "low",
    "IPv4 Address": "low",
    "Heroku API Key": "critical",
    "AI Secret": "medium",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

CATEGORY_MAP = {
    "AWS Access Key": "Cloud Credentials",
    "AWS Secret Key": "Cloud Credentials",
    "GitHub Token": "VCS Token",
    "GitHub OAuth Token": "VCS Token",
    "Slack Token": "Communication Token",
    "Stripe Secret Key": "Payment Credentials",
    "Stripe Publishable Key": "Payment Credentials",
    "Google API Key": "API Key",
    "Twilio API Key": "API Key",
    "SendGrid API Key": "API Key",
    "Private Key Block": "Cryptographic Key",
    "SSH Private Key": "Cryptographic Key",
    "JWT Token": "Auth Token",
    "Password in Config": "Password",
    "Database URL": "Database Credentials",
    "Bearer Token": "Auth Token",
    "Generic Secret": "Generic Secret",
    "Email Address": "PII",
    "IPv4 Address": "Network Info",
    "Heroku API Key": "Cloud Credentials",
    "AI Secret": "AI Detected",
}

@dataclass
class Finding:
    filepath: str
    filename: str
    line_number: int
    secret_type: str
    category: str
    severity: str
    raw_content: str
    redacted_content: str
    confidence: Optional[float] = None
    fingerprint: str = field(default="")

    def __post_init__(self):
        self.fingerprint = hashlib.md5(
            f"{self.filepath}:{self.line_number}:{self.secret_type}:{self.raw_content}".encode()
        ).hexdigest()[:12]

    def to_dict(self):
        return {
            "filepath": self.filepath,
            "filename": self.filename,
            "line_number": self.line_number,
            "secret_type": self.secret_type,
            "category": self.category,
            "severity": self.severity,
            "redacted_content": self.redacted_content,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
        }

def redact(content: str) -> str:
    content = content.strip()
    if len(content) <= 8:
        return "****"
    visible = max(4, len(content) // 5)
    return content[:visible] + "****" + content[-2:]

def scan_file(filepath: str) -> List[Finding]:
    findings: List[Finding] = []
    seen_fingerprints = set()
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    filesize = os.path.getsize(filepath)

    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
    except (IOError, OSError) as e:
        return findings

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for pattern_name, pattern in PATTERNS.items():
            try:
                match = re.search(pattern, line)
                if match:
                    matched_text = match.group(0)
                    severity = SEVERITY_MAP.get(pattern_name, "low")
                    category = CATEGORY_MAP.get(pattern_name, "Unknown")
                    finding = Finding(
                        filepath=filepath,
                        filename=filename,
                        line_number=line_num,
                        secret_type=pattern_name,
                        category=category,
                        severity=severity,
                        raw_content=matched_text,
                        redacted_content=redact(stripped),
                    )
                    if finding.fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(finding.fingerprint)
                        findings.append(finding)
            except re.error:
                continue

        words = re.findall(r'[A-Za-z0-9+/=_\-]{8,}', line)
        for word in words:
            is_secret, confidence = predict_secret_with_confidence(word)
            if is_secret:
                finding = Finding(
                    filepath=filepath,
                    filename=filename,
                    line_number=line_num,
                    secret_type="AI Secret",
                    category="AI Detected",
                    severity="medium",
                    raw_content=word,
                    redacted_content=redact(word),
                    confidence=confidence,
                )
                if finding.fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(finding.fingerprint)
                    findings.append(finding)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.line_number))
    return findings

def get_scan_summary(findings: List[Finding]) -> dict:
    summary = {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
        "categories": {},
        "types": {},
    }
    for f in findings:
        summary["categories"][f.category] = summary["categories"].get(f.category, 0) + 1
        summary["types"][f.secret_type] = summary["types"].get(f.secret_type, 0) + 1
    return summary