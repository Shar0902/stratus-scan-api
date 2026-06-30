"""
Stratus Cloud Security — Lead Scan API
---------------------------------------
A small FastAPI backend that performs real security checks for the
"Free Cybersecurity Check" lead-qualification flow, replacing the
mocked checks in the frontend artifact (stratus-lead-check.jsx).

Run locally:
    pip install fastapi uvicorn dnspython requests python-dotenv
    uvicorn scan_api:app --reload --port 8000

Environment variables (.env):
    HIBP_API_KEY=your_haveibeenpwned_api_key   # optional, business breach check

Endpoints:
    POST /api/scan/domain   -> SPF / DMARC / DKIM presence check for a business domain
    POST /api/scan/email    -> breach exposure check for a single email (home leads)
    POST /api/scan/filtering -> tests whether the caller's current DNS resolver
                                 blocks a known-safe malware test domain

Security notes:
    - This service should sit behind your own auth / rate limiting before
      going to production — it's written for clarity, not hardened yet.
    - Never put HIBP_API_KEY or any other secret in frontend code. This
      backend is exactly where keys like that should live.
    - CORS is wide open below for local development. Lock allow_origins
      down to your real frontend domain before deploying.
"""

import os
import re
import socket
from typing import Optional

import dns.resolver
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# ---- Config ----------------------------------------------------------

HIBP_API_KEY = os.environ.get("HIBP_API_KEY")  # https://haveibeenpwned.com/API/Key
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"

# A domain that's safe to resolve as a malware-test indicator.
# Cloudflare and other DNS security vendors publish test domains like this;
# replace with whichever test domain your upstream filtering provider (e.g.
# Control D / Cloudflare Gateway) recommends for verification.
MALWARE_TEST_DOMAIN = "testsafebrowsing.appspot.com"  # placeholder — verify against your vendor's docs

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")

app = FastAPI(title="Stratus Cloud Security — Scan API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: lock to your real frontend origin before going live
    allow_methods=["POST"],
    allow_headers=["*"],
)


# ---- Models ------------------------------------------------------------

class DomainScanRequest(BaseModel):
    domain: str


class EmailScanRequest(BaseModel):
    email: EmailStr


class FilteringScanRequest(BaseModel):
    resolver_ip: Optional[str] = None  # if omitted, uses the server's default resolver


# ---- Helpers ------------------------------------------------------------

def _validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1]
    domain = domain.split("/")[0]
    if not DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return domain


def _check_spf(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=spf1"):
                return {"present": True, "record": txt}
        return {"present": False, "record": None}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return {"present": False, "record": None}


def _check_dmarc(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.startswith("v=DMARC1"):
                policy_match = re.search(r"p=(\w+)", txt)
                return {"present": True, "record": txt, "policy": policy_match.group(1) if policy_match else None}
        return {"present": False, "record": None, "policy": None}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return {"present": False, "record": None, "policy": None}


def _check_dkim(domain: str) -> dict:
    # DKIM selectors vary by provider. We probe the most common ones
    # (Google Workspace, Microsoft 365) — a production version should let
    # the customer confirm their email provider to pick the right selector.
    common_selectors = ["google", "selector1", "selector2", "default", "k1"]
    for selector in common_selectors:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=3)
            return {"present": True, "selector_found": selector}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            continue
    return {"present": False, "selector_found": None}


# ---- Endpoints ------------------------------------------------------------

@app.post("/api/scan/domain")
def scan_domain(req: DomainScanRequest):
    """
    Checks a business domain's email authentication posture:
    SPF, DMARC, and (best-effort) DKIM presence.
    """
    domain = _validate_domain(req.domain)

    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain)

    gaps = []
    if not spf["present"]:
        gaps.append("No SPF record — your domain can be spoofed in phishing emails.")
    if not dmarc["present"]:
        gaps.append("No DMARC policy — spoofed emails aren't being rejected or flagged.")
    elif dmarc.get("policy") == "none":
        gaps.append("DMARC policy is set to 'none' — spoofed mail is monitored but not blocked.")
    if not dkim["present"]:
        gaps.append("No DKIM signature found on common selectors — email authenticity can't be verified.")

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "gaps": gaps,
        "status": "fail" if len(gaps) >= 2 else "warn" if gaps else "pass",
    }


@app.post("/api/scan/email")
def scan_email(req: EmailScanRequest):
    """
    Checks whether an email address appears in known data breaches,
    via the HaveIBeenPwned API. Requires HIBP_API_KEY to be set.
    """
    if not HIBP_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Breach check unavailable — set HIBP_API_KEY to enable this endpoint.",
        )

    headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "StratusCloudSecurity-ScanAPI"}
    url = f"{HIBP_BASE_URL}/breachedaccount/{req.email}"

    try:
        resp = requests.get(url, headers=headers, timeout=8)
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Breach check service unreachable")

    if resp.status_code == 404:
        return {"email": req.email, "breached": False, "breach_count": 0, "breaches": []}
    if resp.status_code == 200:
        breaches = resp.json()
        return {
            "email": req.email,
            "breached": True,
            "breach_count": len(breaches),
            "breaches": [b.get("Name") for b in breaches],
        }
    if resp.status_code == 429:
        raise HTTPException(status_code=429, detail="Rate limited by breach check provider — try again shortly.")

    raise HTTPException(status_code=502, detail=f"Unexpected response from breach check provider ({resp.status_code})")


@app.post("/api/scan/filtering")
def scan_filtering(req: FilteringScanRequest):
    """
    Best-effort check for DNS-level threat filtering: attempts to resolve
    a known test domain. If your filtering vendor (Control D / Cloudflare
    Gateway) publishes a dedicated test-block domain, swap MALWARE_TEST_DOMAIN
    for that — it will give a much more reliable pass/fail signal than a
    generic safe-browsing test domain.
    """
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(MALWARE_TEST_DOMAIN)
        resolved = True
    except socket.error:
        resolved = False

    # NOTE: resolving successfully does NOT necessarily mean "no filtering" —
    # it depends entirely on what MALWARE_TEST_DOMAIN represents. Once you
    # swap in your real vendor's test-block domain, invert this logic so
    # that "fails to resolve" = filtering is active and working.
    return {
        "test_domain": MALWARE_TEST_DOMAIN,
        "resolved": resolved,
        "note": "Replace MALWARE_TEST_DOMAIN with your filtering vendor's official test-block domain before relying on this in production.",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
