from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import socket
import requests
import dns.resolver
import whois
import ssl
import json
import re
import struct
import ipaddress
from datetime import datetime, timedelta
import hashlib
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# Load credentials from config.py
try:
    import config as _cfg
    app.secret_key = _cfg.SECRET_KEY
    _USERS = _cfg.USERS
except ImportError:
    app.secret_key = "cyberreconx_secret_2025"
    _USERS = {"admin": "cyberrecon2025"}

# ── File-based registered users (new signups) ─────────────────────
_DB_FILE = os.path.join(os.path.dirname(__file__), "users_db.json")

def _load_db():
    if os.path.exists(_DB_FILE):
        with open(_DB_FILE) as f:
            return json.load(f)
    return {}

def _save_db(db):
    with open(_DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def _hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def _check_credentials(username, password):
    # Check config.py users first (plain text match)
    if _USERS.get(username) == password:
        return True
    # Check registered users (hashed)
    db = _load_db()
    if username in db:
        return db[username]["password"] == _hash(password)
    return False

def _username_exists(username):
    if username in _USERS:
        return True
    return username in _load_db()

# ─── Constants ────────────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cache-Control",
]

DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MongoDB",
}

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "WordPress"],
    "Drupal": ["Drupal", "drupal.js"],
    "Joomla": ["Joomla", "/components/com_"],
    "React": ["react.js", "react.min.js", "__react"],
    "Angular": ["angular.js", "ng-version"],
    "Vue.js": ["vue.js", "vue.min.js"],
    "jQuery": ["jquery.js", "jquery.min.js"],
    "Bootstrap": ["bootstrap.css", "bootstrap.min.css"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Next.js": ["__NEXT_DATA__", "_next/"],
    "Nginx": ["nginx"],
    "Apache": ["Apache"],
    "IIS": ["IIS", "X-Powered-By: ASP.NET"],
    "Cloudflare": ["cloudflare", "cf-ray"],
    "AWS": ["amazon", "aws", "x-amz"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "Node.js": ["X-Powered-By: Express"],
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def clean_domain(target):
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.netloc
    return target.split("/")[0]


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Not Found"


# ─── Full Scan ────────────────────────────────────────────────────────────────

def get_dns_records(domain):
    records = {}
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for record_type in types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(a) for a in answers]
        except:
            records[record_type] = ["Not Found"]
    return records


def get_whois_info(domain):
    try:
        data = whois.whois(domain)
        return {
            "domain_name": str(data.domain_name),
            "registrar": str(data.registrar),
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "updated_date": str(data.updated_date) if hasattr(data, "updated_date") else "N/A",
            "name_servers": str(data.name_servers),
            "status": str(data.status) if hasattr(data, "status") else "N/A",
            "emails": str(data.emails) if hasattr(data, "emails") else "N/A",
            "org": str(data.org) if hasattr(data, "org") else "N/A",
        }
    except Exception as e:
        return {k: "Not Found" for k in ["domain_name","registrar","creation_date","expiration_date","updated_date","name_servers","status","emails","org"]}


def check_security_headers(domain):
    result = {"url": "", "status_code": "Not Reachable", "server": "Not Found", "headers": {}}
    for url in [f"https://{domain}", f"http://{domain}"]:
        try:
            resp = requests.get(url, timeout=6, allow_redirects=True)
            result["url"] = url
            result["status_code"] = resp.status_code
            result["server"] = resp.headers.get("Server", "Not Disclosed")
            for h in SECURITY_HEADERS:
                result["headers"][h] = "Present" if h in resp.headers else "Missing"
            return result
        except:
            continue
    return result


def check_public_files(domain):
    files = {}
    paths = ["robots.txt", "sitemap.xml", ".well-known/security.txt", "crossdomain.xml", "humans.txt"]
    for f in paths:
        url = f"https://{domain}/{f}"
        try:
            resp = requests.get(url, timeout=5)
            files[f] = "Found ✓" if resp.status_code == 200 else "Not Found"
        except:
            files[f] = "Not Found"
    return files


def check_ports_default(ip):
    results = []
    if ip == "Not Found":
        return results
    for port, service in DEFAULT_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            status = s.connect_ex((ip, port))
            s.close()
            results.append({"port": port, "service": service, "status": "Open" if status == 0 else "Closed"})
        except:
            results.append({"port": port, "service": service, "status": "Error"})
    return results


def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = []
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                sans.append(val)
        return {
            "valid": True,
            "subject": subject.get("commonName", "N/A"),
            "issuer": issuer.get("organizationName", "N/A"),
            "issued_to": subject.get("commonName", "N/A"),
            "not_before": cert.get("notBefore", "N/A"),
            "not_after": cert.get("notAfter", "N/A"),
            "version": cert.get("version", "N/A"),
            "serial": str(cert.get("serialNumber", "N/A")),
            "san": sans[:10],
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def detect_technologies(domain):
    detected = []
    try:
        url = f"https://{domain}"
        resp = requests.get(url, timeout=6)
        content = resp.text.lower()
        headers_str = str(resp.headers).lower()
        combined = content + headers_str
        for tech, sigs in TECH_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    detected.append(tech)
                    break
    except:
        pass
    return list(set(detected))


def get_ip_geolocation(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            return data
        return {}
    except:
        return {}


def get_reverse_ip(ip):
    try:
        resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=8)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            domains = [d.strip() for d in resp.text.strip().split("\n") if d.strip()]
            return domains[:30]
        return []
    except:
        return []


def get_subdomains(domain):
    subdomains = set()
    wordlist = ["www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
                "smtp", "pop", "imap", "api", "dev", "staging", "test", "admin", "portal",
                "vpn", "cdn", "shop", "forum", "help", "support", "m", "mobile", "secure",
                "login", "app", "dashboard", "beta", "old", "new", "static", "media", "img"]
    
    # DNS brute-force
    def check_sub(sub):
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            return full
        except:
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_sub, s): s for s in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)

    # crt.sh certificate transparency
    try:
        resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n != domain:
                        subdomains.add(n)
    except:
        pass

    return sorted(list(subdomains))[:50]


def get_ip_history(domain):
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=8)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            entries = []
            for line in resp.text.strip().split("\n"):
                if "," in line:
                    parts = line.split(",")
                    entries.append({"domain": parts[0], "ip": parts[1] if len(parts) > 1 else "N/A"})
            return entries[:20]
        return []
    except:
        return []


def calculate_risk(headers, ports):
    score = 0
    for v in headers.get("headers", {}).values():
        if v == "Missing":
            score += 10
    for p in ports:
        if p["status"] == "Open":
            score += 5
    score = min(score, 100)
    level = "Low" if score <= 30 else ("Medium" if score <= 60 else "High")
    return score, level


def run_full_scan(domain):
    ip = get_ip(domain)
    dns_records = get_dns_records(domain)
    whois_info = get_whois_info(domain)
    security_headers = check_security_headers(domain)
    public_files = check_public_files(domain)
    ports = check_ports_default(ip)
    ssl_info = get_ssl_info(domain)
    technologies = detect_technologies(domain)
    geo = get_ip_geolocation(ip) if ip != "Not Found" else {}
    risk_score, risk_level = calculate_risk(security_headers, ports)

    return {
        "domain": domain,
        "ip": ip,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dns": dns_records,
        "whois": whois_info,
        "security": security_headers,
        "files": public_files,
        "ports": ports,
        "ssl": ssl_info,
        "technologies": technologies,
        "geo": geo,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if _check_credentials(u, p):
            session.permanent = True
            session["user"] = u
            session.setdefault("history", [])
            session.setdefault("saved_domains", [])
            return redirect(url_for("index"))
        error = "Incorrect username or password. Please try again."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for("index"))
    error = None
    success = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        p2 = request.form.get("confirm_password", "")
        if not u or not p:
            error = "Username and password are required."
        elif len(u) < 3:
            error = "Username must be at least 3 characters."
        elif len(p) < 6:
            error = "Password must be at least 6 characters."
        elif p != p2:
            error = "Passwords do not match."
        elif _username_exists(u):
            error = "Username already taken. Please choose another."
        else:
            db = _load_db()
            db[u] = {"password": _hash(p), "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            _save_db(db)
            success = "Account created! You can now sign in."
    return render_template("register.html", error=error, success=success)




def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# Explicit root guard — always send unauthenticated users to login
@app.before_request
def require_login():
    open_routes = {"login", "register", "static"}
    if request.endpoint not in open_routes and "user" not in session:
        return redirect(url_for("login"))


# ─── Main Routes ──────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    result = None
    error = None
    if request.method == "POST":
        perm = request.form.get("permission")
        target = request.form.get("domain", "").strip()
        if perm != "yes":
            error = "You must confirm permission to scan this target."
        elif not target:
            error = "Please enter a domain or IP."
        else:
            domain = clean_domain(target)
            result = run_full_scan(domain)
            history = session.get("history", [])
            history.insert(0, {"target": domain, "time": result["time"], "risk": result["risk_level"]})
            session["history"] = history[:20]
    return render_template("index.html", result=result, error=error, user=session.get("user"),
                           saved=session.get("saved_domains", []))


# ─── Tool Routes ──────────────────────────────────────────────────────────────

@app.route("/subdomain", methods=["GET", "POST"])
@login_required
def subdomain():
    result = None; error = None
    if request.method == "POST":
        target = clean_domain(request.form.get("domain", ""))
        if not target:
            error = "Enter a domain."
        else:
            subs = get_subdomains(target)
            result = {"domain": target, "subdomains": subs, "count": len(subs)}
    return render_template("tool.html", tool="subdomain", result=result, error=error, user=session.get("user"))


@app.route("/reverse-ip", methods=["GET", "POST"])
@login_required
def reverse_ip():
    result = None; error = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            error = "Enter an IP or domain."
        else:
            ip = target if is_ip(target) else get_ip(clean_domain(target))
            domains = get_reverse_ip(ip)
            result = {"ip": ip, "domains": domains, "count": len(domains)}
    return render_template("tool.html", tool="reverse_ip", result=result, error=error, user=session.get("user"))


@app.route("/reverse-whois", methods=["GET", "POST"])
@login_required
def reverse_whois():
    result = None; error = None
    if request.method == "POST":
        target = clean_domain(request.form.get("domain", ""))
        if not target:
            error = "Enter a domain."
        else:
            info = get_whois_info(target)
            result = {"domain": target, "whois": info}
    return render_template("tool.html", tool="reverse_whois", result=result, error=error, user=session.get("user"))


@app.route("/dns-report", methods=["GET", "POST"])
@login_required
def dns_report():
    result = None; error = None
    if request.method == "POST":
        target = clean_domain(request.form.get("domain", ""))
        if not target:
            error = "Enter a domain."
        else:
            records = get_dns_records(target)
            result = {"domain": target, "records": records}
    return render_template("tool.html", tool="dns_report", result=result, error=error, user=session.get("user"))


@app.route("/http-headers", methods=["GET", "POST"])
@login_required
def http_headers():
    result = None; error = None
    if request.method == "POST":
        target = clean_domain(request.form.get("domain", ""))
        if not target:
            error = "Enter a domain."
        else:
            sec = check_security_headers(target)
            result = {"domain": target, "security": sec}
    return render_template("tool.html", tool="http_headers", result=result, error=error, user=session.get("user"))


@app.route("/ip-history", methods=["GET", "POST"])
@login_required
def ip_history():
    result = None; error = None
    if request.method == "POST":
        target = clean_domain(request.form.get("domain", ""))
        if not target:
            error = "Enter a domain."
        else:
            entries = get_ip_history(target)
            result = {"domain": target, "entries": entries}
    return render_template("tool.html", tool="ip_history", result=result, error=error, user=session.get("user"))


@app.route("/ip-geo", methods=["GET", "POST"])
@login_required
def ip_geo():
    result = None; error = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            error = "Enter an IP or domain."
        else:
            ip = target if is_ip(target) else get_ip(clean_domain(target))
            geo = get_ip_geolocation(ip)
            result = {"ip": ip, "geo": geo}
    return render_template("tool.html", tool="ip_geo", result=result, error=error, user=session.get("user"))


# ── Standalone port scan helper (defined outside route for threading) ──
def _scan_single_port(args):
    ip, port = args
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        r = s.connect_ex((ip, port))
        s.close()
        try:
            svc = socket.getservbyport(port)
        except:
            svc = "Unknown"
        return {"port": port, "service": svc, "status": "Open" if r == 0 else "Closed"}
    except:
        return {"port": port, "service": "Unknown", "status": "Closed"}


@app.route("/port-scanner", methods=["GET", "POST"])
@login_required
def port_scanner():
    result = None; error = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        mode = request.form.get("mode", "default")
        perm = request.form.get("permission")

        if perm != "yes":
            error = "You must confirm permission to scan this domain."
        elif not target:
            error = "Enter a domain or IP address."
        else:
            domain = clean_domain(target)
            ip = target if is_ip(target) else get_ip(domain)
            if ip == "Not Found":
                error = f"Could not resolve: {domain}"
            else:
                if mode == "default":
                    ports = check_ports_default(ip)
                    open_ports = [p for p in ports if p["status"] == "Open"]
                    result = {
                        "target": domain, "ip": ip,
                        "ports": ports, "open_ports": open_ports,
                        "mode": "default", "start": None, "end": None
                    }
                else:
                    try:
                        start_port = max(1, int(request.form.get("start_port", 1)))
                        end_port   = min(65535, int(request.form.get("end_port", 1024)))
                    except ValueError:
                        start_port, end_port = 1, 1024

                    if start_port > end_port:
                        start_port, end_port = end_port, start_port

                    total = end_port - start_port + 1
                    # Use more workers for large ranges, cap at 300
                    workers = min(300, max(100, total // 20))

                    port_args = [(ip, p) for p in range(start_port, end_port + 1)]
                    ports = []
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        for res in executor.map(_scan_single_port, port_args):
                            ports.append(res)

                    ports.sort(key=lambda x: x["port"])
                    open_ports = [p for p in ports if p["status"] == "Open"]
                    result = {
                        "target": domain, "ip": ip,
                        "ports": ports, "open_ports": open_ports,
                        "mode": "custom", "start": start_port, "end": end_port
                    }

    return render_template("tool.html", tool="port_scanner", result=result, error=error, user=session.get("user"))


@app.route("/ssl-scanner", methods=["GET", "POST"])
@login_required
def ssl_scanner():
    result = None; error = None
    if request.method == "POST":
        target = clean_domain(request.form.get("domain", ""))
        if not target:
            error = "Enter a domain."
        else:
            ssl_info = get_ssl_info(target)
            result = {"domain": target, "ssl": ssl_info}
    return render_template("tool.html", tool="ssl_scanner", result=result, error=error, user=session.get("user"))


@app.route("/tech-detect", methods=["GET", "POST"])
@login_required
def tech_detect():
    result = None; error = None
    if request.method == "POST":
        target = clean_domain(request.form.get("domain", ""))
        if not target:
            error = "Enter a domain."
        else:
            techs = detect_technologies(target)
            result = {"domain": target, "technologies": techs}
    return render_template("tool.html", tool="tech_detect", result=result, error=error, user=session.get("user"))


@app.route("/history")
@login_required
def history():
    return render_template("history.html", history=session.get("history", []), user=session.get("user"))


@app.route("/history/clear")
@login_required
def clear_history():
    session["history"] = []
    return redirect(url_for("history"))


# ─── Saved Domains ────────────────────────────────────────────────────────────

@app.route("/saved-domains")
@login_required
def saved_domains():
    return render_template("saved_domains.html",
                           saved=session.get("saved_domains", []),
                           user=session.get("user"))


@app.route("/saved-domains/add", methods=["POST"])
@login_required
def save_domain():
    domain = request.form.get("domain", "").strip()
    label  = request.form.get("label", "").strip() or domain
    if domain:
        saved = session.get("saved_domains", [])
        # avoid duplicates
        if not any(d["domain"] == domain for d in saved):
            saved.insert(0, {
                "domain": domain,
                "label":  label,
                "added":  datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            session["saved_domains"] = saved[:50]
    # redirect back to wherever the form was submitted from
    next_url = request.form.get("next", "/")
    return redirect(next_url)


@app.route("/saved-domains/remove/<path:domain>")
@login_required
def remove_saved_domain(domain):
    saved = session.get("saved_domains", [])
    session["saved_domains"] = [d for d in saved if d["domain"] != domain]
    return redirect(url_for("saved_domains"))


@app.route("/saved-domains/clear")
@login_required
def clear_saved_domains():
    session["saved_domains"] = []
    return redirect(url_for("saved_domains"))


if __name__ == "__main__":
    app.run(debug=True)
