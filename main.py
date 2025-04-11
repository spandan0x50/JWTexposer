from flask import Flask, render_template_string, request
import requests
import re
import time
import jwt
import json
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "admin": "admin"
}

@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username
    return None

# @app.route("/", methods=["GET", "POST"])
# @auth.login_required
# def index():
#     ...

WAYBACK_URL = "https://web.archive.org/cdx/search/cdx?url=*.{target}&output=text&fl=original&collapse=urlkey"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; JWT-Finder/1.0; +https://github.com/yourusername/jwt_finder)"}
JWT_REGEX = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
JUICY_FIELDS = ["email", "username", "password", "api_key", "access_token", "session_id", "role", "scope"]

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>JWTexposer</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #1a1a1a;
      color: #f8f9fa;
    }
    .highlight {
      background-color: #222;
      color: #0dcaf0;
      padding: 0.2em 0.4em;
      border-radius: 5px;
      font-family: monospace;
      word-break: break-word;
    }
    pre {
      background-color: #2c2c2c;
      padding: 1em;
      border-radius: 0.5em;
      overflow-x: auto;
    }
    .card {
      border: none;
      border-radius: 0.75em;
      box-shadow: 0 0 15px rgba(0, 0, 0, 0.5);
    }
    .summary-box {
      background-color: #2c2c2c;
      border-left: 5px solid #0dcaf0;
      padding: 1em;
      border-radius: 0.5em;
      margin-bottom: 2em;
    }
  </style>
</head>
<body>
<div class="container mt-5">
  <p class="lead">Automated JWT Extraction & Analysis Tool</p>

  <form method="POST" class="mb-5">
    <div class="row g-2">
      <div class="col-md-9">
        <input type="text" name="domain" class="form-control form-control-lg" placeholder="Enter domain (e.g. example.com to scan *.example.com)" required>
      </div>
      <div class="col-md-3 d-grid">
        <button type="submit" class="btn btn-primary btn-lg">Analyze</button>
      </div>
    </div>
  </form>

  {% if results or checked %}
    <div class="summary-box">
      <p>
        <strong>Scanned:</strong> {{ summary.urls_scanned }} URLs<br>
        <strong>JWTs Found:</strong> {{ summary.jwt_found }}<br>
        <strong>Decoded:</strong> {{ summary.decoded }}
      </p>
    </div>
  {% endif %}

  {% for url, data in results.items() %}
    <div class="card text-bg-dark mb-4">
      <div class="card-header">
        <strong>Source URL:</strong> <code>{{ url }}</code>
      </div>
      <div class="card-body">
        <p><strong>JWT:</strong> <span class="highlight">{{ data.jwt }}</span></p>
        <p><strong>Juicy Info:</strong></p>
        <pre>{{ data.juicy | tojson(indent=2) }}</pre>
        <p><strong>Decoded Payload:</strong></p>
        <pre>{{ data.decoded | tojson(indent=2) }}</pre>
      </div>
    </div>
  {% endfor %}

  {% if checked and not results %}
    <div class="alert alert-warning">No JWTs found in any scanned URL.</div>
  {% endif %}
</div>
</body>
</html>
"""

def fetch_wayback_urls(target, retries=3):
    url = WAYBACK_URL.format(target=target)
    for _ in range(retries):
        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code == 200:
                return response.text.splitlines()
        except requests.exceptions.RequestException:
            time.sleep(5)
    return []

def extract_jwt_from_url(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    for values in query_params.values():
        for value in values:
            decoded_value = unquote(value)
            if re.match(JWT_REGEX, decoded_value):
                return decoded_value, url
    decoded_url = unquote(url)
    match = JWT_REGEX.search(decoded_url)
    if match:
        return match.group(0), url
    return None, None

def check_url_status(url):
    try:
        response = requests.head(url, headers=HEADERS, allow_redirects=True)
        if response.status_code in [200, 301, 302]:
            return url
    except requests.exceptions.RequestException:
        pass
    return None

def decode_jwt_simple(token):
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError:
        return None

def analyze_jwt(decoded_data):
    return {key: value for key, value in decoded_data.items() if key in JUICY_FIELDS}

@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
    summary = {"urls_scanned": 0, "jwt_found": 0, "decoded": 0}
    checked = False
    if request.method == "POST":
        domain = request.form["domain"]
        urls = fetch_wayback_urls(domain)
        summary["urls_scanned"] = len(urls)
        jwt_tokens = {}
        for url in urls:
            token, src = extract_jwt_from_url(url)
            if token:
                jwt_tokens[src] = token
        summary["jwt_found"] = len(jwt_tokens)
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_url_status, jwt_tokens.keys())
        for url, token in jwt_tokens.items():
            decoded = decode_jwt_simple(token)
            if decoded:
                juicy = analyze_jwt(decoded)
                results[url] = {"jwt": token, "decoded": decoded, "juicy": juicy}
        summary["decoded"] = len(results)
        checked = True
    return render_template_string(HTML_TEMPLATE, results=results, checked=checked, summary=summary)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
