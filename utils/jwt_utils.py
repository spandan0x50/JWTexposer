import jwt
import json
import base64
import datetime
import re
from urllib.parse import urlparse, parse_qs, unquote
import requests

JWT_REGEX = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
JUICY_FIELDS = ["email", "username", "password", "api_key", "access_token", "session_id", "role", "scope"]
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; JWT-Finder/1.0; +https://github.com/yourusername/jwt_finder)"}

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}
        
        header = json.loads(base64.b64decode(parts[0] + '==').decode('utf-8'))
        payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8'))
        
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2]
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_jwt(token):
    try:
        decoded = decode_jwt(token)
        if "error" in decoded:
            return decoded
        
        analysis = {
            "decoded": decoded,
            "security_issues": [],
            "expiration": "N/A",
            "juicy_info": {}
        }
        
        if "exp" in decoded["payload"]:
            exp_timestamp = decoded["payload"]["exp"]
            exp_date = datetime.datetime.fromtimestamp(exp_timestamp)
            now = datetime.datetime.now()
            
            if exp_date < now:
                analysis["expiration"] = f"Expired on {exp_date.strftime('%Y-%m-%d %H:%M:%S')}"
                analysis["security_issues"].append("Token is expired")
            else:
                analysis["expiration"] = f"Expires on {exp_date.strftime('%Y-%m-%d %H:%M:%S')}"
        
        if decoded["header"].get("alg") == "none":
            analysis["security_issues"].append("Using 'none' algorithm is insecure")
        
        if decoded["header"].get("alg") == "HS256":
            analysis["security_issues"].append("HS256 algorithm can be vulnerable to brute force attacks if using a weak secret")
        
        analysis["juicy_info"] = {
            key: value for key, value in decoded["payload"].items() 
            if key.lower() in JUICY_FIELDS or any(juicy in key.lower() for juicy in JUICY_FIELDS)
        }
        
        return analysis
    except Exception as e:
        return {"error": str(e)}

def extract_jwt_from_url(url):
    """Extract JWT token from a URL string"""
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Check query parameters for JWT
        for values in query_params.values():
            for value in values:
                decoded_value = unquote(value)
                if re.match(JWT_REGEX, decoded_value):
                    return decoded_value
        
        decoded_url = unquote(url)
        match = JWT_REGEX.search(decoded_url)
        if match:
            return match.group(0)
    except Exception:
        pass
    
    return None

def fetch_wayback_urls(target, retries=3):
    """Fetch archived URLs for a domain from Wayback Machine"""
    wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}&output=text&fl=original&collapse=urlkey"
    
    for _ in range(retries):
        try:
            response = requests.get(wayback_url, headers=HEADERS)
            if response.status_code == 200:
                return response.text.splitlines()
        except requests.exceptions.RequestException:
            import time
            time.sleep(5)
    
    return []

def scan_domain_for_jwts(domain):
    """Scan a domain for JWTs using Wayback Machine"""
    results = {
        "urls_scanned": 0,
        "jwts_found": [],
        "summary": {"urls_scanned": 0, "jwt_found": 0, "decoded": 0}
    }
    
    # Fetch URLs from Wayback Machine
    urls = fetch_wayback_urls(domain)
    results["urls_scanned"] = len(urls)
    results["summary"]["urls_scanned"] = len(urls)
    
    # Extract and decode JWTs from each URL
    for url in urls:
        token = extract_jwt_from_url(url)
        if token:
            decoded_result = decode_jwt(token)
            
            # Make sure decoded results follow the same structure expected by templates
            if "error" not in decoded_result:
                jwt_info = {
                    "url": url,
                    "token": token,
                    "decoded": {
                        "header": decoded_result["header"],
                        "payload": decoded_result["payload"],
                        "signature": decoded_result["signature"]
                    }
                }
            else:
                jwt_info = {
                    "url": url,
                    "token": token,
                    "decoded": decoded_result
                }
                
            results["jwts_found"].append(jwt_info)
    
    # Update summary statistics
    results["summary"]["jwt_found"] = len(results["jwts_found"])
    results["summary"]["decoded"] = len([jwt for jwt in results["jwts_found"] if "error" not in jwt["decoded"]])
    
    return results
