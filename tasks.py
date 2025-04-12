from celery import Celery
from utils.jwt_utils import decode_jwt, analyze_jwt, scan_domain_for_jwts
from config import Config

celery_app = Celery('jwt_exposer',
                 broker=Config.REDIS_URL,
                 backend=Config.RESULT_BACKEND)

@celery_app.task
def decode_jwt_task(token):
    result = decode_jwt(token)
    return result

@celery_app.task
def analyze_jwt_task(token):
    result = analyze_jwt(token)
    return result

@celery_app.task
def scan_domain_task(domain):
    """
    Background task to scan a domain for JWTs using Wayback Machine
    """
    results = scan_domain_for_jwts(domain)
    
    # Add domain to results for display context
    results['domain'] = domain
    
    # Process each JWT to add analysis info
    for jwt_info in results.get('jwts_found', []):
        if 'error' not in jwt_info.get('decoded', {}):
            jwt_info['analysis'] = analyze_jwt(jwt_info['token'])
    
    return results

