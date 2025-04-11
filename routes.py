from flask import render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename
import os
import uuid
from utils.jwt_utils import decode_jwt, analyze_jwt, scan_domain_for_jwts
from tasks import decode_jwt_task, analyze_jwt_task, scan_domain_task
import markupsafe

def register_routes(app):
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/decode', methods=['POST'])
    def decode():
        jwt_token = request.form.get('jwt_token', '')
        if not jwt_token:
            return jsonify({"error": "No JWT token provided"}), 400
        
        # Start background task for JWT decoding
        task = decode_jwt_task.delay(jwt_token)
        return redirect(url_for('results', task_id=task.id))
    
    @app.route('/analyze', methods=['POST'])
    def analyze():
        jwt_token = request.form.get('jwt_token', '')
        if not jwt_token:
            return jsonify({"error": "No JWT token provided"}), 400
        
        # Start background task for JWT analysis
        task = analyze_jwt_task.delay(jwt_token)
        return redirect(url_for('results', task_id=task.id))
    
    @app.route('/scan_domain', methods=['POST'])
    def scan_domain():
        domain = request.form.get('domain', '')
        if not domain:
            return jsonify({"error": "No domain provided"}), 400
        
        # Start background task for domain scanning
        task = scan_domain_task.delay(domain)
        return redirect(url_for('scan_results', task_id=task.id))
    
    @app.route('/scan_results/<task_id>')
    def scan_results(task_id):
        from tasks import celery_app
        task_result = celery_app.AsyncResult(task_id)
        
        if task_result.ready():
            results = task_result.get()
            domain = results.get('domain', 'Unknown domain')
            return render_template('scan_results.html', results=results, domain=domain)
        else:
            return render_template('loading.html', task_id=task_id, task_type='scan')
    
    @app.route('/results/<task_id>')
    def results(task_id):
        from tasks import celery_app
        task_result = celery_app.AsyncResult(task_id)
        
        if task_result.ready():
            result = task_result.get()
            
            # Handle different types of results (decode vs analyze)
            if isinstance(result, dict) and 'decoded' in result:
                # This is from an analysis task, restructure for template
                decoded = result.get('decoded', {})
                result.update(decoded)  # Move decoded content to the top level
                result.pop('decoded', None)  # Remove the decoded key
            
            # Sanitize any user data to prevent SSTI
            for key in result:
                if isinstance(result[key], str):
                    result[key] = markupsafe.escape(result[key])
            
            return render_template('results.html', result=result, task_complete=True)
        else:
            return render_template('loading.html', task_id=task_id, task_type='analyze')
    
    @app.route('/check_task/<task_id>')
    def check_task(task_id):
        from tasks import celery_app
        task_result = celery_app.AsyncResult(task_id)
        
        if task_result.ready():
            return jsonify({'status': 'complete'})
        else:
            return jsonify({'status': 'pending'})
