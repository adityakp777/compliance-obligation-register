# app.py
# AI Developer 3 — Flask Entry Point with Rate Limiting
# Day 4 — Tool-11 Compliance Obligation Register

from flask_talisman import Talisman
import os
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from routes.describe import describe_bp
from routes.recommend import recommend_bp
from routes.categorise import categorise_bp
from routes.generate_report import generate_report_bp
from routes.query import query_bp

# ------------------------------------------------------------------ #
# App initialisation                                                   #
# ------------------------------------------------------------------ #

app = Flask(__name__)
# Remove server header to prevent version disclosure — fixes ZAP finding
@app.after_request
def remove_server_header(response):
    response.headers['Server'] = 'Tool-11-AI-Service'
    return response
# ------------------------------------------------------------------ #
# Security headers — fixes ZAP findings F-001, F-002, F-003, F-004  #
# ------------------------------------------------------------------ #

Talisman(
    app,
    force_https=False,           # False for local dev — True in production
    strict_transport_security=False,  # disable HSTS for local dev
    content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': "'self'",
    'img-src': "'self'",
    'font-src': "'self'",
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'form-action': "'self'",
    'base-uri': "'self'",
},
    x_content_type_options=True,     # fixes F-004
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
    }
)

# ------------------------------------------------------------------ #
# Rate limiting                                                        #
# ------------------------------------------------------------------ #

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["30 per minute"],
    headers_enabled=True         # adds RateLimit headers to responses
)

# ------------------------------------------------------------------ #
# Register blueprints                                                  #
# ------------------------------------------------------------------ #

app.register_blueprint(describe_bp,       url_prefix='/describe')
app.register_blueprint(recommend_bp,      url_prefix='/recommend')
app.register_blueprint(categorise_bp,     url_prefix='/categorise')
app.register_blueprint(generate_report_bp, url_prefix='/generate-report')
app.register_blueprint(query_bp,          url_prefix='/query')

# ------------------------------------------------------------------ #
# Apply stricter limit to generate-report                             #
# ------------------------------------------------------------------ #

limiter.limit("10 per minute")(generate_report_bp)

# ------------------------------------------------------------------ #
# Health check endpoint                                                #
# ------------------------------------------------------------------ #

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "service": "Tool-11 AI Service",
        "port": 5000
    }), 200

# ------------------------------------------------------------------ #
# 429 handler — rate limit exceeded                                    #
# ------------------------------------------------------------------ #

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description),
        "retry_after": e.retry_after if hasattr(e, 'retry_after') else 60
    }), 429

# ------------------------------------------------------------------ #
# Run                                                                  #
# ------------------------------------------------------------------ #

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5001, debug=debug_mode)