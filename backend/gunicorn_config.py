# Gunicorn configuration file for Render.com free tier
import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"
backlog = 2048

# Worker processes
workers = 2  # Reduced for free tier (512MB RAM)
worker_class = 'sync'
worker_connections = 1000
threads = 2
timeout = 300  # 5 minutes for large file uploads
keepalive = 2

# Memory management
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'secure-file-transfer'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Request handling
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
