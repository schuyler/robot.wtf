"""Shared Gunicorn configuration for robot.wtf WSGI services.

Used by: otterwiki (port 8000), platform (auth + management, port 8002).
The MCP sidecar uses uvicorn instead.

Usage:
    gunicorn -c app/gunicorn.conf.py app.wsgi:application
"""

import multiprocessing
import os

# Bind address — override with GUNICORN_BIND env var
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8000")

# Workers: 2*CPU+1, capped at 4
_cpu_count = multiprocessing.cpu_count()
workers = min(2 * _cpu_count + 1, 4)

# Timeout
timeout = 30

# Logging — access log to stdout, error log to stderr
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

# Preload app for faster worker startup (shared memory)
preload_app = True

# Graceful restart timeout
graceful_timeout = 10
