#!/bin/bash -e

if [[ -n "$RUN_DJANGO_APP" ]]; then
    python manage.py makemigrations trust_monitor
    python manage.py migrate
    python manage.py runserver 0.0.0.0:8000
fi

if [[ -n "$SERVE_STATIC" ]]; then
    python manage.py collectstatic --noinput
    cd /static
    python -m SimpleHTTPServer 8080
fi
