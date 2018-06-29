"""
Django settings for componentTrustMonitor project.

Generated by 'django-admin startproject' using Django 2.0.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '8obe11(g7fw^x=9k50j%1twrszb-4s$1$hgy5_1299ef-ldi+3'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['localhost']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'trust_monitor.apps.TrustmonitorConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'trust_monitor_django.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'trust_monitor_django.wsgi.application'

USE_X_FORWARDED_HOST = True

# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join("/db", 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [{
    'NAME': 'django.contrib.auth.password_validation.'
    'UserAttributeSimilarityValidator',
}, {
    'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
}, {
    'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
}, {
    'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
},
]


# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = '/static'


CASSANDRA_LOCATION = ''
CASSANDRA_PORT = ''

OAT_LOCATION = ''

OPEN_CIT = ''

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s [%(asctime)s] %(module)s'
                      ': %(message)s',
            'datefmt': "%Y-%b-%d %H:%M:%S"
        },
    },
    'handlers': {
        'file-log': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/logs/trust-monitor.log',
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file-log'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

BASIC_URL_DARE = 'http://tm_dare_connector:5000'
BASIC_URL_STORE = 'http://localhost:5100'
BASIC_URL_DASHBOARD = 'http://tm_dashboard_connector:5000'
BASIC_URL_MANAGEOSM = 'http://tm_manage_osm_connector:5000'
BASIC_URL_STORE = 'http://tm_store_connector:5000'

try:
    LOCAL_SETTINGS
except NameError:
    try:
        from local_settings import *
    except ImportError:
        pass
