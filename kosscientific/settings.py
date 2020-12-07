"""
Django settings for kosscientific project.

Generated by 'django-admin startproject' using Django 2.2.7.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

import os
from django.contrib.messages import constants as messages

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'd*p4xqwfe0n_oqj(=hw1a(z3u)773ky+&46z9#p94wk*a&ss9w'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
TESTING = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'channels',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'koscientific',
    'cities_light',
    'kosmemberapi',
    'rest_framework',
    'corsheaders',
    'notification',
    'ckeditor',
    'ckeditor_uploader',
    'django_crontab',
    'django_select2',
    'crispy_forms'
]
CRISPY_TEMPLATE_PACK = 'bootstrap4'


AUTH_USER_MODEL = 'koscientific.User'

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)


# City light python lib for country state city data
CITIES_LIGHT_TRANSLATION_LANGUAGES = ['fr', 'en']
# CITIES_LIGHT_INCLUDE_COUNTRIES = ['']
CITIES_LIGHT_INCLUDE_CITY_TYPES = ['PPL', 'PPLA', 'PPLA2', 'PPLA3', 'PPLA4', 'PPLC', 'PPLF', 'PPLG', 'PPLL', 'PPLR', 'PPLS', 'STLMT',]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ORIGIN_ALLOW_ALL = True

CORS_ALLOW_METHODS = (
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
)

CORS_ALLOW_HEADERS = (
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'tus-resumable',
    'upload-length',
    'upload-metadata',
    'upload-offset',
)

ROOT_URLCONF = 'kosscientific.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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
ASGI_APPLICATION = 'notification.routing.application'

WSGI_APPLICATION = 'kosscientific.wsgi.application'

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("localhost", 6379)],
        },
    },
}


# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'kosscientific',
        'USER': 'root',
        'PASSWORD': 'welcome',
        'HOST': 'localhost',  # Or an IP Address that your DB is hosted on
        'PORT': '3306',
        'OPTIONS': {
            'sql_mode': 'traditional',
        }
    }
}
# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/


STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

STATIC_ROOT = os.path.join(BASE_DIR, "collect_static")

MESSAGE_TAGS = {
    messages.ERROR: 'danger'
}


MEDIA_ROOT =  os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'

#********************************************************#
#****************SMS settings****************************#
#********************************************************#

CAN_SEND_SMS = True # enable to send sms

sms_credential = {
    'api': 'http://api.msg91.com/api/sendhttp.php',
    'otp_api': 'https://api.msg91.com/api/v5/otp',
    'auth_key': '322620AEIWl8y45e68bd50',
    'sender': 'KOSKOS',
    'route': 4,
    'country': 91,
    'otp_expiry': 5000
}

#********************************************************#
#****************Email settings**************************#
#********************************************************#
EMAIL_BACKEND ='django.core.mail.backends.smtp.EmailBackend'
CAN_SEND_MAIL = True # enable to send email

#********************************************************#
#****************Ckeditor settings***********************#
#********************************************************#

CKEDITOR_UPLOAD_PATH = "uploadsCK/"
CKEDITOR_RESTRICT_BY_USER = True
CKEDITOR_STORAGE_BACKEND = "koscientific.storage.FileSystemStoragee"
CKEDITOR_MEDIA_URL = "https://member.kosonline.org/media/"
CKEDITOR_CONFIGS = {
    'default': {
        'width': '100%',
        'height': 'auto',
        'toolbar': 'Custom',
        'toolbar_Custom': [
            ['Bold', 'Italic', 'Underline'],
            ['Font', 'FontSize','TextColor', 'BGColor'],
            ['NumberedList', 'BulletedList', '-', 'Outdent', 'Indent', '-', 'JustifyLeft', 'JustifyCenter', 'JustifyRight', 'JustifyBlock'],
            ['Link', 'Unlink'],
            ['RemoveFormat', 'Image']
        ],
    
    },
}
#****************************************#
# one time link expiration time in days #
ONE_TIME_LINK_VALID_UPTO = 2 # days

# max paper limit
MAX_IC_PAPER_LIMIT = 225
MAX_FREE_PAPER_LIMIT = 225
MAX_VIDEOS_LIMIT = 225

# Razor pay keys
if TESTING:
    RAZOR_PAY_KEY = 'rzp_test_eTodfnkdR5B7ib'
    RAZOR_PAY_SECRET = 'dIZiXMGy2C2zSwne5nqDedtt'
    RAZOR_PAY_AMOUNT = 100 #paisa
else:
    RAZOR_PAY_KEY = 'rzp_live_5kVdeBEokiahFO'
    RAZOR_PAY_SECRET = '9icy5zzGH8lZIqr56VogHCss'
    RAZOR_PAY_AMOUNT = 400000 #paisa
RAZOR_PAY_CURRENCY = 'INR'

########################################
# max adding multiple co instructor limit
########################################
IC_PAPER_MAX_NON_MEMBER = 1
IC_PAPER_MAX_MEMBER = 4
FREE_PAPER_MAX_NON_MEMBER = 1
FREE_PAPER_MAX_MEMBER = 4
VIDEO_PAPER_MAX_NON_MEMBER = 1
VIDEO_PAPER_MAX_MEMBER = 4

# form auto save for every 60 second
AUTO_SAVE_IN = 60000 # seconds

# NOTE: Run “python manage.py crontab add” each time you change CRONJOBS in any way!
# Doc in https://pypi.org/project/django-crontab/
CORN_ROOT =  os.path.join(BASE_DIR, 'log')
CRONJOBS = [('0 0 */2 * *', 'koscientific.cron.all_paper_incomplete', '>> {}/scheduled_job.log'.format(CORN_ROOT)),
            ('0 0 * * *', 'koscientific.cron.application_form_incomplete',
             '>> {}/scheduled_job.log'.format(CORN_ROOT)),
            ('0 0 * * *', 'koscientific.cron.evaluator_reminder',
             '>> {}/scheduled_job.log'.format(CORN_ROOT))
            ]

DOMAIN_NAME = 'https://member.kosonline.org'


#=========secretary settings ================#
if TESTING:
    SECRETARY_MAIL = "ranjeetrock99@gmail.com"
    INFO_KOS_ONLINE_MAIL = "ranjeetrock99@gmail.com"
    AGM_MAIL = "ranjeetrock99@gmail.com"
    PRESIDENT_MAIL = "ranjeetrock99@gmail.com"
    ELECTION_PRESIDENT_MAIL = "ranjeetrock99@gmail.com"
    VICE_PRESIDENT_MAIL = "ranjeetrock99@gmail.com"
    TREASURER_MAIL = "ranjeetrock99@gmail.com"
    SCIENTIFIC_CHAIRMAN = "ranjeetrock99@gmail.com"
else:
    SECRETARY_MAIL = "secretary@kosonline.org"
    INFO_KOS_ONLINE_MAIL = "info@kosonline.org"
    AGM_MAIL = "info@kosonline.org"
    PRESIDENT_MAIL = "president@kosonline.org"
    ELECTION_PRESIDENT_MAIL = "info@kosonline.org"
    VICE_PRESIDENT_MAIL = "info@kosonline.org"
    TREASURER_MAIL = "treasurer@kosonline.org"
    SCIENTIFIC_CHAIRMAN = "info@kosonline.org"


#============================================#

#===========marks difference================
PERCENTAGE_DIFFERENCE = 30
#===========================================

# log
LOG_ROOT = os.path.join(BASE_DIR,'log')

if not os.path.exists(LOG_ROOT):
    os.makedirs(LOG_ROOT)

LOG_BACKUP_COUNT = 1
LOG_MAX_FILE_SIZE = 1024*1024*10 # 10MB
LOG_HANDLER_CLASS = 'logging.handlers.RotatingFileHandler'
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(levelname)s %(asctime)s %(name)s.%(funcName)s:%(lineno)s- %(message)s'
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': LOG_HANDLER_CLASS,
            'filename': BASE_DIR + "/log/info.log",
            'formatter': 'simple',
            'maxBytes': LOG_MAX_FILE_SIZE,
            'backupCount': LOG_BACKUP_COUNT,
        },
        'error': {
            'level': 'ERROR',
            'class': LOG_HANDLER_CLASS,
            'filename': BASE_DIR + "/log/error.log",
            'formatter': 'simple',
            'maxBytes': LOG_MAX_FILE_SIZE,
            'backupCount': LOG_BACKUP_COUNT,
        },
        'debug': {
            'level': 'DEBUG',
            'class': LOG_HANDLER_CLASS,
            'filename': BASE_DIR + "/log/debug.log",
            'formatter': 'simple',
            'maxBytes': LOG_MAX_FILE_SIZE,
            'backupCount': LOG_BACKUP_COUNT,
        },
        'critical': {
            'level': 'CRITICAL',
            'class': LOG_HANDLER_CLASS,
            'filename': BASE_DIR + "/log/critical.log",
            'maxBytes': LOG_MAX_FILE_SIZE,
            'backupCount': LOG_BACKUP_COUNT,
        },
    },
    'loggers': {
        '': {
            'handlers': ['critical', 'debug', 'file', 'error'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },

}