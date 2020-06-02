import datetime
import re

LOCAL_APPS = [
    'rest_framework',
    'common',
    'account'
]

AUTHENTICATION_BACKENDS = (
    # 'django.contrib.auth.backends.ModelBackend',
    'account.auth.backend.ModelBackend',
)

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        # 'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.coreapi.AutoSchema',
    'EXCEPTION_HANDLER': 'common.helper.custom_exception',
}

JWT_AUTH = {
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=3000),
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',

}

EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = '********@gmail.com'
EMAIL_HOST_PASSWORD = '************'
EMAIL_PORT = 587
# ******************CUSTOME SETTINGS*******************************
TOTP_TOKEN_VALIDITY = 900
TOTP_DIGITS = 6

TEMPLATES_DIRECTORY = ["account/templates"]

EMAIL_PATTERN = re.compile(r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
                           r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-011\013\014\016-\177])*"'  # quoted-string
                           r')@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?$', re.IGNORECASE)  # domain
MOBILE_PATTERN = re.compile(r'^\+?1?\d{9,15}$')

SMS_GETWAY = {
    'DEFAULT':"PROD",
    'TEST': {
        'url': 'http://sms.hspsms.com/sendSMS',
        'apikey': '65b8475e-6df8-4d19-95e0-56f7d979dc8e',
        'username': 'hspdemo',
        'sendername': 'hspsms',
        'smstype': 'TRANS',
    },
    "PROD": {
        'url': 'http://sms.hspsms.com/sendSMS',
        'apikey': '**********************',
        'username': '*****************',
        'sendername': '**************',
        'smstype': '***********',
    }
}
