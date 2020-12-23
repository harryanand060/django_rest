import re
import environ

env = environ.Env()
# reading .env file
environ.Env.read_env()


# ******************CUSTOME SETTINGS*******************************

TEMPLATES_DIRECTORY = ["account/templates"]

EMAIL_PATTERN = re.compile(r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
                           r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-011\013\014\016-\177])*"'  # quoted-string
                           r')@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?$', re.IGNORECASE)  # domain

MOBILE_PATTERN = re.compile(r'^\+?1?\d{9,15}$')

EMAIL_USE_TLS = env('EMAIL_USE_TLS')
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
EMAIL_PORT = env.int('EMAIL_PORT')

SMS_GETWAY = {
    'DEFAULT': env("SMS_GETWAY"),
    'TEST': {
        'url': env('SMS_API'),
        'apikey': env('SMS_API_KEY'),
        'username': env('SMS_USER_NAME'),
        'sendername': env('SMS_SENDER_NAME'),
        'smstype': env('SMS_TYPE'),
    },
    "PROD": {
        'url': env('SMS_API'),
        'apikey': env('SMS_API_KEY'),
        'username': env('SMS_USER_NAME'),
        'sendername': env('SMS_SENDER_NAME'),
        'smstype': env('SMS_TYPE'),
    }
}

TOTP_TOKEN_VALIDITY = env.int('OTP_TOKEN_VALIDITY')
TOTP_DIGITS = env.int('OTP_DIGITS')
