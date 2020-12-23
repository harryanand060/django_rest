from os import urandom
from binascii import hexlify
from django.contrib.auth import get_user_model
from django.conf import settings


class CommonHelper:
    @staticmethod
    def render(*args):
        return {
            "status": args[0],
            "data": args[1],
            "message": args[2],
            "status_code": args[3]
        }  # ,args[3]

    @staticmethod
    def is_email(value):
        return settings.EMAIL_PATTERN.search(value)

    @staticmethod
    def is_mobile(value):
        return settings.MOBILE_PATTERN.search(value)

    @staticmethod
    def user_exists(**kwargs):
        model = get_user_model()
        try:
            user = model.objects.get(**kwargs)
        except model.DoesNotExist:
            return False
        return user

    @staticmethod
    def secret_key():
        """
             Returns a string of random bytes encoded as hex. This uses
             :func:`os.urandom`, so it should be suitable for generating cryptographic
             keys.

             :param int length: The number of (decoded) bytes to return.

             :returns: A string of hex digits.
             :rtype: bytes

             """
        return hexlify(urandom(20)).decode()

    @staticmethod
    def email_or_mobile(value):
        UserModel = get_user_model()
        if CommonHelper.is_email(value):
            data = {UserModel.EMAIL_FIELD: value}
        elif CommonHelper.is_mobile(value):
            data = {UserModel.USERNAME_FIELD: value}
        else:
            data = {UserModel.USERNAME_FIELD: value}
        return data
