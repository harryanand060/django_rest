import fileinput
import os
import re
import sys

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

    @staticmethod
    def save_to_settings(value, parameter_name, file_name: str, settings_dir_name=''):
        """
        Save the value to the given parameter in  file.
        :param value:
        :param parameter_name:
        :param file_name:
        :param settings_dir_name:
        :return:
        """

        if not settings_dir_name:
            settings_dir_name = ''

        settings_dir = os.path.join(settings.BASE_DIR, settings_dir_name, file_name)

        if not os.path.exists(settings_dir):
            raise FileNotFoundError(f"Can't find `.env` file: {settings_dir}")

        return CommonHelper._replace_line(value, parameter_name, settings_dir)

    @staticmethod
    def _replace_line(value, parameter_name, settings_file):
        """
        Method for replace the .env file Key Value
        :param value: value for text file
        :param parameter_name: Name of Parameter need to change
        :param settings_file: file location
        :return: True Or False
        """
        parameter_is_exist = False
        if parameter_name:
            new_line = f'{parameter_name}={value}'
            line_pattern = fr'^{parameter_name}=.*'
            new_env_file = []

            with open(settings_file, 'r') as env_file:
                for key in env_file.readlines():
                    if re.match(line_pattern, key):
                        parameter_is_exist = True
                    line = re.sub(line_pattern, new_line, key)
                    new_env_file.append(line)

            with open(settings_file, 'w') as env_file:
                for line in new_env_file:
                    env_file.writelines(line)

            if not parameter_is_exist:
                raise NameError(f"Can't find parameter name: {parameter_name}")
            return True
        return False
