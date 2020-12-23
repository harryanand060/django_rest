import time
from binascii import unhexlify
from django.conf import settings
from common.core import topt


class OTP:
    def __init__(self, secret_key):
        self.step = settings.TOTP_TOKEN_VALIDITY
        self.digits = settings.TOTP_DIGITS
        self.secret_key = secret_key

    @property
    def bin_key(self):
        return unhexlify(self.secret_key.encode())

    def totp_obj(self):
        totp = topt.TOTP(key=self.bin_key, step=self.step, digits=self.digits)
        totp.time = time.time()
        return totp

    def generate_otp(self):
        totp = self.totp_obj()
        return str(totp.token()).zfill(self.digits)

    def otp_validity(self):
        return self.step // 60
