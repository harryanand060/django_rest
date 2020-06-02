from binascii import unhexlify

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils.text import gettext_lazy as _
from django.utils import timezone
from django.core.mail import send_mail
from django.core.validators import validate_email
from .utils import validators, topt, account_helper
from .auth.manager import UserManager, DeviceManager
from django.conf import settings
from rest_framework_jwt.settings import api_settings
import logging
import time

from datetime import datetime

# from . import validators

logger = logging.getLogger("accounts.token")
# Create your models here.
validate_mobile = validators.MobileValidator()


class User(AbstractBaseUser, PermissionsMixin):
    mobile = models.CharField(
        _('mobile'), max_length=16, unique=True,
        help_text=_("Required. mobile number must be entered in the format: '+999999999'."),
        validators=[validate_mobile],
        error_messages={'unique': _("A user with that mobile no already exists")}, )

    email = models.EmailField(
        _('Email Address'), max_length=100, unique=True,
        help_text=_("Required. email number must be entered in the format: 'abc@abc.com'."),
        validators=[validate_email],
        error_messages={'unique': _("A user with that email already exists.")}, )

    password = models.CharField(
        _('Password'), max_length=128,
        help_text=_("Required. enter password."), )

    first_name = models.CharField(
        _('first name'), max_length=30, blank=False,
        help_text=_('Required. Please enter name '), )

    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=False,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'mobile'
    REQUIRED_FIELDS = ['email', 'password']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        # abstract = True

    def __str__(self):
        """
        Returns a string representation of this `User`.

        This string is used when a `User` is printed in the console.
        """
        return self.email

    @property
    def token(self):
        """
        Allows us to get a user's token by calling `user.token` instead of
        `user.generate_jwt_token().

        The `@property` decorator above makes this possible. `token` is called
        a "dynamic property".
        """
        return self._generate_jwt_token()

    def clean(self):
        super.clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def _generate_jwt_token(self):
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        token = jwt_encode_handler(jwt_payload_handler(self))
        return token


def default_key():
    return validators.random_hex(20).decode()


class Verification(models.Model):
    user = models.OneToOneField(User, related_name='verification', on_delete=models.CASCADE)
    unverified_mobile = models.CharField(
        _('mobile'), max_length=16, unique=True,
        help_text=_("Required. mobile number must be entered in the format: '+999999999'."),
        validators=[validate_mobile],
        error_messages={'unique': _("A user with that mobile no already exists.")}, )

    unverified_email = models.EmailField(
        _('Email Address'), max_length=100, unique=True,
        help_text=_("Required. email number must be entered in the format: 'abc@abc.com'."),
        validators=[validate_email],
        error_messages={'unique': _("A user with that email already exists.")}, )

    secret_key = models.CharField(
        max_length=40,
        default=default_key,
        validators=[validators.hex_validator],
        help_text="Hex-encoded secret key to generate totp tokens.",
        unique=True,
    )

    last_reset_verified_counter = models.BigIntegerField(
        default=-1,
        help_text=("The counter value of the latest verified reset token."
                   "The next token must be at a higher counter value."
                   "It makes sure a token is used only once.")
    )
    last_email_verified_counter = models.BigIntegerField(
        default=-1,
        help_text=("The counter value of the latest verified email token."
                   "The next token must be at a higher counter value."
                   "It makes sure a token is used only once.")
    )
    last_mobile_verified_counter = models.BigIntegerField(
        default=-1,
        help_text=("The counter value of the latest verified mobile token."
                   "The next token must be at a higher counter value."
                   "It makes sure a token is used only once.")
    )
    mobile_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    is_reset = models.BooleanField(default=False)
    step = settings.TOTP_TOKEN_VALIDITY
    digits = settings.TOTP_DIGITS

    objects = DeviceManager()

    class Meta(object):
        verbose_name = "Verification"

    def __str__(self):
        """
        Returns a string representation of this `User`.

        This string is used when a `User` is printed in the console.
        """
        return str(self.user)

    @property
    def bin_key(self):
        return unhexlify(self.secret_key.encode())

    def totp_obj(self):
        totp = topt.TOTP(key=self.bin_key, step=self.step, digits=self.digits)
        totp.time = time.time()
        return totp

    def generate_otp(self):
        totp = self.totp_obj()
        token = str(totp.token()).zfill(self.digits)
        time_validity = self.step // 60
        logger.debug("Token has been sent to %s " % self.unverified_mobile)
        account_helper.verification_mail(self.user, token, time_validity)
        account_helper.sent_sms(self.user, token, time_validity)
        return token

    def verify_otp(self, type, token, tolerance=0):
        verified = False
        totp = self.totp_obj()
        if type == "email":
            if totp.t() > self.last_email_verified_counter and totp.verify(token, tolerance=tolerance):
                self.last_email_verified_counter = totp.t()
                self.email_verified = True
                self.save()
                verified = self.email_verified
        elif type == "mobile":
            if totp.t() > self.last_mobile_verified_counter and totp.verify(token, tolerance=tolerance):
                self.last_mobile_verified_counter = totp.t()
                self.mobile_verified = True
                self.save()
                verified = self.mobile_verified
        elif type == "reset":
            if totp.t() > self.last_reset_verified_counter and totp.verify(token, tolerance=tolerance):
                self.last_reset_verified_counter = totp.t()
                self.is_reset = True
                self.save()
                verified = self.is_reset
        if verified:
            self.user.is_active = True
            self.user.save()
        return verified
