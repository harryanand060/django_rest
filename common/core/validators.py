from __future__ import absolute_import, division, print_function, unicode_literals
import re
import six
from binascii import unhexlify
from django.core import validators
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.conf import settings
from common.helper import CommonHelper


@deconstructible
class ASCIIUsernameValidator(validators.RegexValidator):
    regex = r'^[\w.@+-]+$'
    message = _(
        'Enter a valid username. This value may contain only English letters, '
        'numbers, and @/./+/-/_ characters.'
    )
    flags = re.ASCII


@deconstructible
class UnicodeUsernameValidator(validators.RegexValidator):
    regex = r'^[\w.@+-]+$'
    message = _(
        'Enter a valid username. This value may contain only letters, '
        'numbers, and @/./+/-/_ characters.'
    )
    flags = 0


@deconstructible
class MobileValidator(validators.RegexValidator):
    regex = settings.MOBILE_PATTERN
    message = _("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")


validate_mobile = MobileValidator()


def validate_user(value):
    kwargs = CommonHelper.email_or_mobile(value)
    if kwargs:
        if not CommonHelper.user_exists(**kwargs):
            raise ValidationError(_("User not exists"))
    else:
        raise ValidationError(_("Please enter valid email or mobile"))
    return value


def hex_validator(length=0):
    """
    Returns a function to be used as a model validator for a hex-encoded
    CharField. This is useful for secret keys of all kinds::

        def key_validator(value):
            return hex_validator(20)(value)

        key = models.CharField(max_length=40, validators=[key_validator], help_text=u'A hex-encoded 20-byte secret key')

    :param int length: If greater than 0, validation will fail unless the
        decoded value is exactly this number of bytes.

    :rtype: function

    >>> hex_validator()('0123456789abcdef')
    >>> hex_validator(8)(b'0123456789abcdef')
    >>> hex_validator()('phlebotinum')          # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
        ...
    ValidationError: ['phlebotinum is not valid hex-encoded data.']
    >>> hex_validator(9)('0123456789abcdef')    # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
        ...
    ValidationError: ['0123456789abcdef does not represent exactly 9 bytes.']
    """

    def _validator(value):
        try:
            if isinstance(value, six.text_type):
                value = value.encode()

            unhexlify(value)
        except Exception:
            raise ValidationError('{0} is not valid hex-encoded data.'.format(value))

        if (length > 0) and (len(value) != length * 2):
            raise ValidationError('{0} does not represent exactly {1} bytes.'.format(value, length))

    return _validator
