from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from common.helper import CommonHelper


class UserManager(BaseUserManager):
    use_in_migrations = True

    def get_by_natural_key(self, username):
        kwargs = CommonHelper.email_or_mobile(username)
        return self.get(**kwargs)


    def _create_user(self, mobile, email, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        if not mobile:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        mobile = self.model.normalize_username(mobile)
        user = self.model(mobile=mobile, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, mobile, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(mobile, email, password, **extra_fields)

    def create_superuser(self, mobile, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(mobile, email, password, **extra_fields)


class DeviceManager(models.Manager):
    """
    The :class:`~django.db.models.Manager` object installed as
    ``Device.objects``.
    """

    def devices_for_user(self, user, confirmed=None):
        """
        Returns a queryset for all devices of this class that belong to the
        given user.

        :param user: The user.
        :type user: :class:`~django.contrib.auth.models.User`

        :param confirmed: If ``None``, all matching devices are returned.
            Otherwise, this can be any true or false value to limit the query
            to confirmed or unconfirmed devices, respectively.
        """
        devices = self.model.objects.filter(user=user)
        if confirmed is not None:
            devices = devices.filter(confirmed=bool(confirmed))

        return devices
