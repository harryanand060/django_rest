from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404
from rest_framework import status
from rest_framework import exceptions
from rest_framework import views
from rest_framework.response import Response
from django.utils.text import gettext_lazy as _

from common.helper import CommonHelper


def custom_exception(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.

    response = custom_exception_handler(exc, context)
    # Now add the HTTP status code to the response.
    if response is not None:
        response.data = CommonHelper.render(False, None, response.data, response.status_code)
    return response


def custom_exception_handler(exc, context):
    """
       Returns the response that should be used for any given exception.

       By default we handle the REST framework `APIException`, and also
       Django's built-in `Http404` and `PermissionDenied` exceptions.

       Any unhandled exceptions may return `None`, which will cause a 500 error
       to be raised.
       """
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, exceptions.PermissionDenied):
        exc = exceptions.PermissionDenied()
    elif isinstance(exc, ObjectDoesNotExist):
        exc = DoesNotExist()
    elif isinstance(exc, exceptions.AuthenticationFailed):
        exc = exceptions.AuthenticationFailed("Token has expired")

    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait

        if isinstance(exc.detail, (list, dict)):
            data = exc.detail
        else:
            data = {'detail': exc.detail}

        views.set_rollback()
        return Response(data, status=exc.status_code, headers=headers)

    return None


class DoesNotExist(exceptions.APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Token has expired')
    default_code = 'authentication_failed'
