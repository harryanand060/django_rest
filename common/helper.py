from rest_framework.views import exception_handler


def render(*args):
    return {
               "status": args[0],
               "data": args[1],
               "message": args[2],
               "status_code": args[3]
           }, args[3]


def custom_exception(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if response is not None:
        result, status_code = render(False, None, response.data, response.status_code)
        response.data = result

    return response
