from celery import shared_task


@shared_task
def add_task(x, y):
    return x + y
