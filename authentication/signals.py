import logging
from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver
from django.utils.timezone import now

logger = logging.getLogger(__name__)

@receiver(user_login_failed)
def login_failed(sender, credentials, request, **kwargs):
    logger.warning(f"Failed login attempt at {now()} for username: {credentials['username']}")
