from django.conf import settings
from django.contrib.auth.models import Group

from django.db.models.signals import post_save
from django.dispatch import receiver
import json
from notification.models import *
from .web_notifications import WebNotification

import logging
from koscientific.models import Role

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def user_created(sender, instance, created, **kwargs):
    ''' create client in keycloack'''

    if created:
        registered_group, created = Group.objects.get_or_create(name='Registered')
        instance.groups.add(registered_group)
        instance.roles.add(Role.REGISTERED)


@receiver(post_save, sender=MemberShip)
def membership(sender, instance, created, **kwargs):
    ''' send notification'''

    # if created:
    #     WebNotification(instance.user).send_notification_to_all('i submitted membership form')