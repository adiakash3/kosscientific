from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from koscientific.models import *
from .models import *
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


class WebNotification:
    ''' Web socket based Notification'''

    def __init__(self, host_user=None):
        self.host_user = host_user

    def send_notification_to_all(self, live_message):
        '''
        live_message will be sent to the all users
        '''
        full_message_title = live_message

        logger.info('sending web notifcation  %s', full_message_title)

        host_user = self.host_user if self.host_user else None
        message_notification = MessageNotification.objects.create(text_message=full_message_title,
                                                                  message_from=host_user)

        try:

            messages = []
            for user in User.objects.all():
                messages.append(Message(user=user, message=message_notification))
            Message.objects.bulk_create(messages)

            # Send message to room group
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "notification", {
                    "type": "user.message",
                    "event": "media_created",
                    "message": full_message_title
                }
            )
        except Exception as e:
            logger.error('Error while sending web socket notification %s', e)
            pass

    def send_only_notification_to_user(self, users=[], live_message=None):
        '''
        live_message will be sent to selected users
        @users list of querset
        @live_message message title
        '''
        full_message_title = live_message

        logger.info('sending web notifcation to selected user %s', full_message_title)

        host_user = self.host_user if self.host_user else None
        message_notification = MessageNotification.objects.create(text_message=full_message_title,
                                                                  message_from=host_user)

        try:
            messages = []
            for user in users:
                messages.append(Message(user=user, message=message_notification))
            Message.objects.bulk_create(messages)

            # Send message to room group
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "notification", {
                    "type": "user.message",
                    "event": "media_created",
                    "message": full_message_title
                }
            )
        except Exception as e:
            logger.error('Error while sending web socket notification %s', e)
            pass

    def send_only_notification_to_role(self, roles=None, live_message=None):
        '''
        live_message will be sent to selected roles
        @users roles in list
        @live_message message title
        '''
        
        full_message_title = live_message

        logger.info('sending web notifcation to selected user %s', full_message_title)

        host_user = self.host_user if self.host_user else None
        message_notification = MessageNotification.objects.create(text_message=full_message_title,
                                                                  message_from=host_user)

        try:
            messages = []
            for user in User.objects.filter(roles__in=roles):
                messages.append(Message(user=user, message=message_notification))
            Message.objects.bulk_create(messages)

            # Send message to room group
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "notification", {
                    "type": "user.message",
                    "event": "media_created",
                    "message": full_message_title
                }
            )
        except Exception as e:
            logger.error('Error while sending web socket notification %s', e)
            pass
