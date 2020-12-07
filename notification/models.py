from django.db import models
# from django.contrib.auth import get_user_model
from django.conf import settings
# User = get_user_model()
# Create your models here.
class MessageNotification(models.Model):
    ''' Main Message system'''

    message_from = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages", null=True, blank=True )
    text_message = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.text_message


    class Meta:
        db_table = 'MessageNotification'
        verbose_name = 'Message notification'
        verbose_name_plural = 'Message notifications'
        ordering = ('-created_at',)

class Message(models.Model):
    ''' user messages '''
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="messages",)
    message = models.ForeignKey(MessageNotification, related_name='user_messages' , on_delete=models.CASCADE)
    is_readed = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.user)+ ' '+ str(self.message)
