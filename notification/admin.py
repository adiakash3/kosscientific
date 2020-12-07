from django.contrib import admin
from .models import *

# Register your models here.
class MessageNotificationAdmin(admin.ModelAdmin):
    list_display = ('message_from', 'text_message', 'created_at')
    list_filter = ('message_from',)
    search_fields = ('text_message', 'message_from')

admin.site.register(MessageNotification, MessageNotificationAdmin)


class MessageAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'is_readed', 'created_at')
    list_filter = ('user', )
    search_fields = ('user', 'message')

admin.site.register(Message, MessageAdmin)
