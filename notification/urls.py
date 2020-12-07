from django.urls import path
from .views import *

app_name = 'notification'

urlpatterns = [


    path('ajax/update_notification/', update_notification, name="update_notification"),

]

