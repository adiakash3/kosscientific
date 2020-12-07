from  django.urls import path
from .views import *

app_name='kosmemberapi'

urlpatterns = [
    path('',Test, name='test'),
    path('testapi/',Testapi, name='testapi'),
    path('member/list/',MemberList, name='member_list'),

    ]


