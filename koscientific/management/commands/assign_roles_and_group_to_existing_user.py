from django.core.management.base import BaseCommand
import time
import json
from koscientific.models import *
from django.contrib.auth.models import Group


class Command(BaseCommand):
    help = 'assign roles and groups to existing user as member'

    def handle(self, *args, **kwargs):
       
        try:
            start_time = time.time()
            for user in User.objects.all():
                user.groups.clear()
                user.groups.add(Group.objects.get(name__iexact='member'))
                user.roles.clear()
                user.roles.add(Role.objects.get(pk=Role.MEMBER))
                user.save()
                
            print("--- %s seconds ---" % (time.time() - start_time))
        except Exception as e:
            print("--- %s error seconds ---" % (time.time() - start_time))
            print('error in main ', e)
            
        message = 'done'
        self.stdout.write(self.style.SUCCESS(message))