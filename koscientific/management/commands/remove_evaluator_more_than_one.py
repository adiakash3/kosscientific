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
            print("--- %s total evaluator ---" % (Evaluator.objects.count()))
            # assuming which duplicate is removed doesn't matter...
            for row in Evaluator.objects.all().reverse():
                if Evaluator.objects.filter(membership=row.membership).count() > 1:
                    row.delete()
            print("--- %s now evaluator ---" % (Evaluator.objects.count()))
            print("--- %s seconds ---" % (time.time() - start_time))
        except Exception as e:
            print("--- %s error seconds ---" % (time.time() - start_time))
            print('error in main ', e)
            
        message = 'done'
        self.stdout.write(self.style.SUCCESS(message))