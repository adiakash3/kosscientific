from django.core.management.base import BaseCommand
from koscientific.models import *


class Command(BaseCommand):
    help = 'script to make old user make introducer 1, introducer 2 and secretory signed'

    def handle(self, *args, **kwargs):
        MemberShip.objects.all().update(is_iis_signed=True,is_member=True,is_provisional=False)
        self.stdout.write(self.style.SUCCESS('3 signed done'))
        
