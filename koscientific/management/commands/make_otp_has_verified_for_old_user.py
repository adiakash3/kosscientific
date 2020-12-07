from django.core.management.base import BaseCommand
from koscientific.models import User
import time


class Command(BaseCommand):
    help = 'make otp is verified for the old user who are inserted through database'

    def handle(self, *args, **kwargs):
        st = time.time()
        users = User.objects.filter(profile__is_otp_verified=False, date_joined__lte='2020-02-01')
        for user in users:
            if hasattr(user, 'profile'):
                if user.profile.mobile_number:
                    user.profile.is_otp_verified=True
                    user.profile.save()
        message = "otp verified automatically for old users and took {} seconds".format(time.time()-st)
        self.stdout.write(self.style.SUCCESS(message))