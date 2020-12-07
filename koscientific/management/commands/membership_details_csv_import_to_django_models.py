from django.core.management.base import BaseCommand
import csv
import time
from django.conf import settings
import json
from koscientific.models import *


class Command(BaseCommand):
    help = 'move users from csv to django models'

    def handle(self, *args, **kwargs):
       
        try:
            start_time = time.time()
            with open('/home/admi/Downloads/dd.csv') as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                line_count = 0
                final_user_created = 0
                final_profile_created = 0
                final_membership_created = 0

                for col in csv_reader:
                    if line_count == 0:
                        self.stdout.write(self.style.WARNING(
                            f'Column names are {", ".join(col)}.'))
                        line_count += 1
                    else:
                        first_name, last_name, email, username = self.get_user_info(col[1], col[11], col[20])
                        
                        kos_no = col[0].strip()
                        mobile_no = col[8].replace('O', '0').replace('o', '0').strip()
                        mobile_no1 = col[19].replace('O', '0').replace('o', '0').strip()
                        pincode = col[7].strip()

                        # Validate mobile number
                        if '*' in mobile_no or len(mobile_no) > 10:
                            mobile_no = ''
                        
                        # Validate mobile number
                        if '*' in mobile_no1 or len(mobile_no1) > 10:
                            mobile_no = ''
                        else:
                            mobile_no = mobile_no1
                        
                        user_info = 'first_name => {}, last_name => {}, email=> {}, username =>{}, mobile_no=>{}, kos_no=>{}'.format(
                            first_name, last_name, email, username, mobile_no, kos_no)
                        self.stdout.write(self.style.SUCCESS(user_info))
                        
                        # If email is empty then it not at all possible to create user

                        if email != '' and kos_no != '':

                            if not User.objects.filter(email=email).exists():
                                # Import user
                                self.stdout.write(self.style.WARNING(
                                    'Importing creating user...'))

                                user = User()
                                user.first_name = first_name
                                user.last_name = last_name
                                user.username = username
                                user.email = email
                                user.set_password('{}@kos123'.format(first_name))
                                user.save()
                                final_user_created += 1
                                message = 'user {} created'.format(email)
                                self.stdout.write(self.style.SUCCESS(message))

                                if not Profile.objects.filter(user__email=email).exists():
                                    
                                    if mobile_no != '':
                                        # Import profile
                                        self.stdout.write(self.style.WARNING('Importing profile data'))
                                        profile = Profile()
                                        profile.user = user
                                        profile.mobile_number = mobile_no
                                        profile.save()
                                        final_profile_created += 1
                                        message = 'user {} profile created'.format(email)
                                        self.stdout.write(self.style.SUCCESS(message))

                                if not MemberShip.objects.filter(kos_no=kos_no).exists():
                                    # Import membership data
                                    self.stdout.write(self.style.WARNING('Importing membership data'))
                                    member_ship = MemberShip()
                                    member_ship.user = user
                                    member_ship.kos_no = kos_no
                                    if mobile_no != '':
                                        member_ship.mobile = mobile_no
                                    if pincode != '':
                                        member_ship.office_pincode = pincode
                                        member_ship.recidence_pincode = pincode
                                    member_ship.save()
                                    final_membership_created += 1
                                    message = 'user {} member_ship created'.format(email)
                                    self.stdout.write(self.style.SUCCESS(message))

                        line_count += 1
                        if line_count == 4:
                            break
                        
                print(f'Processed {line_count} lines.')

                
            print("--- %s seconds ---" % (time.time() - start_time))
        except Exception as e:
            print("--- %s seconds ---" % (time.time() - start_time))
            print('error in main ', e)
            
        message = 'user created {}, profile {}, membership {}'.format(
            final_user_created,
            final_profile_created,
            final_membership_created)
        self.stdout.write(self.style.SUCCESS(message))

    def get_user_info(self, name_col, email_col, second_email_col):
        print('name_col --------->', name_col)
        print('email_col -------->', email_col)
        print('second_email_col ->', second_email_col )

        full_name = str(name_col).replace('Dr.', '').replace('Dr', '').strip()
        last_name = full_name.split(' ')[-1]
        first_name = " ".join(full_name.split(' ')[:-1])

        if first_name.strip() == '':
            first_name = full_name.split(' ')[-1]
            last_name = ''
        else:

            first_name = " ".join(full_name.split(' ')[:-1])

        email = str(email_col).replace('*', '').strip()
        second_email_col = str(second_email_col).replace('*', '').strip()
        
        # Compare two mails
        if '/' in second_email_col:
            email = ''.join(second_email_col.split('/')[:1]).strip()

        if second_email_col != '':
            email = second_email_col
        elif email != '':
            email = email
        
        username = email

        return first_name, last_name, email.strip(), username.strip()
