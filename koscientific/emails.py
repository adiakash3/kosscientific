from django.core.mail import get_connection, send_mail as django_send_mail
from koscientific.models import *
from django.conf import settings
from django.core.mail import EmailMessage, EmailMultiAlternatives
class KosEmail:

    @staticmethod
    def send_mail(**kwargs):
        """
        normal with or without html mail
        """
        if settings.CAN_SEND_MAIL:
            email = MailSettings.objects.first()
            email_server = email.mail_server
            email_port = email.mail_port
            email_username = email.username
            email_password = email.password
            email_ssl = email.use_ssl
            from_email = email.from_email

            connection = get_connection(host=email_server, port=email_port, username=email_username,
                                        password=email_password, use_tls=email_ssl)
            subject = kwargs['subject']
            plain_message = kwargs['plain_message']
            recipient_list = (kwargs['recipient_list']).split(',')
            html_message = kwargs.get('html_message', None)
            send = django_send_mail(subject=subject, message=plain_message, from_email=from_email,
                                    recipient_list=recipient_list, connection=connection, fail_silently=False,
                                    html_message=html_message)

            return 'success'
        else:
            raise Exception('Email function is disabled by admin')
        
    @staticmethod
    def send_mail_altered(**kwargs):
        """
        if recipient_list is more
        normal with or without html mail
        """
        if settings.CAN_SEND_MAIL:
            email = MailSettings.objects.first()
            email_server = email.mail_server
            email_port = email.mail_port
            email_username = email.username
            email_password = email.password
            email_ssl = email.use_ssl
            from_email = email.from_email
            

            connection = get_connection(host=email_server, port=email_port, username=email_username,
                                        password=email_password, use_tls=email_ssl)
            subject = kwargs['subject']
            plain_message = kwargs['plain_message']
            recipient_list = kwargs['recipient_list']
            html_message = kwargs.get('html_message', None)
            send = django_send_mail(subject=subject, message=plain_message, from_email=from_email,
                                    recipient_list=recipient_list, connection=connection, fail_silently=False,
                                    html_message=html_message)

            return 'success'
        else:
            raise Exception('Email function is disabled by admin')
        
    @staticmethod
    def mass_mail(**kwargs):
        """
        mass mail with or without html mail
        """
        if settings.CAN_SEND_MAIL:
            email = MailSettings.objects.first()
            email_server = email.mail_server
            email_port = email.mail_port
            email_username = email.username
            email_password = email.password
            email_ssl = email.use_ssl
            from_email = email.from_email
            

            connection = get_connection(host=email_server, port=email_port, username=email_username,
                                        password=email_password, use_tls=email_ssl)
            subject = kwargs['subject']
            plain_message = kwargs['plain_message']
            recipient_list = kwargs['recipient_list']
            html_message = kwargs.get('html_message', None)
            send = django_send_mail(subject=subject, message=plain_message, from_email=from_email,
                                    recipient_list=recipient_list, connection=connection, fail_silently=False,
                                    html_message=html_message)

            return 'success'
        else:
            raise Exception('Email function is disabled by admin')
        
    @staticmethod
    def send_email(**kwargs):
        """
        first level mail with cc, bcc, email attachment and not html message
        """
        if settings.CAN_SEND_MAIL:
            email = MailSettings.objects.first()
            email_server = email.mail_server
            email_port = email.mail_port
            email_username = email.username
            email_password = email.password
            email_ssl = email.use_ssl
            from_email = email.from_email
            

            connection = get_connection(host=email_server, port=email_port, username=email_username,
                                        password=email_password, use_tls=email_ssl)
            subject = kwargs['subject']
            plain_message = kwargs['plain_message']
            to= kwargs['to']
            cc = kwargs.get('cc', None)
            bcc = kwargs.get('bcc', None)
            email = EmailMessage(subject=subject, body=plain_message, from_email=from_email,
                                    to=to,cc=cc,connection=connection, headers={'Message-ID': 'foo'})
            if 'file_path' in kwargs and 'mimetype' in kwargs:
                email.attach_file(path=kwargs['file_path'], mimetype=kwargs['mimetype'])
            email.send()

            return 'success'
        else:
            raise Exception('Email function is disabled by admin')
        
    
    @staticmethod
    def send_multi_alternatives_email(**kwargs):
        """
        second level mail with cc, bcc, email attachment and html message
        """
        if settings.CAN_SEND_MAIL:
            email = MailSettings.objects.first()
            email_server = email.mail_server
            email_port = email.mail_port
            email_username = email.username
            email_password = email.password
            email_ssl = email.use_ssl
            from_email = email.from_email
            

            connection = get_connection(host=email_server, port=email_port, username=email_username,
                                        password=email_password, use_tls=email_ssl)
            subject = kwargs['subject']
            plain_message = kwargs['plain_message']
            html_message = kwargs.get('html_message', None)
            to= kwargs['to']
            cc = kwargs.get('cc', None)
            bcc = kwargs.get('bcc', None)
            email = EmailMultiAlternatives(subject=subject, body=plain_message, from_email=from_email,
                                    to=to,cc=cc,connection=connection, headers={'Message-ID': 'foo'})
            if 'html_message' in kwargs:
                email.attach_alternative(html_message, "text/html")
            if 'file_path' in kwargs and 'mimetype' in kwargs:
                email.attach_file(path=kwargs['file_path'], mimetype=kwargs['mimetype'])
            email.send()

            return 'success'
        else:
            raise Exception('Email function is disabled by admin')