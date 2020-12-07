
from dateutil import parser
from django.conf import settings
from django.shortcuts import render, reverse
from .constants import PAPER_STATUS
from koscientific.emails import KosEmail
from koscientific.models import EmailMembershipAduit, Evaluator, EvaluatorEmailAduit, FreePaper, InstructionCourse, MemberShip, OneTimeLink, Video
import datetime
import logging
logger = logging.getLogger(__name__)
from django.utils import timezone

import string
import random
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
                   
                   
def all_paper_incomplete():
        """
        Run every 3 days and send notification mail who incompleted the paper 
        """
        logger.info("corn job started time is = %s", datetime.datetime.now())
        
        try:
            for free_paper in FreePaper.objects.filter(status__iexact=PAPER_STATUS['DRAFT']):
                logger.info(free_paper.created_by.email)
                if free_paper.created_by.is_active and not free_paper.created_by.email == "	admin@gmail.com":
                    kwargs = {
                        "paper_id": free_paper.pk,
                    }
                    
                    paper_link = reverse("koscientific:edit_free_paper",  kwargs=kwargs)
                    full_link = "{}{}".format(settings.DOMAIN_NAME, paper_link)

                    mail_dict = {
                                'subject' : 'Free paper {} is in draft'.format(free_paper.title),
                                'plain_message' : "Hi. your free paper in draft state please click here {} to complete".format(full_link) ,
                                'recipient_list' : '{}'.format(free_paper.created_by.email),
                                }
                    KosEmail.send_mail(**mail_dict)

        except Exception as e:
            logger.info("corn job unable to send  free paper = %s", e)
            
        try:
            for video_paper in Video.objects.filter(status__iexact=PAPER_STATUS['DRAFT']):
                if video_paper.created_by.is_active and not video_paper.created_by.email == "admin@gmail.com":
                    logger.info(video_paper.created_by.email)
                    kwargs = {
                        "paper_id": video_paper.pk,
                    }
                    
                    paper_link = reverse("koscientific:edit_video",  kwargs=kwargs)
                    full_link = "{}{}".format(settings.DOMAIN_NAME, paper_link)

                    mail_dict = {
                                'subject' : 'Free paper {} is in draft'.format(video_paper.title),
                                'plain_message' : "Hi. your video paper in draft state please click here {} to complete".format(full_link) ,
                                'recipient_list' : '{}'.format(video_paper.created_by.email),
                                }
                    KosEmail.send_mail(**mail_dict)

        except Exception as e:
            logger.info("corn job unable to send video paper = %s", e)
            
        
        try:
            for ic_paper in InstructionCourse.objects.filter(status__iexact=PAPER_STATUS['DRAFT']):          
                if ic_paper.created_by.is_active and not ic_paper.created_by.email == "admin@gmail.com":
                    logger.info(ic_paper.created_by.email)
                    kwargs = {
                        "paper_id": ic_paper.pk,
                    }
                    
                    paper_link = reverse("koscientific:edit_instruction_course",  kwargs=kwargs)
                    full_link = "{}{}".format(settings.DOMAIN_NAME, paper_link)

                    mail_dict = {
                                'subject' : 'Free paper {} is in draft'.format(ic_paper.title),
                                'plain_message' : "Hi. your ic paper in draft state please click here {} to complete".format(full_link) ,
                                'recipient_list' : '{}'.format(ic_paper.created_by.email),
                                }
                    KosEmail.send_mail(**mail_dict)

        except Exception as e:
            logger.info("corn job unable to send ic paper = %s", e)
            
        logger.info("corn job stoped time is = %s", datetime.datetime.now())
            

def tigger_membership_incomplete_mail(name, membership, mail_dict):
    """Helper mail function"""
    KosEmail.send_mail(**mail_dict)
    email_membership_audit = EmailMembershipAduit()
    email_membership_audit.membership = membership
    email_membership_audit.name = name
    email_membership_audit.mem_status = EmailMembershipAduit.MEMBERSHIP_INCOMPLETE
    email_membership_audit.save()
                            
                            
def application_form_incomplete():
        """ 
        Run every 1 days and send notification mail who incompleted the membership 
        """
        logger.info("corn job started time membership incomplete mail is = %s", datetime.datetime.now())

        try:
            for membership in MemberShip.objects.filter(status__iexact=PAPER_STATUS['DRAFT']):          
                if membership.user.is_active:
                    logger.info(membership.user.email)
                    form_link = reverse("koscientific:application_form")
                    full_link = "{}{}".format(settings.DOMAIN_NAME, form_link)

                    mail_dict = {
                                'subject' : 'Complete your membership details',
                                'plain_message' : "Hi. your membership form in draft state please click here {} to complete".format(full_link) ,
                                'recipient_list' : '{}'.format(membership.user.email),
                    }
                    mail_count = membership.email_membership_aduits.filter(mem_status=EmailMembershipAduit.MEMBERSHIP_INCOMPLETE).count()
                    logger.info('mail count', mail_count)
                    
                    if mail_count > 0:
                        first_mail = membership.email_membership_aduits.filter(mem_status=EmailMembershipAduit.MEMBERSHIP_INCOMPLETE).order_by('created_at').first()
                        td = timezone.now() - first_mail.created_at
                        days, hours, minutes = td.days, td.seconds // 3600, td.seconds % 3600 / 60.0
                        logger.info(days, hours, minutes)

                        if mail_count == 1 and days >= 3:
                            # that 3th day
                            logger.info('3rd day day mail')
                            tigger_membership_incomplete_mail('3rd day mail sending', membership, mail_dict)
                        elif mail_count == 2 and days >= 7:
                            # that 7th day
                            logger.info('7th day day mail')
                            tigger_membership_incomplete_mail('7th day mail sending', membership, mail_dict)
                    else:
                        # that 0th day
                        logger.info('first day mail')
                        tigger_membership_incomplete_mail('1st day mail sending', membership, mail_dict)

        except Exception as e:
            logger.info("corn job unable to send membership incomplete mail = %s", e)
            
        logger.info("corn job stoped time is = %s", datetime.datetime.now())
        logger.info("==========================================================")
            
    
def evaluator_reminder():
    """ 
    run every 1 days and send notification mail reminder on 3, 7th day 
    for evaluator mail status no answer
    """
    logger.info("corn job started time evaluator_reminder is = %s", datetime.datetime.now())

    try:
        #  active evaluators only
        for evaluator in Evaluator.objects.filter(mail_status=Evaluator.NO_ANSWER):         
            
            mail_count = evaluator.evaluator_email_audits.all().count()
            logger.info('mail count', mail_count)
            
            if mail_count > 0:
                first_mail = evaluator.evaluator_email_audits.all().order_by('created_at').first()
                td = timezone.now() - first_mail.created_at
                days, hours, minutes = td.days, td.seconds // 3600, td.seconds % 3600 / 60.0
                logger.info(days, hours, minutes)

                if mail_count == 1 and days >= 3:
                    # that 3th day
                    logger.info('3rd day day mail')
                    tigger_reminder_invite_mail('3rd day mail sending', evaluator)
                elif mail_count == 2 and days >= 7:
                    # that 7th day
                    logger.info('7th day day mail')
                    tigger_reminder_invite_mail('7th day mail sending', evaluator)
                else:
                    # no more mail
                    logger.info('no more mail')

    except Exception as e:
        logger.info("corn job unable to send evaluator_reminder mail = %s", e)
        
    logger.info("corn job evaluator_reminder stoped time is = %s", datetime.datetime.now())
    logger.info("==========================================================")
            
    
def tigger_reminder_invite_mail(message, evaluator):
    for email_aduit in evaluator.evaluator_email_audits.all():
        # delete unused link
        if email_aduit.one_time_link:
            logger.info('deleting token', email_aduit.one_time_link.token)
            OneTimeLink.objects.filter(token=email_aduit.one_time_link.token).delete()
    logger.info('creating link')
    oneTimeLink = OneTimeLink()
    oneTimeLink.name = "evaluator invite reminder"
    oneTimeLink.token = id_generator(50)
    oneTimeLink.save()

    kwargs = {
        "uidb64": urlsafe_base64_encode(force_bytes(evaluator.membership.user.pk)),
        "evaluator_id": urlsafe_base64_encode(force_bytes(evaluator.pk)),
        "token": oneTimeLink.token,
        "opinion": 'accept'
    }

    confirm_link = reverse("koscientific:confirm_evaluator", kwargs=kwargs)
    confirm_url = "{}{}".format(settings.DOMAIN_NAME, confirm_link)
    
    kwargs['opinion'] = 'reject'
    reject_link = reverse("koscientific:confirm_evaluator",  kwargs=kwargs)
    reject_url = "{}{}".format(settings.DOMAIN_NAME, reject_link)
    
    email_context = {
        'evaluator': evaluator,
        'sections': evaluator.section.all(),
        'accept_url': confirm_url,
        'reject_url' : reject_url
    }
    html_message = render_to_string('emails/evaluator/kos_evaluator_invite.html', email_context)
    plain_message = strip_tags(html_message)
    officials_mails = [settings.INFO_KOS_ONLINE_MAIL, settings.SCIENTIFIC_CHAIRMAN]       
    # send cc mail to member to become evaluator
    subject = "Invitation to become evaluator"
    mail_dict = {
        'subject': subject,
        'plain_message': plain_message,
        'html_message': html_message,
        'to': ['{}'.format(evaluator.membership.user.email)],
        'cc': officials_mails,
    }
    KosEmail.send_multi_alternatives_email(**mail_dict)
    logger.info('reminder mail sent to invite evaluator')
    evaluator_email_aduit = EvaluatorEmailAduit()
    evaluator_email_aduit.evaluator = evaluator
    evaluator_email_aduit.one_time_link = oneTimeLink
    evaluator_email_aduit.save()