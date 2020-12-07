from .constants import PAPER_STATUS
from django.db.models import Max
from django.http import HttpResponse
from django.shortcuts import render, reverse, get_object_or_404, redirect
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.views.generic.detail import DetailView
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from .models import *
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.utils.datastructures import MultiValueDictKeyError
from django.contrib.auth.decorators import login_required
from django.forms import modelformset_factory
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.views.generic.edit import CreateView, UpdateView
from itertools import chain
from django.forms.formsets import formset_factory
import razorpay
from django.utils import timezone
import pandas as pd
import json
from .forms import *
from cities_light.models import City, Country, Region
from django.db.models import Q, Sum, Count
from io import BytesIO
from xhtml2pdf import pisa
import pdfkit
from django.template import loader
from django.template.loader import get_template
from datetime import date, datetime
from num2words import num2words
import requests
from django.contrib.auth.hashers import check_password
from koscientific.sms import *
from django.contrib import messages
from django.contrib.auth.decorators import *
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from koscientific.emails import *
from notification.web_notifications import *
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import Group
from .emails import KosEmail
# import library 
import math, random
import csv
import logging

logger = logging.getLogger(__name__)

def email_base_template(email_body):
    """
    helper for dynamic email template
    """
    base_template_view = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    </head>
    <body>
        {email_body}
    </body>
    </html>
    """.format(email_body=email_body)
    return base_template_view
    
    
@login_required
def mail_testing(request):
    mail_dict = {'subject': 'hi hemanth',
                 'plain_message': "Hi. red with kos",
                 'recipient_list': '{}'.format('harshahemanth007@gmail.com'), }
    KosEmail.send_mail(**mail_dict)
    return render(request, 'main/index.html', {})


def generate_otp():
    # Declare a digits variable   
    # which stores all digits  
    digits = "0123456789"
    OTP = ""

    # length of password can be chaged
    # by changing value in range
    for i in range(4):
        OTP += digits[math.floor(random.random() * 10)]

    return OTP


def generate_random_number(num):
    # Declare a digits variable   
    # which stores all digits  
    digits = "0123456789"
    OTP = ""

    # length of password can be chaged
    # by changing value in range
    for i in range(num):
        OTP += digits[math.floor(random.random() * 10)]

    return OTP


def login_request(request):
    """ login user """
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                if not hasattr(user, 'profile'):
                    profile, is_created = Profile.objects.get_or_create(user=user)
                    if is_created:
                        messages.error(request, "please add mobile number to your account")
                        return render(request, 'accounts/login.html', {'form': form})
                if not user.profile.is_otp_verified:
                    messages.error(request, "please verify mobile number")
                    # send transactional message
                    otp = generate_otp()
                    try:
                        message = smsBody.objects.get(smskey__iexact=SmsForm.COMMON_OTP_MESSAGE)
                        message = message.smscontent.replace('{{otp}}', otp)
                        result, response = send_otp_sms(message, int(user.profile.mobile_number), otp)
                    except Exception as e:
                        messages.info(request, "error while sending OTP {}".format(e))
                        return render(request=request,
                                      template_name="accounts/login.html",
                                      context={"form": form})

                    OTP.objects.create(
                        sms_transaction_id=response['request_id'],
                        user=user,
                        otp=otp,
                    )
                    return HttpResponseRedirect(
                        reverse("koscientific:otp_verify", kwargs={'sms_trans_id': response['request_id']}))
                login(request, user)
                if request.GET.get('next'):
                    return redirect(request.GET.get('next'))
                return HttpResponseRedirect(reverse('koscientific:index'))

            else:
                messages.error(request, "Invalid username or password.")
        else:
            return render(request, 'accounts/login.html', {'form': form})
    form = AuthenticationForm()
    return render(request=request, template_name="accounts/login.html", context={"form": form})


def register(request):
    """ 
    user first time registration
    need to check whether he is invite accepted evaluator 
    and make him active
    """

    if request.method == "POST":
        form = NewUserCreationForm(request.POST)
        if form.is_valid():
            # get mobile number
            mobile_number = form.cleaned_data.get('mobile_number')
            if User.objects.filter(profile__mobile_number=mobile_number).exists():
                list(messages.get_messages(request))
                messages.info(request, "user already registed with this number {}".format(mobile_number))
                return render(request=request,
                              template_name="accounts/register.html",
                              context={"form": form})
            user = form.save()
            
            # send transactional otp message
            otp = generate_otp()
            try:
                message = smsBody.objects.get(smskey__iexact=SmsForm.USER_REGISTRATION_OTP_VERIFICATION)
                message = message.smscontent.replace("{{otp}}", otp)
                message = message.replace("{{username}}", user.username)

                result, response = send_otp_sms(message, int(mobile_number), otp)
            except Exception as e:
                messages.info(request, "error while sending OTP {}".format(e))
                return render(request=request,
                              template_name="accounts/register.html",
                              context={"form": form})

            
            OTP.objects.create(
                sms_transaction_id=response['request_id'],
                user=user,
                otp=otp,
            )
        
            group = Group.objects.get(name__iexact='Registered')
            user.groups.add(group)
            user.roles.add(Role.REGISTERED)
            return HttpResponseRedirect(
                reverse("koscientific:otp_verify", kwargs={'sms_trans_id': response['request_id']}))

        else:
            return render(request=request,
                          template_name="accounts/register.html",
                          context={"form": form})

    form = NewUserCreationForm()
    return render(request=request,
                  template_name="accounts/register.html",
                  context={"form": form})


def verify_otp(request, sms_trans_id):
    """ OTP verification while registring account """

    if request.method == "POST":
        form = OtpForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get('otp')
            if OTP.objects.filter(sms_transaction_id=sms_trans_id, otp=otp).exists():
                messages.info(request, "Your otp has been verified successfully")
                otb_obj = OTP.objects.get(sms_transaction_id=sms_trans_id, otp=otp)
                otb_obj.user.profile.is_otp_verified = True
                otb_obj.user.profile.save()
                otb_obj.delete()
                try:
                    # send user registration sms
                    message = smsBody.objects.get(smskey__iexact=SmsForm.USER_REGISTRATION)
                    result, response = send_sms(message.smscontent, otb_obj.user.profile.mobile_number)
                except Exception as e:
                    logger.info('unable to send sms the account creation successfull to user {}'.format(e))

                try:
                    # send user account successful registration mail
                    mailcontent = Mail.objects.get(name__iexact=MailForm.USER_REGISTRATION)
                    mail_dict = {
                        'subject': mailcontent.email_subject,
                        'plain_message': mailcontent.email_body,
                        'html_message': mailcontent.email_body,
                        'recipient_list': '{}'.format(otb_obj.user.email),
                    }
                    KosEmail.send_mail(**mail_dict)
                except Exception as e:
                    logger.info('unable to send email of account creation successfull to user {}'.format(e))

                login(request, otb_obj.user)
                return HttpResponseRedirect(reverse("koscientific:home"))
            else:
                messages.error(request, "Entered otp is invalid")
                return render(request=request,
                              template_name="accounts/otp_verify.html",
                              context={"form": form})
        else:
            return render(request=request,
                          template_name="accounts/otp_verify.html",
                          context={"form": form})

    form = OtpForm()
    return render(request=request,
                  template_name="accounts/otp_verify.html",
                  context={"form": form})


def verify_otp_with_mobile(request, sms_trans_id):
    """ OTP verification while mobile number change """

    if request.method == "POST":
        form = OtpForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get('otp')
            if OTP.objects.filter(sms_transaction_id=sms_trans_id, otp=otp).exists():
                messages.info(request, "Your otp has been verified and mobile number changed successfully")
                otb_obj = OTP.objects.get(sms_transaction_id=sms_trans_id, otp=otp)
                otb_obj.user.profile.is_otp_verified = True
                otb_obj.user.profile.mobile_number = otb_obj.mobile_number
                otb_obj.user.profile.save()
                otb_obj.delete()
                return HttpResponseRedirect(reverse("koscientific:profile"))
            else:
                messages.error(request, "Entered otp is invalid")
                return render(request=request,
                              template_name="accounts/otp_verify_number_change.html",
                              context={"form": form})
        else:
            return render(request=request,
                          template_name="accounts/otp_verify_number_change.html",
                          context={"form": form})

    form = OtpForm()
    return render(request=request,
                  template_name="accounts/otp_verify_number_change.html",
                  context={"form": form})


def logout_request(request):
    """ logout user """

    logout(request)
    messages.info(request, "Logged out successfully!")
    return redirect("koscientific:main_login")


def forgot_password(request):
    """
    Reset password using email or mobile number in login page
    """
    reset_password_form = ResetPasswordForm(request.POST or None)
    if request.method == 'POST':
        if reset_password_form.is_valid():
            input_text = reset_password_form.cleaned_data.get('input_text')

            if User.objects.filter(email__iexact=input_text).exists():
                user = User.objects.get(email__iexact=input_text)
                try:
                    # send mail
                    otp = generate_otp()
                    mailcontent = Mail.objects.get(name__iexact=MailForm.FORGOT_PASSWORD_OTP_REQUEST)
                    email_body = mailcontent.email_body.replace('{{otp}}', str(otp))
                    mail_dict = {
                        'subject': mailcontent.email_subject,
                        'plain_message': strip_tags(email_base_template(email_body)),
                        'html_message': email_base_template(email_body),
                        'recipient_list': '{}'.format(user.email),
                    }
                    KosEmail.send_mail(**mail_dict)
                    randome_number = generate_random_number(10)
                    EmailOTP.objects.create(
                        email_transaction_id=randome_number,
                        otp=otp,
                        user=user
                    )
                    messages.info(request, "Reset password OTP sent to {} ".format(user.email))
                    return HttpResponseRedirect(reverse("koscientific:main_forgot_password_email_otp_verify",
                                                    kwargs={'email_transaction_id': randome_number}))
                except Exception as e:
                    messages.error(request, 'unable to send email otp user while reset password {}'.format(e))
                    logger.info('unable to send email otp user while reset password {}'.format(e))
                    
            elif User.objects.filter(profile__mobile_number__iexact=input_text).exists():
                user = User.objects.get(profile__mobile_number__iexact=input_text)
                try:
                    # send transactional sms
                    # trigger SMS
                    otp = generate_otp()
                    message = smsBody.objects.get(smskey__iexact=SmsForm.USER_FORGOT_PASSWORD_OTP_REQUEST)
                    message = message.smscontent.replace("{{otp}}", otp)
                    message = message.replace("{{username}}", user.username)
                    result, response = send_otp_sms(message, int(user.profile.mobile_number), otp)
                    OTP.objects.create(
                        sms_transaction_id=response['request_id'],
                        otp=otp,
                        user=user
                    )
                    messages.info(request, "Reset password OTP sent to {} ".format(user.profile.mobile_number))
                    return HttpResponseRedirect(reverse("koscientific:main_forgot_password_otp_verify",
                                                    kwargs={'sms_trans_id': response['request_id']}))
                except Exception as e:
                    messages.error(request, "error while sending change password OTP {}".format(e))
                    return render(request=request,
                                template_name="accounts/forgot_password/reset_password.html.html",
                                context={"form": reset_password_form})
            else:
                messages.error(request, "Entered email/mobile number {} does not match our records".format(input_text))
                return render(request=request,
                              template_name="accounts/forgot_password/forgot_password.html",
                              context={"form": reset_password_form})

    return render(request=request, template_name="accounts/forgot_password/reset_password.html", context={"form": reset_password_form})


def forgot_password_otp_verify(request, sms_trans_id):
    """ Mobile verification for new password and generate new txt id"""

    if request.method == "POST":
        form = OtpForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get('otp')
            if OTP.objects.filter(sms_transaction_id=sms_trans_id, otp=otp).exists():
                otp_obj = OTP.objects.get(sms_transaction_id=sms_trans_id, otp=otp)
                otp_obj.sms_transaction_id = generate_random_number(20)
                otp_obj.is_otp_verified=True
                otp_obj.save()
                messages.info(request, "Your otp has been verified successfully")
                return HttpResponseRedirect(
                    reverse("koscientific:main_new_password", kwargs={'sms_trans_id': otp_obj.sms_transaction_id}))
            messages.error(request, "Entered otp is invalid")
            return render(request=request, template_name="accounts/forgot_password/otp_verify.html",
                          context={"form": form})
    if OTP.objects.filter(sms_transaction_id=sms_trans_id).exists():
        form = OtpForm()
        return render(request=request, template_name="accounts/forgot_password/otp_verify.html", context={"form": form})
    return HttpResponseRedirect(reverse("koscientific:main_login"))


def forgot_password_email_otp_verify(request, email_transaction_id):
    """ Email otp verification for new password and generate new txt id"""

    if request.method == "POST":
        form = OtpForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get('otp')
            if EmailOTP.objects.filter(email_transaction_id=email_transaction_id, otp=otp).exists():
                messages.info(request, "Your otp has been verified successfully")
                otp_obj = EmailOTP.objects.get(email_transaction_id=email_transaction_id, otp=otp)
                otp_obj.email_transaction_id = generate_random_number(20)
                otp_obj.is_otp_verified=True
                otp_obj.save()
                return HttpResponseRedirect(
                    reverse("koscientific:set_new_password_using_email", kwargs={'email_transaction_id': otp_obj.email_transaction_id}))
            messages.error(request, "Entered OTP is invalid")
            return render(request=request, template_name="accounts/forgot_password/email_otp_verify.html",
                          context={"form": form})
    if EmailOTP.objects.filter(email_transaction_id=email_transaction_id).exists():
        form = OtpForm()
        return render(request=request, template_name="accounts/forgot_password/email_otp_verify.html", context={"form": form})
    return HttpResponseRedirect(reverse("koscientific:main_login"))


def new_password(request, sms_trans_id):
    """ requesting new password from the verified user"""
    form = NewPasswordForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            password = form.cleaned_data.get('password1')

            if OTP.objects.filter(sms_transaction_id=sms_trans_id, is_otp_verified=True).exists():
                otp_obj = OTP.objects.get(sms_transaction_id=sms_trans_id)
                user = otp_obj.user
                user.set_password(password)
                user.save()
                messages.success(request, 'Your password successfully changed please login to continue')
                return redirect("koscientific:main_login")
            messages.error(request, "Entered otp is invalid")
            
        return render(request=request, template_name="accounts/forgot_password/new_password.html",
                      context={"form": form})

    if OTP.objects.filter(sms_transaction_id=sms_trans_id, is_otp_verified=True).exists():
        return render(request=request, template_name="accounts/forgot_password/new_password.html",
                      context={"form": form})
    return HttpResponseRedirect(reverse("koscientific:main_login"))


def set_new_password_using_email(request, email_transaction_id):
    """ set_new_password_using_email for the verified user"""
    form = NewPasswordForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            password = form.cleaned_data.get('password1')

            if EmailOTP.objects.filter(email_transaction_id=email_transaction_id, is_otp_verified=True).exists():
                otp_obj = EmailOTP.objects.get(email_transaction_id=email_transaction_id)
                user = otp_obj.user
                user.set_password(password)
                user.save()
                messages.success(request, 'Your password successfully changed please login to continue')
                return redirect("koscientific:main_login")
            messages.error(request, "Entered OTP is invalid")
            
        return render(request=request, template_name="accounts/forgot_password/new_password.html",
                      context={"form": form})

    if EmailOTP.objects.filter(email_transaction_id=email_transaction_id, is_otp_verified=True).exists():
        return render(request=request, template_name="accounts/forgot_password/new_password.html",
                      context={"form": form})
    return HttpResponseRedirect(reverse("koscientific:main_login"))


def resend_otp(request):
    """
    Resend otp using mobile sms
    """
    if request.is_ajax():
        old_sms_trans_id = request.GET.get('old_sms_trans_id', None)
        if OTP.objects.filter(sms_transaction_id=old_sms_trans_id).exists():
            # send transactional message
            otp = generate_otp()
            otp_obj = OTP.objects.get(sms_transaction_id=old_sms_trans_id)
            try:
                message = smsBody.objects.get(smskey__iexact=SmsForm.USER_RESEND_OTP)
                message = message.smscontent.replace("{{otp}}", otp)
                message = message.replace("{{username}}", otp_obj.user.username)
                result, response = send_otp_sms(message, int(otp_obj.user.profile.mobile_number), otp)
            except Exception as e:
                res = {
                    'op': 'error',
                    'message': "error while sending OTP {}".format(e)
                }
                return JsonResponse(res)

            otp_obj.otp = otp
            otp_obj.save()
            res = {
                'op': 'success',
                'message': 'OTP sent'
            }
            return JsonResponse(res)
        else:
            res = {
                'op': 'error',
                'message': 'session time out'
            }
            return JsonResponse(res)


def resend_email_otp(request):
    """
    Send new top to mail 
    """
    if request.is_ajax():
        old_email_trans_id = request.GET.get('old_email_trans_id', None)
        if EmailOTP.objects.filter(email_transaction_id=old_email_trans_id).exists():
            # send transactional message
            otp = generate_otp()
            otp_obj = EmailOTP.objects.get(email_transaction_id=old_email_trans_id)
            try:
                mailcontent = Mail.objects.get(name__iexact=MailForm.RESEND_OTP_REQUEST)
                email_body = mailcontent.email_body.replace('{{otp}}', str(otp))
                email_body = email_body.replace('{{username}}', otp_obj.user.email)
                mail_dict = {
                    'subject': mailcontent.email_subject,
                    'plain_message': strip_tags(email_base_template(email_body)),
                    'html_message': email_base_template(email_body),
                    'recipient_list': '{}'.format(otp_obj.user.email),
                }
                KosEmail.send_mail(**mail_dict)
            except Exception as e:
                res = {
                    'op': 'error',
                    'message': "error while sending email OTP {}".format(e)
                }
                return JsonResponse(res)

            otp_obj.otp = otp
            otp_obj.save()
            res = {
                'op': 'success',
                'message': 'otp sent to email'
            }
            return JsonResponse(res)
        else:
            res = {
                'op': 'error',
                'message': 'session time out'
            }
            return JsonResponse(res)
        

def resend_otp_mobile_change(request):
    """ resend otp for mobile number change"""

    if request.is_ajax():
        old_sms_trans_id = request.GET.get('old_sms_trans_id', None)
        if OTP.objects.filter(sms_transaction_id=old_sms_trans_id).exists():
            # send transactional message
            otp = generate_otp()
            otp_obj = OTP.objects.get(sms_transaction_id=old_sms_trans_id)
            username = otp_obj.user
            try:
                message = smsBody.objects.get(smskey__iexact=SmsForm.USER_RESEND_OTP)
                message = message.smscontent.replace("{{otp}}", otp)
                message = message.replace("{{username}}", username)
                result, response = send_otp_sms(message, int(otp_obj.mobile_number), otp)
            except Exception as e:
                res = {
                    'op': 'error',
                    'message': "error while sending OTP {}".format(e)
                }
                return JsonResponse(res)

            otp_obj.otp = otp
            otp_obj.save()
            res = {
                'op': 'success',
                'message': 'otp sent'
            }
            return JsonResponse(res)
        else:
            res = {
                'op': 'error',
                'message': 'session time out'
            }
            return JsonResponse(res)


@login_required
def dashboard(request):
    """
    This function will decide which users need to view which dashboard
    """
    if Role.ADMIN in request.user.roles.all().values_list('id', flat=True):
        return show_admin_dashboard(request)
        
    elif Role.SCIENTIFIC_ADMIN in request.user.roles.all().values_list('id', flat=True):
        return show_scientific_admin_dashboard(request)
    
    elif Role.EVALUATOR in request.user.roles.all().values_list('id', flat=True):
        return show_evaluator_dashboard(request)
    else:
        membercount = MemberShip.all_objects.filter(is_member=True).count()
        user = request.user
        number = Profile.objects.get(user=request.user)
        context = {}
        context['member_count'] = membercount
        context['first_name'] = user.first_name
        context['last_name'] = user.last_name
        context['mobile_number'] = number.mobile_number
        context['email'] = user.email
        context['profile'] = user.profile
        return render(request, 'dashboard/registered_member.html', context)

def show_admin_dashboard(request):
    ins_count = InstructionCourse.objects.all().count()
    FreePaper_count = FreePaper.objects.all().count()
    Video_count = Video.objects.all().count()
    evaluator = Evaluator.objects.all().count()

    ic_under_evaluation = InstructionCourse.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    fp_under_evaluation = FreePaper.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    poster_under_evaluation = FreePaper.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    video_under_evaluation = FreePaper.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    total_under_evaluated = ic_under_evaluation + fp_under_evaluation + poster_under_evaluation + video_under_evaluation

    ic_under_evaluated = InstructionCourse.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    fp_under_evaluated = FreePaper.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    video_under_evaluated = Video.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    total_evaluated = ic_under_evaluated + fp_under_evaluated + video_under_evaluated
    ic_evaluated = InstructionCourse.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    user = User.objects.all().count()
    total_members_count = MemberShip.all_objects.filter(is_member=True).count()
    free_paper_author_limt, is_created= PaperCoAuthorLimit.objects.get_or_create(paper=PaperCoAuthorLimit.FREE_PAPER)
    video_paper_author_limt, is_created= PaperCoAuthorLimit.objects.get_or_create(paper=PaperCoAuthorLimit.VIDEO_PAPER)
    ic_paper_author_limt, is_created= PaperCoAuthorLimit.objects.get_or_create(paper=PaperCoAuthorLimit.IC_PAPER)
    
    if request.method == "POST" and request.POST.get("free_paper"):
        free_paper_author_form = AuthorLimitForm(request.POST)
        if free_paper_author_form.is_valid():
            free_paper_author_limt.max_limit = free_paper_author_form.cleaned_data['limit']
            free_paper_author_limt.max_non_kos_member_limit = free_paper_author_form.cleaned_data['max_non_kos_member_limit']
            free_paper_author_limt.updated_by = request.user
            free_paper_author_limt.save()
    else:
        free_paper_author_form = AuthorLimitForm(initial={
            'limit': free_paper_author_limt.max_limit,
            'max_non_kos_member_limit': free_paper_author_limt.max_non_kos_member_limit
        })
        
    if request.method == "POST" and request.POST.get("ic_paper"):
        ic_paper_author_form = AuthorIcLimitForm(request.POST)
        if ic_paper_author_form.is_valid():
            ic_paper_author_limt.max_limit = ic_paper_author_form.cleaned_data['limit']
            ic_paper_author_limt.max_non_kos_member_limit = ic_paper_author_form.cleaned_data['max_non_kos_member_limit']
            ic_paper_author_limt.updated_by = request.user
            ic_paper_author_limt.save()
    else:
        ic_paper_author_form = AuthorIcLimitForm(initial={
            'limit': ic_paper_author_limt.max_limit,
            'max_non_kos_member_limit': ic_paper_author_limt.max_non_kos_member_limit
        })
        
    if request.method == "POST" and request.POST.get("video_paper"):
        video_paper_author_form = AuthorLimitForm(request.POST)
        if video_paper_author_form.is_valid():
            video_paper_author_limt.max_limit = video_paper_author_form.cleaned_data['limit']
            video_paper_author_limt.max_non_kos_member_limit = video_paper_author_form.cleaned_data['max_non_kos_member_limit']
            video_paper_author_limt.updated_by = request.user
            video_paper_author_limt.save()
    else:
        video_paper_author_form = AuthorLimitForm(initial={
            'limit': video_paper_author_limt.max_limit,
            'max_non_kos_member_limit': video_paper_author_limt.max_non_kos_member_limit
        })
    
    context = {
        "free_paper_author_form" :free_paper_author_form,
        "video_paper_author_form":video_paper_author_form,
        "ic_paper_author_form": ic_paper_author_form,
        'ins_count': ins_count,
        'FreePaper_count': FreePaper_count,
        'Video_count': Video_count,
        'evaluator': evaluator,
        'total_under_evaluated': total_under_evaluated,
        'total_evaluated': total_evaluated,
        'ic_evaluated': ic_evaluated,
        'user': user,
        'total_members_count': total_members_count,
    }
    return render(request, 'dashboard/dashboard.html', context)
    
def show_scientific_admin_dashboard(request):
    """
    helper function to show dash board for the scientific admin
    """
    ins_count = InstructionCourse.objects.all().count()
    FreePaper_count = FreePaper.objects.all().count()
    Video_count = Video.objects.all().count()
    evaluator = Evaluator.objects.all().count()

    ic_under_evaluation = InstructionCourse.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    fp_under_evaluation = FreePaper.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    poster_under_evaluation = FreePaper.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    video_under_evaluation = FreePaper.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).count()
    total_under_evaluated = ic_under_evaluation + fp_under_evaluation + poster_under_evaluation + video_under_evaluation

    ic_under_evaluated = InstructionCourse.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    fp_under_evaluated = FreePaper.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    video_under_evaluated = Video.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    total_evaluated = ic_under_evaluated + fp_under_evaluated + video_under_evaluated
    ic_evaluated = InstructionCourse.objects.filter(status=PAPER_STATUS['EVALUATED']).count()
    user = User.objects.all().count()
    total_members_count = MemberShip.all_objects.filter(is_member=True).count()
    free_paper_author_limt, is_created= PaperCoAuthorLimit.objects.get_or_create(paper=PaperCoAuthorLimit.FREE_PAPER)
    video_paper_author_limt, is_created= PaperCoAuthorLimit.objects.get_or_create(paper=PaperCoAuthorLimit.VIDEO_PAPER)
    ic_paper_author_limt, is_created= PaperCoAuthorLimit.objects.get_or_create(paper=PaperCoAuthorLimit.IC_PAPER)
    
    if request.method == "POST" and request.POST.get("free_paper"):
        free_paper_author_form = AuthorLimitForm(request.POST)
        if free_paper_author_form.is_valid():
            free_paper_author_limt.max_limit = free_paper_author_form.cleaned_data['limit']
            free_paper_author_limt.max_non_kos_member_limit = free_paper_author_form.cleaned_data['max_non_kos_member_limit']
            free_paper_author_limt.updated_by = request.user
            free_paper_author_limt.save()
    else:
        free_paper_author_form = AuthorLimitForm(initial={
            'limit': free_paper_author_limt.max_limit,
            'max_non_kos_member_limit': free_paper_author_limt.max_non_kos_member_limit
        })
        
    if request.method == "POST" and request.POST.get("ic_paper"):
        ic_paper_author_form = AuthorIcLimitForm(request.POST)
        if ic_paper_author_form.is_valid():
            ic_paper_author_limt.max_limit = ic_paper_author_form.cleaned_data['limit']
            ic_paper_author_limt.max_non_kos_member_limit = ic_paper_author_form.cleaned_data['max_non_kos_member_limit']
            ic_paper_author_limt.updated_by = request.user
            ic_paper_author_limt.save()
    else:
        ic_paper_author_form = AuthorIcLimitForm(initial={
            'limit': ic_paper_author_limt.max_limit,
            'max_non_kos_member_limit': ic_paper_author_limt.max_non_kos_member_limit
        })
        
    if request.method == "POST" and request.POST.get("video_paper"):
        video_paper_author_form = AuthorLimitForm(request.POST)
        if video_paper_author_form.is_valid():
            video_paper_author_limt.max_limit = video_paper_author_form.cleaned_data['limit']
            video_paper_author_limt.max_non_kos_member_limit = video_paper_author_form.cleaned_data['max_non_kos_member_limit']
            video_paper_author_limt.updated_by = request.user
            video_paper_author_limt.save()
    else:
        video_paper_author_form = AuthorLimitForm(initial={
            'limit': video_paper_author_limt.max_limit,
            'max_non_kos_member_limit': video_paper_author_limt.max_non_kos_member_limit
        })
    
    context = {
        "free_paper_author_form" :free_paper_author_form,
        "video_paper_author_form":video_paper_author_form,
        "ic_paper_author_form": ic_paper_author_form,
        'ins_count': ins_count,
        'FreePaper_count': FreePaper_count,
        'Video_count': Video_count,
        'evaluator': evaluator,
        'total_under_evaluated': total_under_evaluated,
        'total_evaluated': total_evaluated,
        'ic_evaluated': ic_evaluated,
        'user': user,
        'total_members_count': total_members_count,
    }
    return render(request, 'dashboard/scientific_admin/scientific_admin_dashboard.html', context)
    
    
def show_evaluator_dashboard(request):
    """helper function for evaluators while showing dashboard"""
    
    if hasattr(request.user, 'membership'):
        assigned_ic_paper = AssignedTo.objects.filter(evulator__membership__user=request.user)
        assigned_free_paper = AssignedFreePaper.objects.filter(evulator__membership__user=request.user)
        assigned_video_paper = AssignedVideo.objects.filter(evaluator__membership__user=request.user)
    else:
        assigned_ic_paper = AssignedTo.objects.filter(evulator__user=request.user)
        assigned_free_paper = AssignedFreePaper.objects.filter(evulator__user=request.user)
        assigned_video_paper = AssignedVideo.objects.filter(evaluator__user=request.user)
    
    ic_paper_under_eval_count = assigned_ic_paper.filter(marks__isnull=True).count()
    free_paper_under_eval_count = assigned_free_paper.filter(marks__isnull=True).count()
    video_paper_under_eval_count = assigned_video_paper.filter(marks__isnull=True).count()
    
    ic_paper_evaluated_count = assigned_ic_paper.filter(marks__isnull=False).count()
    free_paper_evaluated_count = assigned_free_paper.filter(marks__isnull=False).count()
    video_paper_evaluated_count = assigned_video_paper.filter(marks__isnull=False).count()

    context = {
        'ic_paper_under_eval_count': ic_paper_under_eval_count,
        'free_paper_under_eval_count': free_paper_under_eval_count,
        'video_paper_under_eval_count': video_paper_under_eval_count,
        'ic_paper_evaluated_count': ic_paper_evaluated_count,
        'free_paper_evaluated_count': free_paper_evaluated_count,
        'video_paper_evaluated_count': video_paper_evaluated_count,
    }
    return render(request, 'dashboard/evaluators/dashboard.html', context)
    
def Instruction_Course(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN ]):
        instruction_course_list = InstructionCourse.objects.all().order_by('-created_at')

    elif User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        instruction_course_list = InstructionCourse.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).order_by(
            '-created_at')
    else:
        instruction_course_list = InstructionCourse.objects.filter(created_by=request.user).order_by('-created_at')
    context = {
        'instruction_course_list': instruction_course_list,
    }
    count = instruction_course_list.count()
    instruction_course_list = instruction_course_list
    page = request.GET.get('page', 1)
    paginator = Paginator(instruction_course_list, 10)
    try:
        instruction_course_list = paginator.page(page)
    except PageNotAnInteger:
        instruction_course_list = paginator.page(1)
    except EmptyPage:
        instruction_course_list = paginator.page(paginator.num_pages)

    index = instruction_course_list.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['instruction_course_list'] = instruction_course_list
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'instructioncourse/instruction_course.html', context)


def Instruction_Course_Evaluated(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        inst_evaluated = InstructionCourse.objects.filter(status=PAPER_STATUS['EVALUATED']).order_by('-created_at')
        context = {
            'inst_evaluated': inst_evaluated,
        }
        return render(request, 'instructioncourse/inst_evaluated.html', context)


def Instruction_Course_Selected(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        inst_selected = InstructionCourse.objects.filter(status=PAPER_STATUS['SELECTED']).order_by('-created_at')
        context = {
            'inst_selected': inst_selected,
        }
        return render(request, 'instructioncourse/inst_selected.html', context)


def ic_paper_ajax(request):
    """Save ic paper through ajax as draft"""

    if request.method == 'POST':
        user_fp_paper_count = InstructionCourse.objects.filter(created_by=request.user).count()
        if user_fp_paper_count > settings.MAX_IC_PAPER_LIMIT:
            response = {
                'status': False,
                'message': 'Submission paper limit {} exceeded'.format(settings.MAX_IC_PAPER_LIMIT),
            }
            return JsonResponse(response)

        if not request.POST['title']:
            response = {
                'status': True,
                'message': 'at least title to draft',
            }
            return JsonResponse(response)

        if 'paper_id' in request.POST:
            logger.info('member ajax draft saving the ic paper {}'.format(request.POST['paper_id']))
            ic_paper = get_object_or_404(InstructionCourse, pk=request.POST['paper_id'])
        elif 'edit' in request.META['HTTP_REFERER']:
            logger.info('member ajax draft edit saving the ic paper {}'.format(request.META['HTTP_REFERER'].split('/')[-2]))
            ic_paper = get_object_or_404(InstructionCourse, pk=request.META['HTTP_REFERER'].split('/')[-2])
        elif InstructionCourse.objects.filter(created_by=request.user, title__iexact=request.POST['title']).exists():
            response = {
                'status': False,
                'message': 'title already there not saving to draft',
            }
            return JsonResponse(response)
        else:
            ic_paper = InstructionCourse()           
            logger.info('member ajax ic create new the ic paper')

        if 'title' in request.POST:
            ic_paper.title = request.POST['title']
        if 'event' in request.POST:
            ic_paper.event_id = request.POST['event']
        if 'section' in request.POST:
            ic_paper.section_id = request.POST['section']
        if 'Instruction_course_type' in request.POST:
            ic_paper.Instruction_course_type = request.POST['Instruction_course_type']
        if 'resume' in request.POST:
            ic_paper.resume = request.POST['resume']
        if 'synopsis' in request.POST:
            ic_paper.synopsis = request.POST['synopsis']
        if 'non_mem_co_instructor' in request.POST:
            ic_paper.non_mem_co_instructor = request.POST['non_mem_co_instructor']
        ic_paper.save()
        if not ic_paper.unique_id:
            ic_paper.save()
            ic_paper.unique_id = "IC" + str(ic_paper.id)
        ic_paper.created_by = request.user
        if not ic_paper.status:
            ic_paper.status = PAPER_STATUS['DRAFT']
        ic_paper.save()
        response = {
            'status': True,
            'message': 'added to draft',
            'paper_id': ic_paper.id
        }
        return JsonResponse(response)
    else:
        response = {
            'status': False,
            'message': 'get wont support',
        }
        return JsonResponse(response)


@login_required
def create_Instruction_course_paper(request, paper_id=None):
    """
    Free paper Add and Edit by submitted member.
    Validate max paper submiting.
    If paper_id present the edit or add.
    Saved form info.
    Assign paper to next available same section evaluator.
    Send email ans sms to Applicant and evaluator.
    Send webnotification to applicant.
    """

    if request.method == 'POST':
        user_ic_paper_count = InstructionCourse.objects.filter(created_by=request.user).count()
        if user_ic_paper_count > settings.MAX_IC_PAPER_LIMIT:
            messages.error(request, 'Your max submitting instruction course limit {} exceeded'.format(
                settings.MAX_IC_PAPER_LIMIT))
            return HttpResponseRedirect(reverse('koscientific:instruction_course'))
        if 'paper_id' in request.POST:
            logger.info('member draft saving the ic paper {}'.format(request.POST['paper_id']))
            add_inst = get_object_or_404(InstructionCourse, pk=request.POST['paper_id'])
        elif paper_id:
            add_inst = get_object_or_404(InstructionCourse, pk=paper_id)
            logger.info('member edit saving the ic paper {}'.format(paper_id))
            
        else:
            add_inst = InstructionCourse()
            logger.info('member create new saving the ic paper')
            
        if not request.POST.get('title'):
            messages.error(request, "At least title required to save draft")
            return HttpResponseRedirect(reverse('koscientific:instruction_course'))
        add_inst.title = request.POST['title']
        if 'event' in request.POST:
            add_inst.event_id = request.POST['event']
        add_inst.Instruction_course_type = request.POST.get('Instruction_course_type')
        add_inst.section_id = request.POST.get('section', None)
        if request.POST.get('section') and 'final' in request.POST:
            evaluators = Evaluator.objects.filter(section=add_inst.section, status__iexact='active')
            if not evaluators.exists():
                messages.error(request, 'Evaulators is not present for this section')
                return HttpResponseRedirect(reverse('koscientific:instruction_course'))
        add_inst.resume = request.POST.get('resume')
        add_inst.synopsis = request.POST.get('synopsis')
        add_inst.created_by = request.user
        add_inst.save()
        if not add_inst.unique_id:
            add_inst.unique_id = "IC" + str(add_inst.id)
            add_inst.save()
        # final stuff to save
        if 'final' in request.POST:
            if 'chief_instructor_name' in request.POST:
                try:
                    chief_ic_paper = get_object_or_404(ChiefInstructorICPaper, instruction_course=add_inst)
                except Exception:
                    chief_ic_paper = ChiefInstructorICPaper()
                chief_ic_paper.instruction_course = add_inst
                chief_ic_paper.chief_instructor_id = request.POST['chief_instructor_name']
                chief_ic_paper.duration = request.POST['chief_instructor_duration'] if request.POST.get(
                    'chief_instructor_duration') else None
                chief_ic_paper.topic = request.POST.get('chief_instructor_topic', None)
                chief_ic_paper.save()
            co_instructors = []
            CoInstructorICPaper.objects.filter(instruction_course=add_inst).delete()
            extra_co_authors = [extra_co_authors for extra_co_authors in request.POST.getlist('co_instructor_name') if extra_co_authors]

            for co_instructor, duration, topic in zip(extra_co_authors,
                                                    request.POST.getlist('co_instructor_duration'),
                                                    request.POST.getlist('co_instructor_topic')):
                co_instructors.append(CoInstructorICPaper(instruction_course=add_inst,
                                                        co_instructor_id=co_instructor,
                                                        duration=duration if duration else None,
                                                        topic=topic))

            CoInstructorICPaper.objects.bulk_create(co_instructors)

            co_non_member_instructors = []
            for first_name, last_name, email, mobile_number, qualification in zip(
                    request.POST.getlist('non_mem_co_instructor_first_name'),
                    request.POST.getlist('non_mem_co_instructor_last_name'),
                    request.POST.getlist('non_mem_co_instructor_email'),
                    request.POST.getlist('non_mem_co_instructor_mobile_number'),
                    request.POST.getlist('non_mem_co_instructor_qualification')):
                if first_name and last_name and email and mobile_number and qualification:
                    if not Profile.objects.filter(mobile_number=mobile_number).exists() and not User.objects.filter(email=email).exists():
            
                        co_non_member_instructors.append(NonMemberICPaperInstructor(instruction_course=add_inst,
                                                                                first_name=first_name,
                                                                                last_name=last_name,
                                                                                email=email,
                                                                                mobile_number=mobile_number,
                                                                                qualification=qualification))

            NonMemberICPaperInstructor.objects.bulk_create(co_non_member_instructors)

        if 'draft' in request.POST:
            add_inst.status = PAPER_STATUS['DRAFT']
            add_inst.save()
            messages.warning(request, 'Instruction course saved to darft')
            return HttpResponseRedirect(reverse('koscientific:instruction_course'))
        elif 'final' in request.POST:
            add_inst.status = PAPER_STATUS['UNDER_EVALUATION']
            add_inst.ref_id = generate_random_number(10)
            add_inst.save()
            for co_instructor in add_inst.co_instructor_ic_paper.all():
                invited_session = InvitedSession()
                invited_session.abstract_title = add_inst.title
                invited_session.submission_type = add_inst.Instruction_course_type
                invited_session.summary = add_inst.synopsis
                invited_session.send_to = co_instructor.co_instructor.user
                invited_session.created_by = request.user
                invited_session.session_date = add_inst.created_at
                invited_session.is_ic_paper = True
                invited_session.paper_id = add_inst.unique_id
                invited_session.save()

        ####################################################
        ######Assign paper to next section evaluator########
        ####################################################
        # ========================================
        # check specific section evaluators available 
        # get last section evaluator from AssignedTo 
        # if no evaluator found then asssign to first 3 section evaluators order by created
        # else found, get last eval from AssignedTo of the section and next 3 eval from section evaluators order by created
        # repeat the procedure
        # =========================================
        logger.info('===============start ic paper evaluator assignment=================')
        if Evaluator.objects.filter(section=add_inst.section_id, status__iexact='active').exists():
            # get last section evaluator from AssignedTo 
            assigned_last_section_eval = AssignedTo.objects.filter(section_id=add_inst.section_id).order_by(
                'created_at').last()
            if assigned_last_section_eval is None:
                next_section_evaluators = Evaluator.objects.filter(section=add_inst.section_id,
                                                                   status__iexact='active')[0:3]
                for fresh_section_evalutor in next_section_evaluators:
                    assign = AssignedTo()
                    assign.ic_id = add_inst.id
                    assign.evulator = fresh_section_evalutor
                    assign.section_id = add_inst.section_id
                    assign.status = PAPER_STATUS['ASSIGNED']
                    assign.save()
                    add_inst.status = PAPER_STATUS['UNDER_EVALUATION']
                    add_inst.save()
            else:
                last_assign_eval = assigned_last_section_eval.evulator
                logger.info('last section evaluator  id {} in the AssignedTo table'.format(last_assign_eval.id))
                section_evals = Evaluator.objects.filter(section=add_inst.section_id,
                                                         status__iexact='active').order_by('created_at')
                logger.info('total section evaluator top to bottom count {}'.format(section_evals.count()))
                remaining_un_selected_section_evaluators_count = section_evals.filter(id__gt=last_assign_eval.id).count()
                logger.info('remaining evaluators count who paper not assigned  {}'.format(remaining_un_selected_section_evaluators_count))
                
                if remaining_un_selected_section_evaluators_count >= 3:
                    next_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)[0:3]
                elif remaining_un_selected_section_evaluators_count == 2:
                    last_two_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                    fist_section_evaluators = section_evals[0:1]
                    next_section_evaluators = list(chain(last_two_section_evaluators, fist_section_evaluators))
                elif remaining_un_selected_section_evaluators_count == 1:
                    logger.info("one evaluator left to assign ic paper")
                    if section_evals.count() > 2:
                        # more user than him
                        last_one_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                        fist_two_section_evaluators = section_evals[0:2]
                        next_section_evaluators = list(chain(last_one_section_evaluators, fist_two_section_evaluators))
                    elif section_evals.count() > 1:
                        # more user than him
                        last_one_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                        fist_section_evaluators = section_evals[0:1]
                        next_section_evaluators = list(chain(last_one_section_evaluators, fist_section_evaluators))
                    else:
                        # no more user except him
                        next_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                elif remaining_un_selected_section_evaluators_count == 0:
                    logger.info('no more un-selected evaluators {}'.format(remaining_un_selected_section_evaluators_count))
                    # no more user except him
                    next_section_evaluators = section_evals[0:3]
                    logger.info('so again consider from old to new 3 evaluator {}'.format(next_section_evaluators))
                
                # Assign ic paper to next section evaluators
                for section_evaluator in next_section_evaluators:
                    assign = AssignedTo()
                    assign.ic_id = add_inst.id
                    assign.evulator = section_evaluator
                    assign.section_id = add_inst.section_id
                    assign.status = PAPER_STATUS['ASSIGNED']
                    assign.save()
                add_inst.status = PAPER_STATUS['UNDER_EVALUATION']
                add_inst.save()
        else:
            messages.warning(request, 'section {} evaluator not found'.format(add_inst.section))
        logger.info('===============end of ic paper evaluator assignment=================')
        try:
            # send sms to ic paper applicant
            message = smsBody.objects.get(smskey__iexact=SmsForm.IC_PAPER_SUBMISSION_TO_APPLICANT)
            message = message.smscontent.replace('{{paper_id}}', add_inst.unique_id)
            result, response = send_sms(message, request.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send sms to ic paper applicant {}'.format(e))

        try:
            # send mail ic paper applicant
            mailcontent = Mail.objects.get(name__iexact=MailForm.IC_PAPER_SUBMISSION_TO_APPLICANT)
            email_body = mailcontent.email_body.replace('{{paper_id}}', add_inst.unique_id)
            mail_dict = {
                'subject': mailcontent.email_subject,
                'plain_message': strip_tags(email_base_template(email_body)),
                'html_message': email_base_template(email_body),
                'recipient_list': '{}'.format(request.user.email)
            }
            KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send mail user who submitted the paper {}'.format(e))
            
        try:
            # send sms confirmation to evaluator
            message = smsBody.objects.get(smskey__iexact=SmsForm.IC_PAPER_SUBMISSION_TO_EVALUATOR)
            message = message.smscontent.replace('{{private_paper_id}}', add_inst.ref_id)
            mobile_numbers = []
            for evaluator in next_section_evaluators:
                try:
                    # get member mobile number
                    mobile_numbers.append(evaluator.membership.user.profile.mobile_number)
                except Exception as e:
                    try:
                        # mobile number which was saved during evaluator invite
                        mobile_numbers.append(evaluator.invite.mobile_number)
                    except Exception as e:
                        pass
            result, response = send_mass_sms(message, mobile_numbers)
        except Exception as e:
            logger.info('unable to send the submitted the instruction paper sms to evaluator {}'.format(e))
            
        try:
            # send ic paper mail to evaluator
            for evaluator in next_section_evaluators:
                try:
                    # get member mobile number
                    email = evaluator.membership.user.email
                    evaluator_full_name = "{} {}".format(evaluator.membership.user.first_name, evaluator.membership.user.last_name)
                except Exception as e:
                    try:
                        # mobile number which was saved during evaluator invite
                        email = evaluator.invite.email
                        evaluator_full_name = "{} {}".format(evaluator.invite.first_name, evaluator.invite.first_name)
                    except Exception as e:
                        pass
                    
                mailcontent = Mail.objects.get(name__iexact=MailForm.IC_PAPER_SUBMISSION_TO_EVALUATOR)
                email_body = mailcontent.email_body.replace('{{evaluator_full_name}}', evaluator_full_name)
                email_body = email_body.replace('{{private_paper_id}}', add_inst.ref_id)
                
                mail_dict = {
                    'subject': mailcontent.email_subject,
                    'plain_message': strip_tags(email_base_template(email_body)),
                    'html_message': email_base_template(email_body),
                    'recipient_list': '{}'.format(email)
                }
                KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send ic paper mail to evaluator {}'.format(e))
        
        try:
            # notification sending to applicant 
            WebNotification(request.user).send_only_notification_to_user([request.user],
                                                                         'instruction course successfully submitted')
            # to evaluator
            message = 'instruction course paper assigned'
            WebNotification(request.user).send_only_notification_to_user(
                [next_section_evaluator.membership.user for next_section_evaluator in next_section_evaluators if next_section_evaluator.membership], message)
        except Exception as e:
            logger.info('unable to send socket notification to evaluator and user {}'.format(e))
            
        try:
            # send sms to co author
            message = smsBody.objects.get(smskey__iexact=SmsForm.IC_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            for co_author in add_inst.co_instructor_ic_paper.all():
                result, response = send_sms(message, co_author.co_instructor.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the ic paper sms to co author {}'.format(e))
            
        try:
            # send sms to non kos co-author
            message = smsBody.objects.get(smskey__iexact=SmsForm.IC_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            for non_kos_member in add_inst.non_members_ic_paper_instructors.all():
                result, response = send_sms(message, non_kos_member.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the ic paper sms to non kos co-author {}'.format(e))
            
        messages.success(request, 'Instruction course submitted successfully!')
        return HttpResponseRedirect(reverse('koscientific:instruction_course'))
    
    if paper_id:
        ic_paper = get_object_or_404(InstructionCourse, pk=paper_id)
    else:
        ic_paper = None

    section_list = Section.objects.filter(status=PAPER_STATUS['ACTIVE'])
    # pure members
    member_name_list = MemberShip.objects.filter(user__roles__in=[Role.MEMBER])
    # status_list = Status.objects.all()
    context = {
        'ic_paper': ic_paper,
        'section_list': section_list,
        'member_name_list': member_name_list,
        'non_member_qualifications': NonMemberICPaperInstructor.QUALIFICATION_CHOICES,
        'events': Event.objects.exclude(status=Event.INACTIVE),
        'auto_save_in': settings.AUTO_SAVE_IN,
        'ic_paper_max_non_member': PaperCoAuthorLimit.objects.get(paper=PaperCoAuthorLimit.IC_PAPER).max_non_kos_member_limit,
        'ic_paper_max_member': PaperCoAuthorLimit.objects.get(paper=PaperCoAuthorLimit.IC_PAPER).max_limit,
    }
    user_ic_paper_count = InstructionCourse.objects.filter(created_by=request.user).count()
    if user_ic_paper_count > settings.MAX_IC_PAPER_LIMIT:
        messages.warning(request,
                         'Your max submitting instruction course {} limit exceeded'.format(settings.MAX_IC_PAPER_LIMIT))
    return render(request, 'instructioncourse/add_instruction_course.html', context)


def member_main_details(request):
    """
    get some member main details using ajax
    """
    logger.info('getting members main details')
    if request.method == 'GET':
        try:
            member_data = MemberShip.objects.get(id=request.GET['id'])
            email = [member_data.user.email]

            context = {
                'email': member_data.user.email,
                'mobile': member_data.user.profile.mobile_number if hasattr(member_data.user,
                                                                            'profile') else member_data.mobile,
                'kos_no': member_data.kos_no,
                'membership_pk':member_data.id,
            }
            return JsonResponse(context, status=200)
        except Exception as e:
            context = {
                'error': str(e)
            }
            logger.info(str(e))
            return JsonResponse(context, status=500)


def ViewInstructionCourse(request, view_instr_id):
    try:
        instruction_course_view = InstructionCourse.objects.get(id=view_instr_id)
    except Exception as e:
        instruction_course_view = InstructionCourse.objects.get(unique_id=view_instr_id)
    try:
        total_marks = instruction_course_view.assignedto_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get(
            'sum_total')
        
    except Exception as e:
        total_marks = None
        
    # check paper fully evaluated
    is_paper_evaluated = True
    section_rank_dict = None
    over_all_rank_dict = None
    total_marks_in_percentage = None
    total_evaluator = None
    if not instruction_course_view.assignedto_set.all():
        is_paper_evaluated = False
        
    # check paper fully evaluated
    for assigned_to in instruction_course_view.assignedto_set.all():
        if assigned_to.marks == None:
            is_paper_evaluated = False
            break
    
    if is_paper_evaluated:
        total_evaluator = instruction_course_view.assignedto_set.count()
        total_marks_in_percentage = total_marks/(total_evaluator*50)
        total_marks_in_percentage = total_marks_in_percentage*100
        paper_section_wise_total_marks = []
        
        # Evaluated free paper of this section 
        free_paper_qs = FreePaper.objects.filter(section=instruction_course_view.section).exclude(status__iexact='draft').select_related().exclude(assignedfreepaper__marks__isnull=True).distinct()
        for free_paper in free_paper_qs:
            paper_marks = free_paper.assignedfreepaper_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = free_paper.assignedfreepaper_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # Evaluated ic paper of this section
        ic_paper_qs = InstructionCourse.objects.filter(section=instruction_course_view.section).exclude(status__iexact='draft').select_related().exclude(assignedto__marks__isnull=True).distinct()
        for ic_paper in ic_paper_qs:
            paper_marks = ic_paper.assignedto_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = ic_paper.assignedto_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # Evaluated video paper of this section 
        video_paper_qs = Video.objects.filter(section=instruction_course_view.section).exclude(status__iexact='draft').select_related().exclude(assignedvideo__marks__isnull=True).distinct()
        for video_paper in video_paper_qs:
            paper_marks = video_paper.assignedvideo_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = video_paper.assignedvideo_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # remove none value
        if paper_section_wise_total_marks:
            paper_section_wise_total_marks = [x for x in paper_section_wise_total_marks if x is not None]
            paper_section_wise_total_marks.sort(reverse=True)
            section_rank = paper_section_wise_total_marks.index(total_marks_in_percentage)
            section_rank = section_rank+1
        else:
            section_rank =None
            
        logger.info('paper_section_wise_total_marks in % {}'.format(paper_section_wise_total_marks))
        logger.info('total marks % {}'.format(total_marks_in_percentage))
        
        # over all rank
        paper_over_all_total_marks = []
        # Evaluated free paper 
        free_paper_qs = FreePaper.objects.exclude(status__iexact='draft').select_related().exclude(assignedfreepaper__marks__isnull=True).distinct()
        for free_paper in free_paper_qs:
            paper_marks = free_paper.assignedfreepaper_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = free_paper.assignedfreepaper_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # Evaluated ic paper
        ic_paper_qs = InstructionCourse.objects.exclude(status__iexact='draft').select_related().exclude(assignedto__marks__isnull=True).distinct()
        for ic_paper in ic_paper_qs:
            paper_marks = ic_paper.assignedto_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = ic_paper.assignedto_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # Evaluated video paper
        video_paper_qs = Video.objects.exclude(status__iexact='draft').select_related().exclude(assignedvideo__marks__isnull=True).distinct()
        for video_paper in video_paper_qs:
            paper_marks = video_paper.assignedvideo_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = video_paper.assignedvideo_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # remove none value
        if paper_over_all_total_marks:
            paper_over_all_total_marks = [x for x in paper_over_all_total_marks if x is not None]
            paper_over_all_total_marks.sort(reverse=True)
            over_all_rank = paper_over_all_total_marks.index(total_marks_in_percentage)
            over_all_rank = over_all_rank+1
        else:
            over_all_rank = None
            
        logger.info('paper_over_all_total_marks in % {}'.format(paper_over_all_total_marks))
        logger.info('total marks % {}'.format(total_marks_in_percentage))
        logger.info('over_all_rank {}'.format(over_all_rank))
        
        section_rank_dict = {
            'rank' : section_rank,
            'out_of': len(paper_section_wise_total_marks)
        }
        over_all_rank_dict = {
            'rank' : over_all_rank,
            'out_of': len(paper_over_all_total_marks)
        }
    context = {
        'instruction_course_view': instruction_course_view,
        'total_obtained_marks': total_marks,
        'total_evaluator': total_evaluator*50 if total_evaluator else None,
        'total_marks_in_percentage': total_marks_in_percentage,
        'section_rank': section_rank_dict if section_rank_dict else None,
        'over_all_rank': over_all_rank_dict if over_all_rank_dict else None
    }
    return render(request, 'instructioncourse/view_instruction_course.html', context)


def Free_paper(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN ]):
        free_paper_list = FreePaper.objects.all().order_by('-created_at')

    elif User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        free_paper_list = FreePaper.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).order_by('-created_at')
    else:
        free_paper_list = FreePaper.objects.filter(created_by=request.user).order_by('-created_at')
    context = {
        'free_paper_list': free_paper_list,
    }
    count = free_paper_list.count()
    free_paper_list = free_paper_list
    page = request.GET.get('page', 1)
    paginator = Paginator(free_paper_list, 10)
    try:
        free_paper_list = paginator.page(page)
    except PageNotAnInteger:
        free_paper_list = paginator.page(1)
    except EmptyPage:
        free_paper_list = paginator.page(paginator.num_pages)

    index = free_paper_list.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['free_paper_list'] = free_paper_list
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'freepaper/free_paper.html', context)


def Free_paper_Evaluated(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        fp_evaluated = FreePaper.objects.filter(status=PAPER_STATUS['EVALUATED']).order_by('-created_at')
        context = {
            'fp_evaluated': fp_evaluated,
        }
        return render(request, 'freepaper/freepaper_evaluated.html', context)


def Free_paper_Selected(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        fp_Selected = FreePaper.objects.filter(status=PAPER_STATUS['SELECTED']).order_by('-created_at')
        context = {
            'fp_Selected': fp_Selected,
        }
        return render(request, 'freepaper/freepaper_Selected.html', context)


def free_paper_ajax(request):
    ''' save free paper as auto save() '''
    if request.method == 'POST':
        user_fp_paper_count = FreePaper.objects.filter(created_by=request.user).count()
        if user_fp_paper_count > settings.MAX_FREE_PAPER_LIMIT:
            response = {
                'status': False,
                'message': 'Submission paper limit {} exceeded'.format(settings.MAX_FREE_PAPER_LIMIT),
            }
            return JsonResponse(response)

        if not request.POST['title']:
            response = {
                'status': True,
                'message': 'at least title required to draft',
            }
            return JsonResponse(response)
        if 'paper_id' in request.POST:
            logger.info('member ajax draft saving the free paper {}'.format(request.POST['paper_id']))
            free_paper = get_object_or_404(FreePaper, pk=request.POST['paper_id'])
        elif 'edit' in request.META['HTTP_REFERER']:
            logger.info('member ajax edit saving the free paper {}'.format(request.META['HTTP_REFERER'].split('/')[-2]))  
            free_paper = get_object_or_404(FreePaper, pk=request.META['HTTP_REFERER'].split('/')[-2])
        elif FreePaper.objects.filter(created_by=request.user, title__iexact=request.POST['title']).exists():
            response = {
                'status': False,
                'message': 'title already there not saving to draft',
            }
            return JsonResponse(response)
        else:
            free_paper = FreePaper()
            logger.info('member ajax creating new the ajax free paper')

        if 'title' in request.POST:
            free_paper.title = request.POST['title']
        if 'event' in request.POST:
            free_paper.event_id = request.POST['event']
        if 'section' in request.POST:
            free_paper.section_id = request.POST['section']
        if 'type_of_presentation' in request.POST:
            free_paper.type_of_presentation = request.POST['type_of_presentation']
        if 'synopsis' in request.POST:
            free_paper.synopsis = request.POST['synopsis']
        if not free_paper.unique_id:
            free_paper.save()
            free_paper.unique_id = "FP" + str(free_paper.id)
        free_paper.created_by = request.user
        if not free_paper.status:
            free_paper.status = PAPER_STATUS['DRAFT']
        free_paper.save()
        response = {
            'status': True,
            'message': 'added to draft',
            'paper_id': free_paper.id
        }
        return JsonResponse(response)
    else:
        response = {
            'status': False,
            'message': 'get wont support',
        }
        return JsonResponse(response)


@login_required
def free_paper_add(request, paper_id=None):
    """
    Free paper Add and Edit by submitted member.
    Validate max paper submiting.
    If paper_id present the edit or add.
    Saved form info.
    Assign paper to next available same section evaluator.
    Send email ans sms to Applicant and evaluator.
    Send webnotification to applicant.
    """
    if request.method == 'POST':
        user_fp_paper_count = FreePaper.objects.filter(created_by=request.user).count()
        if user_fp_paper_count > settings.MAX_FREE_PAPER_LIMIT:
            messages.error(request, 'Your max submitting free paper course {} limit exceeded'.format(
                settings.MAX_FREE_PAPER_LIMIT))
            return HttpResponseRedirect(reverse('koscientific:free_paper'))

        if 'paper_id' in request.POST:
            logger.info('member draft saving the free paper {}'.format(request.POST['paper_id']))
            add_paper = get_object_or_404(FreePaper, pk=request.POST['paper_id'])
        elif paper_id:
            logger.info('member edit saving the free paper {}'.format(paper_id))
            add_paper = get_object_or_404(FreePaper, pk=paper_id)
        else:
            logger.info('creating new free paper')
            add_paper = FreePaper()
        if not request.POST.get('title'):
            messages.error(request, "At least title required to save draft")
            return HttpResponseRedirect(reverse('koscientific:free_paper'))
        add_paper.title = request.POST.get('title')
        add_paper.section_id = request.POST.get('section')
        add_paper.event_id = request.POST.get('event')
        add_paper.type_of_presentation = request.POST.get('type_of_presentation')
        if request.POST.get('section') and 'final' in request.POST:
            evaluators = Evaluator.objects.filter(section=add_paper.section, status__iexact='active')
            if not evaluators.exists():
                messages.error(request, 'Evaluator is not present for this section')
                return HttpResponseRedirect(reverse('koscientific:free_paper'))
        add_paper.synopsis = request.POST.get('synopsis')
        add_paper.chief_author_id = request.POST.get('chief_author_name')
        add_paper.presenting_auther_name_id = request.POST.get('presenting_auther_name')
        add_paper.created_by = request.user
        add_paper.save()
        if 'co_author_membership_id' in request.POST:
            extra_co_authors = [extra_co_authors for extra_co_authors in request.POST.getlist('co_author_membership_id') if extra_co_authors]
            add_paper.coauther_name.set([get_object_or_404(MemberShip, pk=co_ins) for co_ins in extra_co_authors])
        if not add_paper.unique_id:
            add_paper.unique_id = "FP" + str(add_paper.id)
        add_paper.save()
        if 'final' in request.POST:
            co_non_member_instructors = []
            for first_name, last_name, email, mobile_number, qualification in zip(
                    request.POST.getlist('non_mem_co_instructor_first_name'),
                    request.POST.getlist('non_mem_co_instructor_last_name'),
                    request.POST.getlist('non_mem_co_instructor_email'),
                    request.POST.getlist('non_mem_co_instructor_mobile_number'),
                    request.POST.getlist('non_mem_co_instructor_qualification')):
                if first_name and last_name and email and mobile_number and qualification:
                    if not Profile.objects.filter(mobile_number=mobile_number).exists() and not User.objects.filter(email=email).exists():
                    
                        co_non_member_instructors.append(NonMemberFreePaperInstructor(free_paper=add_paper,
                                                                            first_name=first_name,
                                                                            last_name=last_name,
                                                                            email=email,
                                                                            mobile_number=mobile_number,
                                                                            qualification=qualification))
            NonMemberFreePaperInstructor.objects.bulk_create(co_non_member_instructors)

        if 'draft' in request.POST:
            add_paper.status = PAPER_STATUS['DRAFT']
            add_paper.save()
            messages.success(request, 'Instruction course saved to draft!')
            return HttpResponseRedirect(reverse('koscientific:freepaper_list'))
        elif 'final' in request.POST:
            add_paper.status = PAPER_STATUS['UNDER_EVALUATION']
            add_paper.ref_id = generate_random_number(10)
            add_paper.save()

            for co_instructor in add_paper.coauther_name.all():
                invited_session = InvitedSession()
                invited_session.abstract_title = add_paper.title
                invited_session.submission_type = add_paper.get_type_of_presentation_display()
                invited_session.summary = add_paper.synopsis
                invited_session.send_to = co_instructor.user
                invited_session.created_by = request.user
                invited_session.session_date = add_paper.created_at
                invited_session.is_free_paper = True
                invited_session.paper_id = add_paper.unique_id
                invited_session.save()

        ####################################################
        ######Assign paper to next section evaluator########
        ####################################################
        # ========================================
        # check specific section evaluators available 
        # get last section evaluator from AssignedFreePaper 
        # if no evaluator found then asssign to first 3 section evaluators order by created
        # else found, get last eval from AssignedFreePaper of the section and next 3 eval from section evaluators order by created
        # repeat the procedure
        # =========================================
        logger.info('===============start free paper evaluator assignment=================')
        if Evaluator.objects.filter(section=add_paper.section_id, status__iexact='active').exists():
            # get last section evaluator from AssignedFreePaper 
            assigned_last_section_eval = AssignedFreePaper.objects.filter(section_id=add_paper.section_id).order_by(
                'created_at').last()
            if assigned_last_section_eval is None:
                next_section_evaluators = Evaluator.objects.filter(section=add_paper.section_id,
                                                                   status__iexact='active')[0:3]
                for fresh_section_evalutor in next_section_evaluators:
                    assign = AssignedFreePaper()
                    assign.fp_id = add_paper.id
                    assign.evulator = fresh_section_evalutor
                    assign.section_id = add_paper.section_id
                    assign.status = PAPER_STATUS['ASSIGNED']
                    assign.save()
                    add_paper.status = PAPER_STATUS['UNDER_EVALUATION']
                    add_paper.save()
            else:
                last_assign_eval = assigned_last_section_eval.evulator
                logger.info('last section evaluator  id {} in the AssignedFreePaper table'.format(last_assign_eval.id))
                section_evals = Evaluator.objects.filter(section=add_paper.section_id,
                                                         status__iexact='active').order_by('created_at')
                logger.info('total section evaluator top to bottom count {}'.format(section_evals.count()))
                remaining_un_selected_section_evaluators_count = section_evals.filter(id__gt=last_assign_eval.id).count()
                logger.info('remaining evaluators count who paper not assigned  {}'.format(remaining_un_selected_section_evaluators_count))
                
                if remaining_un_selected_section_evaluators_count >= 3:
                    next_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)[0:3]
                elif remaining_un_selected_section_evaluators_count == 2:
                    last_two_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                    fist_section_evaluators = section_evals[0:1]
                    next_section_evaluators = list(chain(last_two_section_evaluators, fist_section_evaluators))
                elif remaining_un_selected_section_evaluators_count == 1:
                    logger.info("one evaluator left to assign free paper")
                    if section_evals.count() > 2:
                        # more user than him
                        last_one_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                        fist_two_section_evaluators = section_evals[0:2]
                        next_section_evaluators = list(chain(last_one_section_evaluators, fist_two_section_evaluators))
                    elif section_evals.count() > 1:
                        # more user than him
                        last_one_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                        fist_section_evaluators = section_evals[0:1]
                        next_section_evaluators = list(chain(last_one_section_evaluators, fist_section_evaluators))
                    else:
                        # no more user except him
                        next_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                elif remaining_un_selected_section_evaluators_count == 0:
                    logger.info('no more un-selected evaluators {}'.format(remaining_un_selected_section_evaluators_count))
                    # no more user except him
                    next_section_evaluators = section_evals[0:3]
                    logger.info('so again consider from old to new 3 evaluator {}'.format(next_section_evaluators))
                
                # Assign ic paper to next section evaluators
                for section_evaluator in next_section_evaluators:
                    assign = AssignedFreePaper()
                    assign.fp_id = add_paper.id
                    assign.evulator = section_evaluator
                    assign.section_id = add_paper.section_id
                    assign.status = PAPER_STATUS['ASSIGNED']
                    assign.save()
                add_paper.status = PAPER_STATUS['UNDER_EVALUATION']
                add_paper.save()
        else:
            messages.warning(request, 'section {} evaluator not found'.format(add_paper.section))
        logger.info('===============end of free paper evaluator assignment=================')
        
        
        try:
            # send sms to submitted applicant
            message = smsBody.objects.get(smskey__iexact=SmsForm.FREE_PAPER_SUBMISSION_TO_APPLICANT)
            message = message.smscontent.replace('{{paper_id}}', add_paper.unique_id)
            result, response = send_sms(message, request.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the FREE paper sms to user {}'.format(e))

        try:
            # send free paper mail to applicant
            mailcontent = Mail.objects.get(name__iexact=MailForm.FREE_PAPER_SUBMISSION_TO_APPLICANT)
            email_body = mailcontent.email_body.replace('{{paper_id}}', add_paper.unique_id)
            mail_dict = {
                'subject': mailcontent.email_subject,
                'plain_message': strip_tags(email_base_template(email_body)) ,
                'html_message': email_base_template(email_body),
                'recipient_list': '{}'.format(request.user.email)
            }
            KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send mail user who submitted the free paper {}'.format(e))
            
        try:
            # send sms confirmtion to evaluator
            message = smsBody.objects.get(smskey__iexact=SmsForm.FREE_PAPER_SUBMISSION_TO_EVALUATOR)
            message = message.smscontent.replace('{{private_paper_id}}', add_paper.ref_id)
            mobile_numbers = []
            for evaluator in next_section_evaluators:
                try:
                    # get member mobile number
                    mobile_numbers.append(evaluator.membership.user.profile.mobile_number)
                except Exception as e:
                    try:
                        # mobile number which was saved during evaluator invite
                        mobile_numbers.append(evaluator.invite.mobile_number)
                    except Exception as e:
                        pass
            result, response = send_mass_sms(message, mobile_numbers)
        except Exception as e:
            logger.info('unable to send the submitted the free paper sms to evaluator {}'.format(e))
            
        try:
            # send mail to evaluator
            emails = []
            for evaluator in next_section_evaluators:
                try:
                    # get member mobile number
                    email = evaluator.membership.user.email
                    evaluator_full_name = "{} {}".format(evaluator.membership.user.first_name, evaluator.membership.user.last_name)
                except Exception as e:
                    try:
                        # mobile number which was saved during evaluator invite
                        email = evaluator.invite.email
                        evaluator_full_name = "{} {}".format(evaluator.invite.first_name, evaluator.invite.last_name)
                    except Exception as e:
                        pass
                    
                mailcontent = Mail.objects.get(name__iexact=MailForm.FREE_PAPER_SUBMISSION_TO_EVALUATOR)
                email_body = mailcontent.email_body.replace('{{evaluator_full_name}}', evaluator_full_name)
                email_body = email_body.replace('{{private_paper_id}}', add_paper.ref_id)
                
                mail_dict = {
                    'subject': mailcontent.email_subject,
                    'plain_message': strip_tags(email_base_template(email_body)) ,
                    'html_message': email_base_template(email_body),
                    'recipient_list': '{}'.format(email)
                }
                KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send the submitted the free paper email to evaluator {}'.format(e))
        
        try:
            # notification sending to applicant 
            WebNotification(request.user).send_only_notification_to_user([request.user],
                                                                        'free paper course successfully submitted')
            # to evaluator
            message = 'Free paper assigned'
            WebNotification(request.user).send_only_notification_to_user(
                [next_section_evaluator.membership.user for next_section_evaluator in next_section_evaluators if next_section_evaluator.membership], message)
        except Exception as e:
            logger.info('unable to send socket notification to evaluator and user {}'.format(e))
        
        try:
            # send sms to presenting author
            message = smsBody.objects.get(smskey__iexact=SmsForm.FREE_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            result, response = send_sms(message, add_paper.presenting_auther_name.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the FREE paper sms to presenting author {}'.format(e))
            
        try:
            # send sms to co author
            message = smsBody.objects.get(smskey__iexact=SmsForm.FREE_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            for co_author in add_paper.coauther_name.all():
                result, response = send_sms(message, co_author.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the FREE paper sms to co author {}'.format(e))
            
        try:
            # send sms to non kos co-author
            message = smsBody.objects.get(smskey__iexact=SmsForm.FREE_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            for non_kos_member in add_paper.non_members_free_paper_instructors.all():
                result, response = send_sms(message, non_kos_member.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the FREE paper sms to non kos co-author {}'.format(e))
            
        messages.success(request, 'Free paper submitted successfully!')
        return HttpResponseRedirect(reverse('koscientific:freepaper_list'))
    if paper_id:
        free_paper = get_object_or_404(FreePaper, pk=paper_id)
    else:
        free_paper = None
    section_list = Section.objects.filter(status=PAPER_STATUS['ACTIVE'])
    # pure members excluding evaluator
    member_name_list = MemberShip.objects.filter(user__roles__in=[Role.MEMBER])
    co_members = MemberShip.objects.filter(user__roles__in=[Role.MEMBER]).exclude(user=request.user)
    context = {
        'free_paper': free_paper,
        'section_list': section_list,
        'member_name_list': member_name_list,
        'co_members': co_members,
        'type_of_presentations': FreePaper.PRESENTATION_CHOICES,
        'free_paper_max_non_member': PaperCoAuthorLimit.objects.get(paper=PaperCoAuthorLimit.FREE_PAPER).max_non_kos_member_limit,
        'free_paper_max_member': PaperCoAuthorLimit.objects.get(paper=PaperCoAuthorLimit.FREE_PAPER).max_limit,
        'non_member_qualifications': NonMemberFreePaperInstructor.QUALIFICATION_CHOICES,
        'events': Event.objects.exclude(status=Event.INACTIVE),
        'auto_save_in': settings.AUTO_SAVE_IN,
    }
    user_fp_paper_count = FreePaper.objects.filter(created_by=request.user).count()
    if user_fp_paper_count > settings.MAX_FREE_PAPER_LIMIT:
        messages.warning(request, 'Your max submitting free paper course {} limit exceeded'.format(
            settings.MAX_FREE_PAPER_LIMIT))
    return render(request, 'freepaper/create_free_paper.html', context)



def View_free_paper(request, free_paper_id):
    """
    show paper details
    show section rank if evaluated
    show overall rank if evaluated
    """
    try:
        free_paper_view = FreePaper.objects.get(id=free_paper_id)
    except Exception as e:
        free_paper_view = FreePaper.objects.get(unique_id=free_paper_id)

    try:
        total_marks = free_paper_view.assignedfreepaper_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get(
            'sum_total')
    except Exception as e:
        total_marks = None
    
    is_paper_evaluated = True
    section_rank_dict = None
    over_all_rank_dict = None
    total_marks_in_percentage = None
    total_evaluator = None
    if not free_paper_view.assignedfreepaper_set.all():
        is_paper_evaluated = False
    for assigned_to in free_paper_view.assignedfreepaper_set.all():
        if assigned_to.marks == None:
            is_paper_evaluated = False
            break
    
    if is_paper_evaluated:
        total_evaluator = free_paper_view.assignedfreepaper_set.count()
        total_marks_in_percentage = total_marks/(total_evaluator*50)
        total_marks_in_percentage = total_marks_in_percentage*100
            
        paper_section_wise_total_marks = []
        # Evaluated free paper of this section 
        free_paper_qs = FreePaper.objects.filter(section=free_paper_view.section).exclude(status__iexact='draft').select_related().exclude(assignedfreepaper__marks__isnull=True).distinct()
        for free_paper in free_paper_qs:
            paper_marks = free_paper.assignedfreepaper_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            
            paper_total_evaluator = free_paper.assignedfreepaper_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # Evaluated ic paper of this section
        ic_paper_qs = InstructionCourse.objects.filter(section=free_paper_view.section).exclude(status__iexact='draft').select_related().exclude(assignedto__marks__isnull=True).distinct()
        for ic_paper in ic_paper_qs:
            paper_marks = ic_paper.assignedto_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            
            paper_total_evaluator = ic_paper.assignedto_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # Evaluated video paper of this section 
        video_paper_qs = Video.objects.filter(section=free_paper_view.section).exclude(status__iexact='draft').select_related().exclude(assignedvideo__marks__isnull=True).distinct()
        for video_paper in video_paper_qs:
            paper_marks = video_paper.assignedvideo_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            
            paper_total_evaluator = video_paper.assignedvideo_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        logger.info('paper_section_wise_total_marks in % {}'.format(paper_section_wise_total_marks))
        logger.info('total marks % {}'.format(total_marks_in_percentage))

        # remove none value
        if paper_section_wise_total_marks:
            paper_section_wise_total_marks = [x for x in paper_section_wise_total_marks if x is not None]
            paper_section_wise_total_marks.sort(reverse=True)
            section_rank = paper_section_wise_total_marks.index(total_marks_in_percentage)
            section_rank = section_rank+1
        else:
            section_rank =None
        logger.info('section_rank {}'.format(section_rank))

        # over all rank
        paper_over_all_total_marks = []
        # Evaluated free paper 
        free_paper_qs = FreePaper.objects.exclude(status__iexact='draft').select_related().exclude(assignedfreepaper__marks__isnull=True).distinct()
        for free_paper in free_paper_qs:
            paper_marks = free_paper.assignedfreepaper_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = free_paper.assignedfreepaper_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # Evaluated ic paper
        ic_paper_qs = InstructionCourse.objects.exclude(status__iexact='draft').select_related().exclude(assignedto__marks__isnull=True).distinct()
        for ic_paper in ic_paper_qs:
            paper_marks = ic_paper.assignedto_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = ic_paper.assignedto_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # Evaluated video paper
        video_paper_qs = Video.objects.exclude(status__iexact='draft').select_related().exclude(assignedvideo__marks__isnull=True).distinct()
        for video_paper in video_paper_qs:
            paper_marks = video_paper.assignedvideo_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = video_paper.assignedvideo_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        logger.info('paper_over_all_total_marks {}'.format(paper_over_all_total_marks))
        logger.info('total marks {}'.format(total_marks_in_percentage))
        
        # remove none value
        if paper_over_all_total_marks:
            paper_over_all_total_marks = [x for x in paper_over_all_total_marks if x is not None]
            paper_over_all_total_marks.sort(reverse=True)
            over_all_rank = paper_over_all_total_marks.index(total_marks_in_percentage)
            over_all_rank = over_all_rank+1
        else:
            over_all_rank = None
            
        logger.info('paper_over_all_total_marks in % {}'.format(paper_over_all_total_marks))
        logger.info('total marks % {}'.format(total_marks_in_percentage))
        logger.info('over_all_rank {}'.format(over_all_rank))
        
        section_rank_dict = {
            'rank' : section_rank,
            'out_of': len(paper_section_wise_total_marks)
        }
        over_all_rank_dict = {
            'rank' : over_all_rank,
            'out_of': len(paper_over_all_total_marks)
        }
    context = {
        'free_paper_view': free_paper_view,
        'total_obtained_marks': total_marks,
        'total_evaluator': total_evaluator*50 if total_evaluator else None,
        'total_marks_in_percentage': total_marks_in_percentage,
        'section_rank': section_rank_dict if section_rank_dict else None,
        'over_all_rank': over_all_rank_dict if over_all_rank_dict else None
    }

    return render(request, 'freepaper/view_free_paper.html', context)


def Video_list(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN ]):
        video_list = Video.objects.all().order_by('-created_at')
    elif User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        video_list = Video.objects.filter(status=PAPER_STATUS['UNDER_EVALUATION']).order_by('-created_at')
    else:
        video_list = Video.objects.filter(created_by=request.user).order_by('-created_at')
    context = {
        'video_list': video_list,
    }
    count = video_list.count()
    video_list = video_list
    page = request.GET.get('page', 1)
    paginator = Paginator(video_list, 10)
    try:
        video_list = paginator.page(page)
    except PageNotAnInteger:
        video_list = paginator.page(1)
    except EmptyPage:
        video_list = paginator.page(paginator.num_pages)

    index = video_list.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['video_list'] = video_list
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'video/video.html', context)


def Video_Evaluated(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        video_evaluated = Video.objects.filter(status=PAPER_STATUS['EVALUATED']).order_by('-created_at')
        context = {
            'video_evaluated': video_evaluated,
        }
        return render(request, 'video/video_evaluated.html', context)


def Video_Selected(request):
    if User.objects.filter(email=request.user.email, roles__in=[Role.EVALUATOR, ]):
        video_selected = Video.objects.filter(status=PAPER_STATUS['SELECTED']).order_by('-created_at')
        context = {
            'video_selected': video_selected,
        }
        return render(request, 'video/video_selected.html', context)


def video_paper_ajax(request):
    """
    video paper ajax auto draft save
    """
    if request.method == 'POST':
        user_video_paper_count = Video.objects.filter(created_by=request.user).count()
        if user_video_paper_count > settings.MAX_VIDEOS_LIMIT:
            response = {
                'status': False,
                'message': 'Submission paper limit {} exceeded'.format(settings.MAX_VIDEOS_LIMIT),
            }
            return JsonResponse(response)

        if not request.POST['title']:
            response = {
                'status': True,
                'message': 'at least title to draft',
            }
            return JsonResponse(response)
        if 'paper_id' in request.POST:
            logger.info('member ajax draft saving the video paper {}'.format(request.POST['paper_id']))
            video_paper = get_object_or_404(Video, pk=request.POST['paper_id'])
        elif 'edit' in request.META['HTTP_REFERER']:
            logger.info('member ajax edit the video paper {}'.format(request.META['HTTP_REFERER'].split('/')[-2]))
            video_paper = get_object_or_404(Video, pk=request.META['HTTP_REFERER'].split('/')[-2])
        elif Video.objects.filter(created_by=request.user, title__iexact=request.POST['title']).exists():
            response = {
                'status': False,
                'message': 'title already there not saving to draft',
            }
            return JsonResponse(response)
        else:
            video_paper = Video()
            logger.info("member ajax new video paper")
            
        if 'title' in request.POST:
            video_paper.title = request.POST['title']

        if 'event' in request.POST:
            video_paper.event_id = request.POST['event']
        if 'section' in request.POST:
            video_paper.section_id = request.POST['section']
        if 'video_type' in request.POST:
            video_paper.video_type = request.POST['video_type']
        if 'abstract' in request.POST:
            video_paper.abstract = request.POST['abstract']
        
        if not video_paper.unique_id:
            video_paper.save()
            video_paper.unique_id = "VDO" + str(video_paper.id)
        video_paper.created_by = request.user
        if not video_paper.status:
            video_paper.status = PAPER_STATUS['DRAFT']
        video_paper.save()
        response = {
            'status': True,
            'message': 'added to draft',
            'paper_id': video_paper.id
        }
        return JsonResponse(response)
    else:
        response = {
            'status': False,
            'message': 'get wont support',
        }
        return JsonResponse(response)


@login_required
def create_video(request, paper_id=None):
    """
    video paper Add and Edit by submitted member.
    Validate max paper submiting.
    If paper_id present the edit or add.
    Saved form info.
    Assign paper to next available same section evaluator.
    Send email ans sms to Applicant and evaluator.
    Send webnotification to applicant.
    """

    if request.method == 'POST':
        user_video_paper_count = Video.objects.filter(created_by=request.user).count()
        if user_video_paper_count > settings.MAX_VIDEOS_LIMIT:
            messages.error(request,
                           'Your max submitting video course {} limit exceeded'.format(settings.MAX_VIDEOS_LIMIT))
            return HttpResponseRedirect(reverse('koscientific:video'))
        if 'paper_id' in request.POST:
            logger.info('member draft saving the video paper {}'.format(request.POST['paper_id']))
            add_video = get_object_or_404(Video, pk=request.POST['paper_id'])
        elif paper_id:
            logger.info('member editing the video paper {}'.format(paper_id))
            add_video = get_object_or_404(Video, pk=paper_id)
        else:
            logger.info('member creating new video paper')
            add_video = Video()
            
        if not request.POST.get('title'):
            messages.error(request, "At least title required to save draft")
            return HttpResponseRedirect(reverse('koscientific:video'))

        add_video.title = request.POST.get('title')
        add_video.video_type = request.POST.get('video_type')
        add_video.section_id = request.POST.get('section')
        add_video.abstract = request.POST['abstract']
        add_video.event_id = request.POST.get('event')
            
        if request.POST.get('section') and 'final' in request.POST:
            evaluators = Evaluator.objects.filter(section=add_video.section, status__iexact='active')
            if not evaluators.exists():
                messages.error(request, 'Evaluator is not present for this section')
                return HttpResponseRedirect(reverse('koscientific:video'))

        # add_video.status = request.POST['status']
        add_video.presenting_video_auther_name_id = request.POST.get('presenting_author_id')
        add_video.chief_author_id = request.POST.get('chief_author_id')

        add_video.save()
        if 'co_author_membership_id' in request.POST:
            extra_co_authors = [extra_co_authors for extra_co_authors in request.POST.getlist('co_author_membership_id') if extra_co_authors]
            add_video.coauther_video_name.set(
                [get_object_or_404(MemberShip, pk=co_ins) for co_ins in extra_co_authors])
        add_video.created_by = request.user
        if not add_video.unique_id:
            add_video.unique_id = "VDO" + str(add_video.id)
            add_video.save()
        
        if 'final' in request.POST:
            co_non_member_instructors = []
            for first_name, last_name, email, mobile_number, qualification in zip(
                    request.POST.getlist('non_mem_co_instructor_first_name'),
                    request.POST.getlist('non_mem_co_instructor_last_name'),
                    request.POST.getlist('non_mem_co_instructor_email'),
                    request.POST.getlist('non_mem_co_instructor_mobile_number'),
                    request.POST.getlist('non_mem_co_instructor_qualification')):
                if first_name and last_name and email and mobile_number and qualification:
                    if not Profile.objects.filter(mobile_number=mobile_number).exists() and not User.objects.filter(email=email).exists():
                        
                        co_non_member_instructors.append(NonMemberVideoPaperInstructor(video=add_video,
                                                                                first_name=first_name,
                                                                                last_name=last_name,
                                                                                email=email,
                                                                                mobile_number=mobile_number,
                                                                                qualification=qualification))

            NonMemberVideoPaperInstructor.objects.bulk_create(co_non_member_instructors)

        if 'draft' in request.POST:
            add_video.status = PAPER_STATUS['DRAFT']
            add_video.save()
            return HttpResponseRedirect(reverse('koscientific:video'))
        elif 'final' in request.POST:
            add_video.status = PAPER_STATUS['UNDER_EVALUATION']
            add_video.ref_id = generate_random_number(10)
            add_video.save()

            for co_instructor in add_video.coauther_video_name.all():
                invited_session = InvitedSession()
                invited_session.abstract_title = add_video.title
                invited_session.submission_type = add_video.video_type
                invited_session.summary = add_video.abstract
                invited_session.send_to = co_instructor.user
                invited_session.created_by = request.user
                invited_session.session_date = add_video.created_at
                invited_session.is_video_paper = True
                invited_session.paper_id = add_video.unique_id
                invited_session.save()

        ####################################################
        ######Assign paper to next section evaluator########
        ####################################################

        # ========================================
        # check specific section evaluators available 
        # get last section evaluator from AssignedTo 
        # if no evaluator found then asssign to first 3 section evaluators order by created
        # else found, get last eval from AssignedTo of the section and next 3 eval from section evaluators order by created
        # repeat the procedure
        # =========================================
        logger.info('===============start video paper evaluator assignment=================')
        if Evaluator.objects.filter(section=add_video.section_id, status__iexact='active').exists():
            # get last section evaluator from AssignedVideo 
            assigned_last_section_eval = AssignedVideo.objects.filter(section_id=add_video.section_id).order_by(
                'created_at').last()
            if assigned_last_section_eval is None:
                next_section_evaluators = Evaluator.objects.filter(section=add_video.section_id,
                                                                   status__iexact='active')[0:3]
                for fresh_section_evalutor in next_section_evaluators:
                    assign = AssignedVideo()
                    assign.vd_id = add_video.id
                    assign.evaluator = fresh_section_evalutor
                    assign.section_id = add_video.section_id
                    assign.status = PAPER_STATUS['ASSIGNED']
                    assign.save()
                    add_video.status = PAPER_STATUS['UNDER_EVALUATION']
                    add_video.save()
            else:
                last_assign_eval = assigned_last_section_eval.evaluator
                logger.info('last section evaluator  id {} in the AssignedVideo table'.format(last_assign_eval.id))
                section_evals = Evaluator.objects.filter(section=add_video.section_id,
                                                         status__iexact='active').order_by('created_at')
                logger.info('total section evaluator top to bottom count {}'.format(section_evals.count()))
                remaining_un_selected_section_evaluators_count = section_evals.filter(id__gt=last_assign_eval.id).count()
                logger.info('remaining evaluators count who paper not assigned  {}'.format(remaining_un_selected_section_evaluators_count))
                
                if remaining_un_selected_section_evaluators_count >= 3:
                    next_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)[0:3]
                elif remaining_un_selected_section_evaluators_count == 2:
                    last_two_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                    fist_section_evaluators = section_evals[0:1]
                    next_section_evaluators = list(chain(last_two_section_evaluators, fist_section_evaluators))
                elif remaining_un_selected_section_evaluators_count == 1:
                    logger.info("one evaluator left to assign ic paper")
                    if section_evals.count() > 2:
                        # more user than him
                        last_one_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                        fist_two_section_evaluators = section_evals[0:2]
                        next_section_evaluators = list(chain(last_one_section_evaluators, fist_two_section_evaluators))
                    elif section_evals.count() > 1:
                        # more user than him
                        last_one_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                        fist_section_evaluators = section_evals[0:1]
                        next_section_evaluators = list(chain(last_one_section_evaluators, fist_section_evaluators))
                    else:
                        # no more user except him
                        next_section_evaluators = section_evals.filter(id__gt=last_assign_eval.id)
                elif remaining_un_selected_section_evaluators_count == 0:
                    logger.info('no more un-selected evaluators {}'.format(remaining_un_selected_section_evaluators_count))
                    # no more user except him
                    next_section_evaluators = section_evals[0:3]
                    logger.info('so again consider from old to new 3 evaluator {}'.format(next_section_evaluators))
                
                # Assign ic paper to next section evaluators
                for section_evaluator in next_section_evaluators:
                    assign = AssignedVideo()
                    assign.vd_id = add_video.id
                    assign.evaluator = section_evaluator
                    assign.section_id = add_video.section_id
                    assign.status = PAPER_STATUS['ASSIGNED']
                    assign.save()
                add_video.status = PAPER_STATUS['UNDER_EVALUATION']
                add_video.save()
        else:
            messages.warning(request, 'section {} evaluator not found'.format(add_video.section))
        logger.info('===============end of free paper evaluator assignment=================')
               
        try:
            # send sms to video paper applicant
            message = smsBody.objects.get(smskey__iexact=SmsForm.VIDEO_PAPER_SUBMISSION_TO_APPLICANT)
            message = message.smscontent.replace('{{paper_id}}', add_video.unique_id)
            result, response = send_sms(message, request.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the video paper sms to applicant {}'.format(e))

        try:
            # send mail to vedio paper applicant
            mailcontent = Mail.objects.get(name__iexact=MailForm.VIDEO_PAPER_SUBMISSION_TO_APPLICANT)
            email_body = mailcontent.email_body.replace('{{paper_id', add_video.unique_id)
            mail_dict = {
                'subject': mailcontent.email_subject,
                'plain_message': strip_tags(email_base_template(email_body)) ,
                'html_message': email_base_template(email_body),
                'recipient_list': '{}'.format(request.user.email)
            }
            KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send mail to vedio paper applicant')
            
        try:
            # send sms confirmtion to evaluator
            message = smsBody.objects.get(smskey__iexact=SmsForm.VIDEO_PAPER_SUBMISSION_TO_EVALUATOR)
            message = message.smscontent.replace('{{private_paper_id}}', add_video.ref_id)
            mobile_numbers = []
            for evaluator in next_section_evaluators:
                try:
                    # get member mobile number
                    mobile_numbers.append(evaluator.membership.user.profile.mobile_number)
                except Exception as e:
                    try:
                        # mobile number which was saved during evaluator invite
                        mobile_numbers.append(evaluator.invite.mobile_number)
                    except Exception as e:
                        pass
            result, response = send_mass_sms(message, mobile_numbers)
        except Exception as e:
            logger.info('unable to send the submitted the video paper sms to evaluator {}'.format(e))
            
        try:
            # send mail to video paper to evaluator
            for evaluator in next_section_evaluators:
                try:
                    email = evaluator.membership.user.email
                    evaluator_full_name = "{} {}".format(evaluator.membership.user.first_name, evaluator.membership.user.last_name)
                except Exception as e:
                    try:
                        email = evaluator.invite.email
                        evaluator_full_name = "{} {}".format(evaluator.invite.first_name, evaluator.invite.last_name)
                    except Exception as e:
                        pass
                    
                mailcontent = Mail.objects.get(name__iexact=MailForm.VIDEO_PAPER_SUBMISSION_TO_EVALUATOR)
                email_body = mailcontent.email_body.replace('{{evaluator_full_name}}', evaluator_full_name)
                email_body = email_body.replace('{{private_paper_id}}', add_video.ref_id)
                mail_dict = {
                    'subject': mailcontent.email_subject,
                    'plain_message': strip_tags(email_base_template(email_body)) ,
                    'html_message': email_base_template(email_body),
                    'recipient_list': '{}'.format(email)
                }
                KosEmail.send(**mail_dict)
        except Exception as e:
            logger.info('unable to send the submitted the video paper email to evaluator {}'.format(e))
        
        try:
            # notification sending to applicant 
            WebNotification(request.user).send_only_notification_to_user([request.user],
                                                                        'video paper successfully submitted')
            # to evaluator
            message = 'video  paper assigend'
            WebNotification(request.user).send_only_notification_to_user(
                [next_section_evaluator.membership.user for next_section_evaluator in next_section_evaluators if next_section_evaluator.membership], message)
        except Exception as e:
            logger.info('unable to send socket notification to evaluator and user {}'.format(e))

        try:
            # notification sending
            WebNotification(request.user).send_only_notification_to_user([request.user],
                                                                         'video paper successfully submitted')
            message = '{} {} submitted the vedio paper'.format(request.user.first_name, request.user.last_name)
            WebNotification(request.user).send_only_notification_to_user(
                [next_section_evaluator.membership.user for next_section_evaluator in next_section_evaluators], message)
        except Exception as e:
            logger.info('unable to send socket notification to evaluator and user')
            
        try:
            # send sms to presenting author
            message = smsBody.objects.get(smskey__iexact=SmsForm.VIDEO_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            result, response = send_sms(message, add_video.presenting_video_auther_name.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the video paper sms to presenting author {}'.format(e))
            
        try:
            # send sms to co author
            message = smsBody.objects.get(smskey__iexact=SmsForm.VIDEO_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            for co_author in add_video.coauther_video_name.all():
                result, response = send_sms(message, co_author.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the video paper sms to co author {}'.format(e))
            
        try:
            # send sms to non kos co-author
            message = smsBody.objects.get(smskey__iexact=SmsForm.VIDEO_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER)
            user_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            message = message.smscontent.replace('{{user_full_name}}', user_full_name)
            for non_kos_member in add_video.non_members_video_paper_instructors.all():
                result, response = send_sms(message, non_kos_member.mobile_number)
        except Exception as e:
            logger.info('unable to send the submitted the video paper sms to non kos co-author {}'.format(e))

        messages.success(request, 'Free paper submitted successfully!')
        return HttpResponseRedirect(reverse('koscientific:video'))
    if paper_id:
        video_paper = get_object_or_404(Video, pk=paper_id)
    else:
        video_paper = None

    section_list = Section.objects.filter(status=PAPER_STATUS['ACTIVE'])
    # pure members excluding evaluator
    member_name_list = MemberShip.objects.filter(user__roles__in=[Role.MEMBER])
    co_members = MemberShip.objects.filter(user__roles__in=[Role.MEMBER]).exclude(user=request.user)
    context = {
        'video_paper': video_paper,
        'section_list': section_list,
        'member_name_list': member_name_list,
        'co_members': co_members,
        'non_member_qualifications': NonMemberVideoPaperInstructor.QUALIFICATION_CHOICES,
        'events': Event.objects.exclude(status=Event.INACTIVE),
        'auto_save_in': settings.AUTO_SAVE_IN,
        'video_paper_max_non_member': PaperCoAuthorLimit.objects.get(paper=PaperCoAuthorLimit.VIDEO_PAPER).max_non_kos_member_limit,
        'video_paper_max_member': PaperCoAuthorLimit.objects.get(paper=PaperCoAuthorLimit.VIDEO_PAPER).max_limit,
    }
    user_video_paper_count = Video.objects.filter(created_by=request.user).count()
    if user_video_paper_count > settings.MAX_VIDEOS_LIMIT:
        messages.warning(request,
                         'Your max submitting video course {} limit exceeded'.format(settings.MAX_VIDEOS_LIMIT))
    return render(request, 'video/add_video.html', context)


def View_video(request, video_id):
    try:
        video_view = Video.objects.get(id=video_id)
    except Exception as e:
        video_view = Video.objects.get(unique_id=video_id)

    try:
        total_marks = video_view.assignedvideo_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
    except Exception as e:
        total_marks = None
        
    is_paper_evaluated = True
    section_rank_dict = None
    over_all_rank_dict = None
    total_marks_in_percentage = None
    total_evaluator = None
    if not video_view.assignedvideo_set.all():
        is_paper_evaluated = False
    for assigned_to in video_view.assignedvideo_set.all():
        if assigned_to.marks == None:
            is_paper_evaluated = False
            break
    
    if is_paper_evaluated:
        total_evaluator = video_view.assignedvideo_set.count()
        total_marks_in_percentage = total_marks/(total_evaluator*50)
        total_marks_in_percentage = total_marks_in_percentage*100
            
        paper_section_wise_total_marks = []
        # Evaluated free paper of this section 
        free_paper_qs = FreePaper.objects.filter(section=video_view.section).exclude(status__iexact='draft').select_related().exclude(assignedfreepaper__marks__isnull=True).distinct()
        for free_paper in free_paper_qs:
            paper_marks = free_paper.assignedfreepaper_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            
            paper_total_evaluator = free_paper.assignedfreepaper_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # Evaluated ic paper of this section
        ic_paper_qs = InstructionCourse.objects.filter(section=video_view.section).exclude(status__iexact='draft').select_related().exclude(assignedto__marks__isnull=True).distinct()
        for ic_paper in ic_paper_qs:
            paper_marks = ic_paper.assignedto_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get(
            'sum_total')
            
            paper_total_evaluator = ic_paper.assignedto_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # Evaluated video paper of this section 
        video_paper_qs = Video.objects.filter(section=video_view.section).exclude(status__iexact='draft').select_related().exclude(assignedvideo__marks__isnull=True).distinct()
        for video_paper in video_paper_qs:
            paper_marks = video_paper.assignedvideo_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = video_paper.assignedvideo_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_section_wise_total_marks.append(paper_marks)
            
        # remove none value
        if paper_section_wise_total_marks:
            paper_section_wise_total_marks = [x for x in paper_section_wise_total_marks if x is not None]
            paper_section_wise_total_marks.sort(reverse=True)
            section_rank = paper_section_wise_total_marks.index(total_marks_in_percentage)
            section_rank = section_rank+1
        else:
            section_rank =None
        
        logger.info('paper_section_wise_total_marks in % {}'.format(paper_section_wise_total_marks))
        logger.info('total marks % {}'.format(total_marks_in_percentage))
        
        # over all rank
        paper_over_all_total_marks = []
        # Evaluated free paper 
        free_paper_qs = FreePaper.objects.exclude(status__iexact='draft').select_related().exclude(assignedfreepaper__marks__isnull=True).distinct()
        for free_paper in free_paper_qs:
            paper_marks = free_paper.assignedfreepaper_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = free_paper.assignedfreepaper_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # Evaluated ic paper
        ic_paper_qs = InstructionCourse.objects.exclude(status__iexact='draft').select_related().exclude(assignedto__marks__isnull=True).distinct()
        for ic_paper in ic_paper_qs:
            paper_marks = ic_paper.assignedto_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = ic_paper.assignedto_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # Evaluated video paper
        video_paper_qs = Video.objects.exclude(status__iexact='draft').select_related().exclude(assignedvideo__marks__isnull=True).distinct()
        for video_paper in video_paper_qs:
             
            paper_marks = video_paper.assignedvideo_set.all().aggregate(sum_total=Sum('ic_marks__marks')).get('sum_total')
            paper_total_evaluator = video_paper.assignedvideo_set.count()
            paper_marks = paper_marks/(paper_total_evaluator*50)
            paper_marks = paper_marks*100
            paper_over_all_total_marks.append(paper_marks)
            
        # remove none value
        if paper_over_all_total_marks:
            paper_over_all_total_marks = [x for x in paper_over_all_total_marks if x is not None]
            paper_over_all_total_marks.sort(reverse=True)
            over_all_rank = paper_over_all_total_marks.index(total_marks_in_percentage)
            over_all_rank = over_all_rank+1
        else:
            over_all_rank = None
        
        logger.info('paper_over_all_total_marks in % {}'.format(paper_over_all_total_marks))
        logger.info('total marks % {}'.format(total_marks_in_percentage))
        logger.info('over_all_rank {}'.format(over_all_rank))
        
        section_rank_dict = {
            'rank' : section_rank,
            'out_of': len(paper_section_wise_total_marks)
        }
        over_all_rank_dict = {
            'rank' : over_all_rank,
            'out_of': len(paper_over_all_total_marks)
        }
    context = {
        'video_view': video_view,
        'total_obtained_marks': total_marks,
        'total_evaluator': total_evaluator*50 if total_evaluator else None,
        'total_marks_in_percentage': total_marks_in_percentage,
        'section_rank': section_rank_dict if section_rank_dict else None,
        'over_all_rank': over_all_rank_dict if over_all_rank_dict else None
    }
    return render(request, 'video/view_video.html', context)


counrty_id = None
region_id = None


def load_state(request):
    global counrty_id
    country_id = request.GET.get('country')
    logger.info(country_id)
    region = Region.objects.filter(country_id=country_id).order_by('name')
    return render(request, 'member/city_dropdown_list_options.html', {'region': region})


def load_city(request):
    global region_id
    region_id = request.GET.get('region')
    logger.info(region_id)
    city1 = City.objects.filter(region_id=region_id).order_by('name')
    return render(request, 'member/citys_dropdown_list_options.html', {'city': city1})


def Register(request):
    context = {}
    quaFormset = modelformset_factory(Qualification, form=QualificationForm)

    formset = quaFormset(request.POST or None, queryset=Qualification.objects.none(), prefix='qualification')
    if request.method == 'POST':
        for qua in formset:
            logger.info('qua: ', qua)
            data = qua.save(commit=False)
            data.save()

        member = MemberShip()

        if 'first_name' in request.POST:
            member.user.first_name = request.POST['first_name']
        if 'last_name' in request.POST:
            member.user.last_name = request.POST['last_name']
        if 'dob' in request.POST:
            member.dob = request.POST['dob']
        if 'gender' in request.POST:
            member.gender = request.POST['gender']
        if 'recidence_Street_address' in request.POST:
            member.recidence_Street_address = request.POST['recidence_Street_address']
        if 'recidence_address_line_2' in request.POST:
            member.recidence_address_line_2 = request.POST['recidence_address_line_2']
        if 'recidencecountry' in request.POST:
            member.recidencecountry_id = request.POST['recidencecountry']
        if 'recidencesstate' in request.POST:
            member.recidencestate_id = request.POST['recidencesstate']
        if 'recidencecity' in request.POST:
            member.recidencecity_id = request.POST['recidencecity']
        if 'recidence_pincode' in request.POST:
            member.recidence_pincode = request.POST['recidence_pincode']
        if 'address_condition' in request.POST:
            member.address_condition = request.POST['address_condition']
        if member.address_condition == True:
            member.office_Street_address = request.POST['recidence_Street_address']
            logger.info(member.office_Street_address)
            member.office_address_line_2 = member.recidence_address_line_2
            member.office_city = member.recidence_city
            member.office_state = member.recidencestate
            member.office_pincode = member.recidence_pincode
            member.office_country_id = member.recidencecountry_id
        elif member.address_condition == False:
            if 'office_Street_address' in request.POST:
                member.office_Street_address = request.POST['office_Street_address']
            if 'office_address_line_2' in request.POST:
                member.office_address_line_2 = request.POST['office_address_line_2']
            if 'office_country' in request.POST:
                member.office_country_id = request.POST['office_country']
            if 'office_state' in request.POST:
                member.office_state_id = request.POST['office_state']
            if 'office_city' in request.POST:
                member.office_city_id = request.POST['office_city']

            if 'office_pincode' in request.POST:
                member.office_pincode = request.POST['office_pincode']
        if 'office_Street_address' in request.POST:
            member.office_Street_address = request.POST['office_Street_address']
        if 'office_address_line_2' in request.POST:
            member.office_address_line_2 = request.POST['office_address_line_2']
        if 'mobile' in request.POST:
            member.mobile = request.POST['mobile']
        if 'home_phone' in request.POST:
            member.home_phone = request.POST['home_phone']
        if 'office_phone' in request.POST:
            member.office_phone = request.POST['office_phone']
        # if 'email' in request.POST:
        #     member.email = request.POST['email']
        if 'cheque_no' in request.POST:
            member.cheque_no = request.POST['cheque_no']
        if 'bank' in request.POST:
            member.bank = request.POST['bank']
        if 'medical_registration_no' in request.POST:
            member.medical_registration_no = request.POST['medical_registration_no']
        # if 'state_registration' in request.POST:
        #     member.state_registration = request.POST['state_registration']
        if 'reg_country' in request.POST:
            member.reg_country_id = request.POST['reg_country']
        if 'office_state' in request.POST:
            member.reg_state_id = request.POST['reg_state']
        if 'date' in request.POST:
            member.date = request.POST['date']
        if 'photo' in request.FILES:
            member.photo = request.FILES['photo']
        if 'certificate' in request.FILES:
            member.certificate = request.FILES['certificate']
        member.price = 100

        if 'agree' in request.POST:
            member.agree = request.POST['agree']
        member.qualification_id = 1
        member.introduced_by_id = 1
        member.save()
        member.kos_no = member.id
        logger.info(member.kos_no)
        member.save()
        context = {
            'name': member.user.first_name,
            'gender': member.gender,
            'mobile': member.mobile,
            'email': member.user.email,
            'kos_no': member.kos_no,
            'date': member.date,

        }
        return render(request, 'member/payment_view.html', context)
        # member.qualification_id=request.POST.getlist('degree[]')
        # data1=[]
        # data=[]
        # asd = {}
        # for x in range(6):
        #     a = request.POST.getlist('degree[]')[x]
        #     b = request.POST.getlist('year[]')[x]
        #     c = request.POST.getlist('college[]')[x]
        #
        #     data.append({"degree":a,"college":c,"year": b})
        #
        # data1.append({'data':data})
        # logger.info(data1)
        # # data = {"asd":data}
        # # data=json.dumps(data)
        # # data=json.loads(data)
        # # logger.info(data)
        # # logger.info(type(data))
        # # logger.info(type(data['asd'][0]['degree']))
        # # logger.info(len(json.loads(data['asd'][0]['degree'])))

    country = Country.objects.all()
    context['formset'] = formset
    context['country'] = country

    return render(request, 'member/register.html', context)


def Evaluter_list(request):
    all_evaluator = Evaluator.objects.all().order_by('-created_at')
    count = all_evaluator.count()
    context = {
        'all_evaluator': all_evaluator,
    }
    all_evaluator = all_evaluator
    page = request.GET.get('page', 1)
    paginator = Paginator(all_evaluator, 10)
    try:
        all_evaluator = paginator.page(page)
    except PageNotAnInteger:
        all_evaluator = paginator.page(1)
    except EmptyPage:
        all_evaluator = paginator.page(paginator.num_pages)

    index = all_evaluator.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['all_evaluator'] = all_evaluator
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'evalutor/evalutor_list.html', context)


def section_evaluator(request):
    """ get the section evaluator based on the section id """
    section_id = request.GET.get('section_id', None)
    evalutor_id = request.GET.get('evalutor_id', None)

    eval_and_invite_evals = []
    section_evaluators = Evaluator.objects.filter(status__iexact='active', section__id=section_id)
    for evaluator in section_evaluators:
        if evaluator.membership:
            eval_and_invite_evals.append({
                'id': evaluator.id,
                'membership__user__first_name' : evaluator.membership.user.first_name,
                'membership__user__last_name' : evaluator.membership.user.last_name,
            })
        elif hasattr(evaluator, 'invite'):
            eval_and_invite_evals.append({
                'id': evaluator.id,
                'membership__user__first_name' : evaluator.invite.first_name,
                'membership__user__last_name' : evaluator.invite.last_name,
            })
        
        
    # real_s_e = []
    # for evaluator in section_evaluators:
    #     if evaluator.membership.user.freepaper_set.count() <= 0 and evaluator.membership.user.instructioncourse_set.count() <= 0 and evaluator.membership.user.video_set.count() <= 0:
    #         real_s_e.append(evaluator)

    data = {
        'result': 'success',
        'section_evaluator': eval_and_invite_evals
    }
    return JsonResponse(data)


def accept_invite(request, id):
    activate_eva = Evaluator.objects.get(id=id)
    logger.info(activate_eva.status)
    # if request.method=='POST':
    activate_eva.status = PAPER_STATUS['ACTIVE']
    activate_eva.save()
    messages.success(request, 'Evaluator activated successfully!')
    return HttpResponseRedirect('http://scientific.kosonline.org/')


import string

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

@login_required
def evalutor_add(request):
    """
    Admin will invite kos evaluator
    send cc mail to member to become evaluator
    """
    if request.method == 'POST':
        evaluator_add_form = EvaluatorAddForm(request.POST)
        evaluator_add_form.fields['membership'].queryset = MemberShip.objects.filter(is_member=True)
        if evaluator_add_form.is_valid():
            evaluator = evaluator_add_form.save(commit=True)
            evaluator.status = PAPER_STATUS['INACTIVE']
            evaluator.mail_status = Evaluator.NOT_SENT
            evaluator.save()
        else:
            evaluator_add_form.fields['membership'].queryset = MemberShip.objects.none()
            
            context = {
                'form': evaluator_add_form,
                'already_selected_members': list(MemberShip.objects.exclude(evaluator__isnull = True).values_list('id', flat=True)),
                'sections': Section.objects.filter(status__iexact="active"),
                'members': json.dumps(list(MemberShip.objects.filter(is_member=True).order_by('created_at').values('id', 'user__first_name', 'user__last_name','user__profile__mobile_number', 'kos_no' )))
            }
            return render(request, 'evalutor/kos_evaluator_add.html', context)


        # admin will invite via mail
        email = [evaluator.membership.user.email, ]

        try:
            # send sms to evaluator
            message = smsBody.objects.get(smskey__iexact=SmsForm.KOS_EVALUATOR_INVITE)
            send_sms(message.smscontent, evaluator.membership.user.profile.mobile_number)
        except Exception as e:
            logger.warning('admin unable to send evaluator invite sms to member')

        try:
            oneTimeLink = OneTimeLink()
            oneTimeLink.name = "evaluator add link"
            oneTimeLink.token = id_generator(50)
            oneTimeLink.save()

            kwargs = {
                "uidb64": urlsafe_base64_encode(force_bytes(evaluator.membership.user.pk)),
                "evaluator_id": urlsafe_base64_encode(force_bytes(evaluator.pk)),
                "token": oneTimeLink.token,
                "opinion": 'accept'
            }

            confirm_url = reverse("koscientific:confirm_evaluator", kwargs=kwargs)
            confirm_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), confirm_url)

            kwargs['opinion'] = 'reject'
            reject_link = reverse("koscientific:confirm_evaluator", kwargs=kwargs)
            reject_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), reject_link)

            email_context = {
                'evaluator': evaluator,
                'sections': evaluator.section.all(),
                'accept_url': confirm_url,
                'reject_url': reject_url
            }
            html_message = render_to_string('emails/evaluator/kos_evaluator_invite.html', email_context)
            plain_message = strip_tags(html_message)
            
            officials_mails = [settings.INFO_KOS_ONLINE_MAIL, settings.SCIENTIFIC_CHAIRMAN]
            # send cc mail to member to become evaluator
            mail_dict = {
                'subject': "Invitation to Evaluator",
                'plain_message': plain_message,
                'html_message': html_message,
                'to': ['{}'.format(evaluator.membership.user.email)],
                'cc': officials_mails,
            }
            KosEmail.send_multi_alternatives_email(**mail_dict)
            evaluator.mail_status = Evaluator.NO_ANSWER
            evaluator.save()
        
            evaluator_email_reminder = EvaluatorEmailAduit()
            evaluator_email_reminder.evaluator = evaluator
            evaluator_email_reminder.one_time_link = oneTimeLink
            evaluator_email_reminder.save()
        except Exception as e:
            logger.warning('unable to send mail invite evaluator to evaluator')

        # web socket notification
        message = "Your invited as evaluated by {} {} for sections".format(request.user.first_name,
                                                                            request.user.last_name)
        WebNotification(request.user).send_only_notification_to_user([evaluator.membership.user], message)

        messages.success(request, 'Evaluator invited successfully!')
        return HttpResponseRedirect(reverse('koscientific:evaluter_list'))

    form = EvaluatorAddForm()
    context = {
        'form': form,
        'already_selected_members': list(MemberShip.objects.exclude(evaluator__isnull = True).values_list('id', flat=True)),
        'sections': Section.objects.filter(status__iexact="active"),
        'members': json.dumps(list(MemberShip.objects.filter(is_member=True).order_by('created_at').values('id', 'user__first_name', 'user__last_name','user__profile__mobile_number', 'kos_no' )))
        
    }
    return render(request, 'evalutor/kos_evaluator_add.html', context)


def is_token_expired(token):
    one_time_link = OneTimeLink.objects.get(token=token)
    start_time = one_time_link.created_at
    from datetime import datetime, timedelta

    end_time = start_time + timedelta(days=settings.ONE_TIME_LINK_VALID_UPTO)
    if timezone.now() > end_time:
        return True
    return False


def confirm_evaluator(request, uidb64=None, evaluator_id=None, token=None, opinion=None):
    """
    Take member opinion to become evaluator
    """
    if OneTimeLink.objects.filter(token=token).exists() and not is_token_expired(token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            evaluator_id = force_text(urlsafe_base64_decode(evaluator_id))
            evaluator = Evaluator.objects.get(pk=evaluator_id)
        except User.DoesNotExist:
            return HttpResponse("This link is not associated with anything")

        if opinion.lower() == 'accept':
            evaluator.status = PAPER_STATUS['ACTIVE']
            evaluator.save()
            # assign new role
            user.roles.clear()
            user.roles.add(Role.EVALUATOR)
            user.groups.clear()
            member_group = Group.objects.get(name__iexact='Evaluator')
            user.groups.add(member_group)
            OneTimeLink.objects.filter(token=token).delete()
            messages.success(request, 'Congratulations now you become evaluator')
        elif opinion.lower() == 'reject':
            evaluator.status = "rejected"
            evaluator.save()
            OneTimeLink.objects.filter(token=token).delete()
            messages.warning(request, 'You are rejected to become evaluator')
        return redirect('koscientific:home')
    else:
        return HttpResponse("Activation link has expired")


@login_required
def Evaluator_edit(request, evaluator_id):
    eval_edit = Evaluator.objects.get(id=evaluator_id)
    form = EvaluatorEditForm(request.POST or None, instance=eval_edit)
    if request.method == 'POST':
        if form.is_valid():
            form.save()
            messages.success(request, 'Evaluator updated successfully!')
            return HttpResponseRedirect(reverse('koscientific:evaluter_list'))
        else:
            context = {
                'form': form
            }
            return render(request, 'evalutor/evalutor_edit.html', context)

    context = {
        'form': form
    }
    return render(request, 'evalutor/evalutor_edit.html', context)


@login_required
def Asigned_to_instruction(request):
    if request.method == "POST":
        assign = AssignedTo.objects.get(id=request.POST['id'])
        assign.evulator_id = request.POST['evulator']
        assign.status = 'Reassigned'
        assign.save()
        messages.success(request, 'Reassigned  Successfully')

    context = {}

    if request.GET.get('section'):
        section_filter = request.GET.get('section')
        if User.objects.filter(email=request.user.email, roles__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN ]):
            inst_assign = AssignedTo.objects.filter(evulator__section__id=request.GET.get('section'))
        else:
            inst_assign = AssignedTo.objects.filter(evulator__membership__user=request.user,
                                                    evulator__section__id=request.GET.get('section'))
        # else:
        #     inst_assign = AssignedTo.objects.filter(evulator__membership__user = request.user , evulator__section__id=request.GET.get('section'))
    else:

        if request.user.roles.filter(pk__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN]).exists():
            inst_assign = AssignedTo.objects.all().order_by('-created_at')
            logger.info('inst_assign for admin :', inst_assign)

        elif request.user.roles.filter(pk=Role.EVALUATOR).exists():
            if request.user.groups.filter(name__iexact='evaluator').exists():
                inst_assign = AssignedTo.objects.filter(evulator__membership__user=request.user).order_by('-created_at')
            elif request.user.groups.filter(name__iexact='Evaluator_non_member').exists():
                inst_assign = AssignedTo.objects.filter(evulator__invite__email=request.user.email).order_by('-created_at')
        else:
            messages.error(request, 'Not Permission')
    count = inst_assign.count()
    ic = InstructionCourse.objects.all()
    eva = Evaluator.objects.filter(status__iexact='active')
    sec = Section.objects.all()
    logger.info(sec)
    inst_assign = inst_assign
    page = request.GET.get('page', 1)
    paginator = Paginator(inst_assign, 10)
    try:
        inst_assign = paginator.page(page)
    except PageNotAnInteger:
        inst_assign = paginator.page(1)
    except EmptyPage:
        inst_assign = paginator.page(paginator.num_pages)

    index = inst_assign.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index

    context['count'] = count
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    context['inst_assign'] = inst_assign
    context['eva'] = eva
    context['ic'] = ic
    context['sec'] = sec
    return render(request, 'member/assign_to_InstructionCourse.html', context)


def Add_marks(request, id):
    """
    save marks and send mail to admin if percentage difference bewteen marks
    more than 30%
    """
    context = {}
    res = AssignedTo.objects.get(id=id)
    if request.method == 'POST':
        ic_marks = IcEvalMarks()
        ic_marks.assigned = res
        ic_marks.name = 'title'
        ic_marks.marks = request.POST['title']
        ic_marks.remarks = request.POST['title_remarks']
        ic_marks.save()

        ic_marks = IcEvalMarks()
        ic_marks.assigned = res
        ic_marks.name = 'heading'
        ic_marks.marks = request.POST['heading']
        ic_marks.remarks = request.POST['heading_remarks']
        ic_marks.save()

        ic_marks = IcEvalMarks()
        ic_marks.assigned = res
        ic_marks.name = 'synopsis'
        ic_marks.marks = request.POST['synopsis']
        ic_marks.remarks = request.POST['synopsis_remarks']
        ic_marks.save()

        ic_marks = IcEvalMarks()
        ic_marks.assigned = res
        ic_marks.name = 'originality'
        ic_marks.marks = request.POST['originality']
        ic_marks.remarks = request.POST['originality_remarks']
        ic_marks.save()

        ic_marks = IcEvalMarks()
        ic_marks.assigned = res
        ic_marks.name = 'content'
        ic_marks.marks = request.POST['content']
        ic_marks.remarks = request.POST['content_remarks']
        ic_marks.save()

        total_marks = res.ic_marks.all().aggregate(total_marks=Sum('marks')).get('total_marks')
        res.marks = total_marks
        res.save()
        all_marks = res.ic.assignedto_set.all().values_list('marks', flat=True)
        all_marks =  [x for x in all_marks if x]
        if len(all_marks) == len(list(res.ic.assignedto_set.all().values_list('marks', flat=True))):
            res.ic.status = "Evaluated"
        else:
            res.ic.status = "Evaluated by E{}".format(len(all_marks))
        # res.ic.status = PAPER_STATUS['EVALUATED']
        res.ic.save()
        
        # marks compare
        others_marks = res.ic.assignedto_set.all().exclude(id=res.id).values_list('marks', flat=True)
        others_marks = [x for x in others_marks if x]
        if others_marks:
            for marks in others_marks:
                percentage_difference = calculate_percentage_difference(total_marks, marks)
                if percentage_difference > settings.PERCENTAGE_DIFFERENCE:
                    logger.warning('evaluator {} given marks {} is making huge difference'.format(res.evulator, total_marks))
                    # send mail to admin
                    try:
                        if res.evulator.membership:
                            evaluator_name = res.evulator.membership.user.first_name+" "+res.evulator.membership.user.last_name
                        elif res.evulator.invite:
                            evaluator_name = "{} {}".format(res.evulator.invite.first_name, res.evulator.invite.last_name)
                        else:
                            evaluator_name = ""
                        email_subject = "Marks difference alert"
                        mailcontent = """Hi, For the paper {} evaluator {} given marks {}, which is making making difference of more than {} compare
                        to others already given marks that is {} """.format(res.ic.unique_id,
                                                                            evaluator_name,
                                                                            total_marks,
                                                                            settings.PERCENTAGE_DIFFERENCE,
                                                                            others_marks)
                        officials_mails = [settings.SECRETARY_MAIL]
                        mail_dict = {
                            'subject': email_subject,
                            'plain_message': mailcontent,
                            'html_message': mailcontent,
                            'recipient_list': officials_mails, 
                        }
                        KosEmail.send_mail_altered(**mail_dict)
                        logger.warning('sent marks warning to admin')
                    except Exception as e:
                        logger.info('unable to send the marks difference email to admin {}'.format(e))
                        
                    break;

        messages.success(request, 'marks assigned')
        return HttpResponseRedirect(reverse('koscientific:assign_to_instruction_course'))

    context['res'] = res
    return render(request, 'instructioncourse/add_marks_ins_course.html', context)

def calculate_percentage_difference(marks1, marks2):
    # Step 1: The difference is 4 − 6 = −2, but ignore the minus sign: difference=2
    # Step 2: The average is (4 + 6)/2 = 10/2 = 5
    # Step 2: Divide: 2/5 = 0.4
    # Step 3: Convert 0.4 to percentage: 0.4×100 = 20%.
    difference = abs(marks1 - marks2)
    average = (marks1+marks2)/2
    divided = difference/average
    convert_to_percentage = (divided*100)
    return convert_to_percentage
    
@login_required
def Asigned_to_freePaper(request):
    if request.method == "POST":
        assign = AssignedFreePaper.objects.get(id=request.POST['id'])
        assign.evulator_id = request.POST['evulator']
        assign.status = 'Reassigned'
        assign.save()
        messages.success(request, 'Reassigned  Successfully')

    context = {}

    if request.GET.get('section'):
        section_filter = request.GET.get('section')
        logger.info(section_filter)
        if User.objects.filter(email=request.user.email, roles__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN ]):
            inst_assign = AssignedFreePaper.objects.filter(evulator__section__id=request.GET.get('section'))
        else:
            inst_assign = AssignedFreePaper.objects.filter(evulator__membership__user=request.user,
                                                           evulator__section__id=request.GET.get('section'))

    else:

        if request.user.roles.filter(pk__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN]).exists():
            inst_assign = AssignedFreePaper.objects.all().order_by('-created_at')

        elif request.user.roles.filter(pk=Role.EVALUATOR).exists():
            if request.user.groups.filter(name__iexact='evaluator').exists():
                inst_assign = AssignedFreePaper.objects.filter(evulator__membership__user=request.user).order_by(
                    '-created_at')
            elif request.user.groups.filter(name__iexact='Evaluator_non_member').exists():
                inst_assign = AssignedFreePaper.objects.filter(evulator__invite__email=request.user.email).order_by('-created_at')
        else:
            messages.error(request, 'Not Permission')
    count = inst_assign.count()
    ic = FreePaper.objects.all()
    eva = Evaluator.objects.all()
    sec = Section.objects.all()
    inst_assign = inst_assign
    page = request.GET.get('page', 1)
    paginator = Paginator(inst_assign, 10)
    try:
        inst_assign = paginator.page(page)
    except PageNotAnInteger:
        inst_assign = paginator.page(1)
    except EmptyPage:
        inst_assign = paginator.page(paginator.num_pages)

    index = inst_assign.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    context['assigned_free_papers'] = inst_assign
    context['eva'] = eva
    context['ic'] = ic
    context['sec'] = sec
    return render(request, 'freepaper/assign_to_freepaper.html', context)


def Add_marks_freepaper(request, id):
    """
    save marks and send mail to admin if percentage difference bewteen marks
    more than 30%
    """
    context = {}
    res = AssignedFreePaper.objects.get(id=id)
    if request.method == 'POST':
        fp_marks = FreePaperEvalMarks()
        fp_marks.assigned = res
        fp_marks.name = 'title'
        fp_marks.remarks = request.POST['title_remarks']
        fp_marks.marks = request.POST['title']
        fp_marks.save()

        fp_marks = FreePaperEvalMarks()
        fp_marks.assigned = res
        fp_marks.name = 'heading'
        fp_marks.marks = request.POST['heading']
        fp_marks.remarks = request.POST['heading_remarks']
        fp_marks.save()

        fp_marks = FreePaperEvalMarks()
        fp_marks.assigned = res
        fp_marks.name = 'synopsis'
        fp_marks.marks = request.POST['synopsis']
        fp_marks.remarks = request.POST['synopsis_remarks']
        fp_marks.save()

        fp_marks = FreePaperEvalMarks()
        fp_marks.assigned = res
        fp_marks.name = 'originality'
        fp_marks.marks = request.POST['originality']
        fp_marks.remarks = request.POST['originality_remarks']
        fp_marks.save()

        fp_marks = FreePaperEvalMarks()
        fp_marks.assigned = res
        fp_marks.name = 'content'
        fp_marks.marks = request.POST['content']
        fp_marks.remarks = request.POST['content_remarks']
        fp_marks.save()

        total_marks = res.ic_marks.all().aggregate(total_marks=Sum('marks')).get('total_marks')
        res.marks = total_marks
        res.save()
        all_marks = res.fp.assignedfreepaper_set.all().values_list('marks', flat=True)
        all_marks =  [x for x in all_marks if x]
        if len(all_marks) == len(list(res.fp.assignedfreepaper_set.all().values_list('marks', flat=True))):
            res.fp.status = "Evaluated"
        else:
            res.fp.status = "Evaluated by E{}".format(len(all_marks))
        # res.ic.status = PAPER_STATUS['EVALUATED']
        res.fp.save()
        
        # marks compare
        others_marks = res.fp.assignedfreepaper_set.all().exclude(id=res.id).values_list('marks', flat=True)
        others_marks = [x for x in others_marks if x]
        if others_marks:
            for marks in others_marks:
                percentage_difference = calculate_percentage_difference(total_marks, marks)
                if percentage_difference > settings.PERCENTAGE_DIFFERENCE:
                    logger.warning('evaluator {} given marks {} is making huge difference'.format(res.evulator, total_marks))
                    # send mail to admin
                    try:
                        if res.evulator.membership:
                            evaluator_name = res.evulator.membership.user.first_name+" "+res.evulator.membership.user.last_name
                        elif res.evulator.invite:
                            evaluator_name = "{} {}".format(res.evulator.invite.first_name, res.evulator.invite.last_name)
                        else:
                            evaluator_name = ""
                        email_subject = "Marks difference alert"
                        mailcontent = """Hi, For the paper {} evaluator {} given marks {}, which is making making difference of more than {} compare
                        to others already given marks that is {} """.format(res.fp.unique_id,
                                                                            evaluator_name,
                                                                            total_marks,
                                                                            settings.PERCENTAGE_DIFFERENCE,
                                                                            others_marks)
                        officials_mails = [settings.SECRETARY_MAIL]
                        mail_dict = {
                            'subject': email_subject,
                            'plain_message': mailcontent,
                            'html_message': mailcontent,
                            'recipient_list': officials_mails, 
                        }
                        KosEmail.send_mail_altered(**mail_dict)
                        logger.warning('sent marks warning to admin')
                    except Exception as e:
                        logger.info('unable to send the marks difference email to admin {}'.format(e))
                        
                    break;

        messages.success(request, 'marks assigned')
        return HttpResponseRedirect(reverse('koscientific:assign_to_freepaper'))

    context['res'] = res
    return render(request, 'freepaper/add_marks_freepaper.html', context)


@login_required
def Asigned_to_video(request):
    if request.method == "POST":
        assign = AssignedVideo.objects.get(id=request.POST['id'])
        assign.evaluator_id = request.POST['evulator']
        assign.status = 'Reassigned'
        assign.save()
        messages.success(request, 'Reassigned  Successfully')

    context = {}

    if request.GET.get('section'):
        section_filter = request.GET.get('section')
        logger.info(section_filter)
        if User.objects.filter(email=request.user.email, roles__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN ]):
            inst_assign = AssignedVideo.objects.filter(evaluator__section__id=request.GET.get('section'))
        else:
            inst_assign = AssignedVideo.objects.filter(evaluator__membership__user__email=request.user,
                                                       evaluator__section__id=request.GET.get('section'))

    else:

        if request.user.roles.filter(pk__in=[Role.ADMIN, Role.SCIENTIFIC_ADMIN]).exists():
            inst_assign = AssignedVideo.objects.all().order_by('-created_at')
        elif request.user.roles.filter(pk=Role.EVALUATOR).exists():
            if request.user.groups.filter(name__iexact='evaluator').exists():
                inst_assign = AssignedVideo.objects.filter(evaluator__membership__user__email=request.user).order_by('-created_at')
            elif request.user.groups.filter(name__iexact='Evaluator_non_member').exists():
                inst_assign = AssignedVideo.objects.filter(evaluator__invite__email=request.user.email).order_by('-created_at')
        else:
            messages.error(request, 'Not Permission')
    count = inst_assign.count()
    ic = Video.objects.all()
    eva = Evaluator.objects.all()
    sec = Section.objects.all()
    page = request.GET.get('page', 1)
    paginator = Paginator(inst_assign, 10)
    try:
        inst_assign = paginator.page(page)
    except PageNotAnInteger:
        inst_assign = paginator.page(1)
    except EmptyPage:
        inst_assign = paginator.page(paginator.num_pages)

    index = inst_assign.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index

    context['count'] = count
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    context['assigned_videos'] = inst_assign
    context['eva'] = eva
    context['ic'] = ic
    context['sec'] = sec
    return render(request, 'video/assign_to_video.html', context)


def Add_marks_video(request, id):
    """
    save marks and send mail to admin if percentage difference bewteen marks
    more than 30%
    """
    context = {}
    res = AssignedVideo.objects.get(id=id)
    if request.method == 'POST':
        video_marks = VideoPaperEvalMarks()
        video_marks.assigned = res
        video_marks.name = 'title'
        video_marks.marks = request.POST['title']
        video_marks.remarks = request.POST['title_remarks']
        video_marks.save()

        video_marks = VideoPaperEvalMarks()
        video_marks.assigned = res
        video_marks.name = 'heading'
        video_marks.marks = request.POST['heading']
        video_marks.remarks = request.POST['heading_remarks']
        video_marks.save()

        video_marks = VideoPaperEvalMarks()
        video_marks.assigned = res
        video_marks.name = 'synopsis'
        video_marks.marks = request.POST['synopsis']
        video_marks.remarks = request.POST['synopsis_remarks']
        video_marks.save()

        video_marks = VideoPaperEvalMarks()
        video_marks.assigned = res
        video_marks.name = 'originality'
        video_marks.marks = request.POST['originality']
        video_marks.remarks = request.POST['originality_remarks']
        video_marks.save()

        video_marks = VideoPaperEvalMarks()
        video_marks.assigned = res
        video_marks.name = 'content'
        video_marks.marks = request.POST['content']
        video_marks.remarks = request.POST['content_remarks']
        video_marks.save()

        total_marks = res.ic_marks.all().aggregate(total_marks=Sum('marks')).get('total_marks')
        res.marks = total_marks
        res.save()
        
        all_marks = res.vd.assignedvideo_set.all().values_list('marks', flat=True)
        all_marks =  [x for x in all_marks if x]
        if len(all_marks) == len(list(res.vd.assignedvideo_set.all().values_list('marks', flat=True))):
            res.vd.status = "Evaluated"
        else:
            res.vd.status = "Evaluated by E{}".format(len(all_marks))
        # res.ic.status = PAPER_STATUS['EVALUATED']
        res.vd.save()
        
        # marks compare
        others_marks = res.vd.assignedvideo_set.all().exclude(id=res.id).values_list('marks', flat=True)
        others_marks = [x for x in others_marks if x]
        if others_marks:
            for marks in others_marks:
                percentage_difference = calculate_percentage_difference(total_marks, marks)
                if percentage_difference > settings.PERCENTAGE_DIFFERENCE:
                    logger.warning('evaluator {} given marks {} is making huge difference'.format(res.evaluator, total_marks))
                    # send mail to admin
                    try:
                        if res.evaluator.membership:
                            evaluator_name = res.evaluator.membership.user.first_name+" "+res.evaluator.membership.user.last_name
                        elif res.evaluator.invite:
                            evaluator_name = "{} {}".format(res.evaluator.invite.first_name, res.evaluator.invite.last_name)
                        else:
                            evaluator_name = ""
                        email_subject = "Marks difference alert"
                        mailcontent = """Hi, For the paper {} evaluator {} given marks {}, which is making making difference of more than {} compare
                        to others already given marks that is {} """.format(res.vd.unique_id,
                                                                            evaluator_name,
                                                                            total_marks,
                                                                            settings.PERCENTAGE_DIFFERENCE,
                                                                            others_marks)
                        officials_mails = [settings.SECRETARY_MAIL]
                        mail_dict = {
                            'subject': email_subject,
                            'plain_message': mailcontent,
                            'html_message': mailcontent,
                            'recipient_list': officials_mails, 
                        }
                        KosEmail.send_mail_altered(**mail_dict)
                        logger.warning('sent marks warning to admin')
                    except Exception as e:
                        logger.info('unable to send the marks difference email to admin {}'.format(e))
                        
                    break;

        messages.success(request, 'marks assigned')
        return HttpResponseRedirect(reverse('koscientific:assign_to_video'))

    context['res'] = res
    return render(request, 'video/add_marks_video.html', context)


def Asigned_to_evaluator(request):
    return render(request, 'member/assign_evaluator.html', {})


def Asigned_to_evaluator_free_pater(request):
    return render(request, 'member/FreePaperAssign.html', {})


def Assign_poster_paper(request):
    return render(request, 'member/Poster_paper_assign.html', {})


def Assign_video_paper(request):
    return render(request, 'member/Assign_Video.html', {})


def Section_list(request):
    list_of_section = Section.objects.all().order_by('-created_at')
    count = list_of_section.count()
    context = {
        'list_of_section': list_of_section,
    }
    list_of_section = list_of_section
    page = request.GET.get('page', 1)
    paginator = Paginator(list_of_section, 10)
    try:
        list_of_section = paginator.page(page)
    except PageNotAnInteger:
        list_of_section = paginator.page(1)
    except EmptyPage:
        list_of_section = paginator.page(paginator.num_pages)

    index = list_of_section.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['list_of_section'] = list_of_section
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'master/section/section_list.html', context)


def Section_add(request):
    if request.method == 'POST':
        # get html form input name
        section_name = request.POST['section_name']
        status = request.POST['status']
        # select db_model to save request input
        if section_name == '':
            messages.error(request, 'Please fill all the fields!')
        else:
            add_section = Section(section_name=section_name, status=status)
            add_section.save()
            messages.success(request, 'Section added successfully!')
            # go to list view
            return HttpResponseRedirect(reverse('koscientific:section_list'))

    return render(request, 'master/section/section_add.html')


def Section_edit(request, section_id):
    section_update = Section.objects.get(id=section_id)
    if request.method == 'POST':
        section_update.section_name = request.POST['section_name']
        section_update.status = request.POST['status']
        section_update.save()
        return HttpResponseRedirect(reverse('koscientific:section_list'))
    context = {
        'section_update': section_update,
    }

    return render(request, 'master/section/section_edit.html', context)


def MemberList(request):
    context = {}
    member = MemberShip.all_objects.filter(is_iis_signed=True).order_by('-created_at')
    count = member.count()
    # member = MemberShip.objects.filter(user__roles__in=[Role.MEMBER, ]).order_by('-created_at')
    search = request.GET.get('search')
    if search != '' and search is not None:
        member = member.filter(
            Q(user__first_name__icontains=search) | Q(user__last_name__icontains=search) |
            Q(user__email__icontains=search) | Q(mobile__icontains=search) |
            Q(is_active__icontains=search) | Q(kos_no__icontains=search)).distinct()
    else:
        member = member
    member = member
    page = request.GET.get('page', 1)
    paginator = Paginator(member, 10)
    try:
        member = paginator.page(page)
    except PageNotAnInteger:
        member = paginator.page(1)
    except EmptyPage:
        member = paginator.page(paginator.num_pages)

    index = member.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    logger.info(count)
    context['count'] = count
    context['member'] = member
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    context['deceased_membership_model'] = DeceasedMembership
    context['resign_membership_model'] = MemberResign

    return render(request, 'member/member_list.html', context)


def MemberApplication(request):
    context = {}
    member = MemberShip.all_objects.filter(membership_detail__admin_status=MembershipDetail.NO_ANSWER).order_by(
        '-created_at')
    # member = MemberShip.objects.filter(user__roles__in=[Role.REGISTERED, ]).order_by('-created_at')
    count = member.count()
    member = member
    page = request.GET.get('page', 1)
    paginator = Paginator(member, 10)
    try:
        member = paginator.page(page)
    except PageNotAnInteger:
        member = paginator.page(1)
    except EmptyPage:
        member = paginator.page(paginator.num_pages)

    index = member.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    context['member'] = member
    context['membership_detail_constants'] = MembershipDetail
    return render(request, 'member/member_application_list.html', context)


@login_required
def payment_capture(request):
    """
    capture payment then send introducer mail and other mails
    """
    try:
        client = razorpay.Client(auth=(settings.RAZOR_PAY_KEY, settings.RAZOR_PAY_SECRET))
        client_order = client.order.fetch(order_id=request.POST["razorpay_order_id"])
        order = get_object_or_404(Order, membership=request.user.membership, order_id=request.POST["razorpay_order_id"])
        order.transaction = request.POST["razorpay_payment_id"]
        order.status = client_order['status']
        order.amount_paid = client_order['amount_paid']
        order.amount_due = client_order['amount_due']
        order.save()
        
        if not order.amount_due == 0.00:
            context = {'Error': 'Transaction failed'}
            return JsonResponse(context, status=200)
        request.user.membership.status = "completed"
        request.user.membership.save()
        
        if hasattr(request.user.membership, 'membership_status'):
            membership_status = request.user.membership.membership_status
        else:
            membership_status = MembershipStatus()
            membership_status.membership = request.user.membership
        membership_status.status = "We are awaiting for confirmation from your introducers"
        membership_status.save()
        
        try:
            # send membership form success submission sms to user
            message = smsBody.objects.get(smskey__iexact=SmsForm.USER_MEMBERSHIP_SUBMISSION)
            send_sms(message.smscontent, request.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send the membership sms to user {}'.format(e))

        try:
            # send membership form success submission mail to user
            mailcontent = Mail.objects.get(name__iexact=MailForm.MEMBERSHIP_CONFIRMATION_SUBMISSION_TO_USER)
            provisional_membership_id = "P{}".format(request.user.membership.id)
            email_body = mailcontent.email_body.replace('{{provisional_membership_id}}', provisional_membership_id)
            mail_dict = {
                'subject': mailcontent.email_subject,
                'plain_message': strip_tags(email_base_template(email_body)) ,
                'html_message': email_base_template(email_body),
                'recipient_list': '{}'.format(request.user.email),
            }
            KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send the membership email to user {}'.format(e))

        try:
            # send membership details as mail to introducer
            introducer_one = request.user.membership.membership_detail.introducer_one
            introducer_two = request.user.membership.membership_detail.introducer_two
            
            introducers = [introducer_one, introducer_two]
            for introducer in introducers:
                
                oneTimeLink = OneTimeLink()
                oneTimeLink.name = "membership confirmation from introducer"
                oneTimeLink.token = id_generator(50)
                oneTimeLink.save()

                kwargs = {
                    "uidb64": urlsafe_base64_encode(force_bytes(request.user.membership.id)),
                    "introducer_id": urlsafe_base64_encode(force_bytes(introducer.pk)),
                    "token": oneTimeLink.token,
                    "opinion": 'accept'
                }

                accept_link = reverse("koscientific:confirm_membership", kwargs=kwargs)
                accept_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), accept_link)
                kwargs['opinion'] = 'reject'
                reject_link = reverse("koscientific:confirm_membership", kwargs=kwargs)
                reject_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), reject_link)

                email_context = {
                    'member': request.user.membership,
                    'accept_url': accept_url,
                    'reject_url': reject_url,
                    'introducer': introducer,
                }

                # html_message = render_to_string('emails/introducer/introducer_mem_accept_or_reject_mail.html',
                #                                 email_context)
                # plain_message = strip_tags(html_message)
                
                mail = Mail.objects.get(name__iexact=MailForm.USER_MEMBERSHIP_SUBMISSION_INTRODUCER_MESSAGE)
                user_full_name = '{} {}'.format(request.user.membership.user.first_name, request.user.membership.user.last_name)
                introducer_full_name = '{} {}'.format(introducer.user.first_name, introducer.user.last_name)
                email_body = mail.email_body.replace('{{introducer_full_name}}', introducer_full_name)
                email_body = email_body.replace('{{user_full_name}}', user_full_name)
                email_body = email_body.replace('{{accept}}', accept_url)
                email_body = email_body.replace('{{reject}}', reject_url)
                
                mail_dict = {
                    'subject': mail.email_subject.replace('{{user_full_name}}', user_full_name),
                    'html_message': email_base_template(email_body),
                    'plain_message': strip_tags(email_base_template(email_body)),
                    'recipient_list': '{}'.format(introducer.user.email)
                }
                KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send the mail from applicant membership details to introducer {} {}'.format(introducer.user, e))
            
        try:
            # send applicant membership details to introducer as sms
            message = smsBody.objects.get(smskey__iexact=SmsForm.USER_MEMBERSHIP_SUBMISSION_INTRODUCER_MESSAGE)
            message = message.smscontent.replace("{{applicant_mail_id}}", request.user.email)
            send_sms(message, introducer_one.user.profile.mobile_number)
            send_sms(message, introducer_two.user.profile.mobile_number)
        except Exception as e:
            logger.error('unable to send the membership sms to introducer {}'.format(e))
            
        
        try:
            # trigger payment capture sms to applicant
            message = smsBody.objects.get(smskey__iexact=SmsForm.PAYMENT_CAPTURE_TO_USER)
            send_sms(message.smscontent, request.user.profile.mobile_number)
        except Exception as e:
            logger.info('unable to send sms the payment successfull to user {}'.format(e))

        try:
            # trigger payment capture mail to applicant
            mailcontent = Mail.objects.get(name__iexact=MailForm.PAYMENT_CAPTURE_TO_USER)
            mail_dict = {
                'subject': mailcontent.email_subject,
                'plain_message': strip_tags(email_base_template(mailcontent.email_body)),
                'html_message': email_base_template(mailcontent.email_body),
                'recipient_list': '{}'.format(request.user.email)
            }
            KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send the payment successfully email to user {}'.format(e))

        try:
            # trigger payment capture mail to kosinfo
            mailcontent = Mail.objects.get(name__iexact=MailForm.PAYMENT_CAPTURE_TO_KOS_INFO)
            member_full_name = "{} {}".format(request.user.first_name, request.user.last_name)
            email_body = mailcontent.email_body.replace('{{member_full_name}}', member_full_name)
            mail_dict = {
                'subject': mailcontent.email_subject,
                'plain_message': strip_tags(email_base_template(email_body)),
                'html_message': email_base_template(email_body),
                'recipient_list': '{}'.format(settings.INFO_KOS_ONLINE_MAIL)
            }
            KosEmail.send_mail(**mail_dict)
        except Exception as e:
            logger.info('unable to send the payment successfully email to info@kosonline.org {}'.format(e))
        
        try:
            # web socket notification to user
            message = "Membership form submitted successfully"
            WebNotification().send_only_notification_to_user([request.user], message)
        except Exception as e:
            logger.info('unable to send socket notification user {}'.format(e))
            
        context = {
            'success': True,
            'razor_payment_id': order.transaction
        }
        return JsonResponse(context, status=200)

    except Exception as e:
        logger.error('exception occurs after payment processing {}'.format(e))
        return JsonResponse({'Error': 'Transaction failed'}, status=400)


def Member_view(request, mem_id):
    mem_view = MemberShip.objects.get(id=mem_id)
    context = {
        'mem_view': mem_view,
    }
    return render(request, 'member/member_view.html', context)


@permission_required('koscientific.approve_user', raise_exception=True)
def ActivateMember(request, id):
    member = MemberShip.objects.get(id=id)
    max_membership = MemberShip.objects.aggregate(Max('kos_no'))
    member.kos_no = max_membership['kos_no__max'] + 1
    member.is_active = False
    member.is_member = False
    if member.membership_detail:
        member.membership_detail.is_admin_approved = True
        member.membership_detail.save()
    # member.user.roles.clear()
    # member.user.roles.add(Role.MEMBER)
    # member_group = Group.objects.get(name__iexact='member')
    # member.user.groups.clear()
    # member.user.groups.add(member_group)
    member.save()

    messages.success(request,
                     'member: {} membership number {} assigned successfully'.format(member.user.email, member.kos_no))
    return HttpResponseRedirect(reverse('koscientific:member_list'))


def MemberDetails(request, id):
    context = {}
    member = MemberShip.all_objects.get(id=id)

    if DeceasedMembership.objects.filter(membership_id=id).exists():
        deceased_member = DeceasedMembership.objects.get(membership_id=id)
        context['deceased_member'] = deceased_member
    if MemberResign.objects.filter(membership_id=id).exists():
        member_resign = MemberResign.objects.get(membership_id=id)
        context['member_resign'] = member_resign

    logger.info(member.photo)
    if member.photo == '' or None:
        member.photo = 'Not Given'
    else:
        member.phot = member.photo
    if member.certificate == '' or None:
        member.certificate = 'Not Given'
    else:
        member.certificate

    context['member'] = member

    return render(request, 'member/member_details.html', context)


@login_required
def profile(request):
    admin_profile = request.user
    number = Profile.objects.get(user=request.user)
    profile_data = {
        'username': admin_profile.username,
        'first_name': admin_profile.first_name,
        'last_name': admin_profile.last_name,
        'email': admin_profile.email,
        'mobile_number': number.mobile_number,
        'profile_photo': number

    }
    return render(request, 'profile/profile.html', profile_data)


def member_profile(request):
    admin_profile = request.user
    membership = MemberShip.objects.get(user=request.user)
    number = Profile.objects.get(user=request.user)
    profile_data = {
        'username': admin_profile.username,
        'first_name': admin_profile.first_name,
        'last_name': admin_profile.last_name,
        'email': admin_profile.email,
        'profile': number,
        'mobile_number': number.mobile_number,
        'recidence_Street_address': membership.recidence_Street_address,
        'recidence_address_line_2': membership.recidence_address_line_2,
        'recidence_pincode': membership.recidence_pincode,
        'recidencecity': membership.recidencecity,
        'recidencestate': membership.recidencestate,
        'recidencecountry': membership.recidencecountry,
        'office_Street_address': membership.office_Street_address,
        'office_address_line_2': membership.office_address_line_2,
        'office_pincode': membership.office_pincode,
        'office_city': membership.office_city,
        'office_state': membership.office_state,
        'office_country': membership.office_country,
    }
    return render(request, 'profile/member_profile.html', profile_data)


def EditProfile(request):
    try:
        membership = MemberShip.objects.get(user=request.user)
        citylist = City.objects.all()
        statelist = Region.objects.all()
        countrylist = Country.objects.all()
        user = request.user
        if request.method == 'POST':
            profile_watcher = ProfileWatcher.objects.filter(user=request.user).order_by('-created_at').first()
            if profile_watcher:
                profile_watcher.is_recently_updated = True
                profile_watcher.save()
            profile_interest_form = ProfileInterestForm(request.POST, instance=user.profile)
            if profile_interest_form.is_valid():
                profile_interest_form.save(commit=True)

            # name and email should not editable by members
            # user.first_name = request.POST['first_name']
            # user.last_name = request.POST['last_name']
            if request.FILES:
                user.profile.photo = request.FILES['profile_image']

            membership.recidence_Street_address = request.POST['recidence_Street_address']
            membership.recidence_address_line_2 = request.POST['recidence_address_line_2']
            membership.recidence_pincode = request.POST['recidence_pincode']
            if request.POST.get('recidencecity', False):
                membership.recidencecity = City.objects.get(name__iexact=request.POST['recidencecity'])
            if request.POST.get('recidencestate', False):
                membership.recidencestate = Region.objects.get(name__iexact=request.POST['recidencestate'])
            if request.POST.get('recidencecountry', False):
                membership.recidencecountry = Country.objects.get(name__iexact=request.POST['recidencecountry'])
            membership.office_Street_address = request.POST['office_Street_address']
            membership.office_address_line_2 = request.POST['office_address_line_2']
            membership.office_pincode = request.POST['office_pincode']
            if request.POST.get('office_city', False):
                membership.office_city = City.objects.get(name__iexact=request.POST['office_city'])
            if request.POST.get('office_state', False):
                membership.office_state = Region.objects.get(name__iexact=request.POST['office_state'])
            if request.POST.get('office_country', False):
                membership.office_country = Country.objects.get(name__iexact=request.POST['office_country'])
            membership.save()
            user.save()
            user.profile.updated_by = request.user
            user.profile.save()
            if request.POST['mobile_number'] != user.profile.mobile_number:
                if Profile.objects.filter(mobile_number=request.POST['mobile_number']).exists():
                    messages.error(request, 'Entered mobile number already registered with the another user')
                    return HttpResponseRedirect(reverse('koscientific:profile'))
                # send transactional otp message
                otp = generate_otp()
                try:
                    message = smsBody.objects.get(smskey__iexact=SmsForm.COMMON_OTP_MESSAGE)
                    message = message.smscontent.replace('{{otp}}', otp)
                    result, response = send_otp_sms(message, int(request.POST['mobile_number']), otp)
                except Exception as e:
                    messages.info(request, "error while sending OTP {}".format(e))
                    return HttpResponseRedirect(reverse("koscientific:edit_base_profile"))

                OTP.objects.create(
                    sms_transaction_id=response['request_id'],
                    user=user,
                    otp=otp,
                )
                return HttpResponseRedirect(
                    reverse("koscientific:verify_otp_with_mobile", kwargs={'sms_trans_id': response['request_id']}))

            messages.warning(request, 'profile updated')
            return HttpResponseRedirect(reverse('koscientific:member_profile'))

        form = ProfileInterestForm(
            initial={'area_of_interests': [tag for tag in request.user.profile.area_of_interests.all()]})
        context = {
            'countrylist': countrylist,
            'statelist': statelist,
            'citylist': citylist,
            'edit_profile': user,
            'number': user.profile,
            'membership': membership,
            'form': form
        }
        return render(request, 'profile/edit_profile.html', context)
    except City.DoesNotExist:
        messages.warning(request, 'Please enter valid city name')
    except Region.DoesNotExist:
        messages.warning(request, 'Please enter valid state name')
    except Country.DoesNotExist:
        messages.warning(request, 'Please enter valid country name')
    except Exception as e:
        messages.warning(request, 'Error updating profile {}'.format(e))
    return HttpResponseRedirect(reverse('koscientific:edit_profile'))


def EditProfileS(request):
    user = request.user
    if request.method == 'POST':
        profile_watcher = ProfileWatcher.objects.filter(user=request.user).order_by('-created_at').first()
        if profile_watcher:
            profile_watcher.is_recently_updated = True
            profile_watcher.save()
        if request.FILES:
            user.profile.photo = request.FILES['profile_image']
        user.profile.updated_by = request.user
        user.profile.save()
        if request.POST['mobile_number'] != user.profile.mobile_number:
            if Profile.objects.filter(mobile_number=request.POST['mobile_number']).exists():
                messages.error(request, 'Entered mobile number already registered with the another user')
                return HttpResponseRedirect(reverse('koscientific:profile'))
            # send transactional otp message
            otp = generate_otp()
            try:
                message = smsBody.objects.get(smskey__iexact=SmsForm.COMMON_OTP_MESSAGE)
                message = message.smscontent.replace('{{otp}}', otp)
                result, response = send_otp_sms(message, int(request.POST['mobile_number']), otp)
            except Exception as e:
                messages.info(request, "error while sending OTP {}".format(e))
                return HttpResponseRedirect(reverse("koscientific:edit_base_profile"))

            OTP.objects.create(
                sms_transaction_id=response['request_id'],
                user=user,
                otp=otp,
            )
            return HttpResponseRedirect(
                reverse("koscientific:verify_otp_with_mobile", kwargs={'sms_trans_id': response['request_id']}))

        messages.success(request, 'Profile updated successfully!')
        return HttpResponseRedirect(reverse('koscientific:profile'))
    context = {
        'edit_profile': user,

    }
    return render(request, 'profile/edit_profileRegistered.html', context)


def Change_password(request):
    logged_in_user = request.user
    logger.info(logged_in_user.password)
    if request.method == 'POST':
        if check_password(request.POST['old_password'], logged_in_user.password):
            if check_password(request.POST['new_password'], logged_in_user.password):
                messages.error(request, 'New password is same as old password!')
                return HttpResponseRedirect(reverse('koscientific:change_password'))
            if request.POST['new_password'] == request.POST['confirm_password']:
                logged_in_user.set_password(request.POST['new_password'])
                logged_in_user.save()
                messages.success(request, 'Password changed successfully, you can login with new login password!')
                return HttpResponseRedirect('/')
            else:
                messages.error(request, 'New password & Confirm password mismatched')
                return HttpResponseRedirect(reverse('koscientific:change_password'))
        else:
            messages.error(request, 'Old password is wrong')
            return HttpResponseRedirect(reverse('koscientific:change_password'))

    return render(request, 'profile/change_password.html')


def render_to_pdf(template_src, context_dict={}):
    template = get_template(template_src)
    html = template.render(context_dict)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type='application/pdf')
    return None


def InvoicePDF(request):
    User = request.user
    temp = User.membership_set.all()
    for each in temp:
        temp2 = each.id
    order = Order.objects.get(membership_id=temp2)

    # order = Order.objects.get(membership__user=request.user)
    invoice_number = order.invoice
    amount = order.total_amount
    amount_in_words = (num2words(amount)).title()
    context = {
        'order_id': order.id,
        'invoice_number': order.invoice,
        'total_amount': order.total_amount,
        'transaction': order.transaction,
        'status': order.status,
        'name': order.membership.user.first_name,
        'recidence_Street_address': order.membership.recidence_Street_address,
        'recidence_pincode': order.membership.recidence_pincode,
        'recidence_city': order.membership.recidencecity,
        'kos_no': order.membership.kos_no,
        'day1': date.today(),
        'price': order.membership.price,
        'amount_in_words': amount_in_words,
    }
    template = get_template('PDF/invoice.html')
    html = template.render(context)
    pdf = render_to_pdf('invoice.html', context)
    if pdf:
        response = HttpResponse(pdf, content_type='application/pdf')
        filename = "_%s.pdf" % (invoice_number)
        content = "inline; filename='%s'" % (filename)
        download = request.GET.get("download")
        if download:
            content = "attachment; filename='%s'" % (filename)
        response['Content-Disposition'] = content
        return response
    return render(request, 'main/sidebar.html', {'order': order})


def sendSms(request, id):
    Member = MemberShip.objects.get(id=id)

    msg = smsBody.objects.get(id=2)
    logger.info(msg.smscontent)
    number = Member.mobile
    # sms_send(msg.smscontent, number)

    return HttpResponse('sent sms successfully')

@login_required
def add_sms_message(request):
    """
    Add sms message using key
    """
    if request.method == 'POST':
        sms_form = SmsForm(request.POST)
        if sms_form.is_valid():
            sms_form.save()
            messages.success(request, 'SMS {} added successfully'.format(sms_form.cleaned_data['smskey']))
            return HttpResponseRedirect(reverse('koscientific:sms_message_list'))
    else:
        sms_form = SmsForm()
    
    context = {
        'form': sms_form
    }
    return render(request, 'notification/SMS/add_sms.html', context)


@login_required
def edit_sms_message(request, sms_id=None):
    """
    Edit sms using key
    """
    sms_obj = get_object_or_404(smsBody, pk=sms_id)
    sms_form = SmsEditForm(request.POST or None, instance=sms_obj)
    if request.method == 'POST':
        if sms_form.is_valid():
            sms_form.save()
            messages.success(request, 'SMS meassage updated successfully')
            return HttpResponseRedirect(reverse('koscientific:sms_message_list'))
    context = {
        'form': sms_form
    }
    return render(request, 'notification/SMS/edit_sms.html', context)


@login_required
def smslist(request):
    smsbody_list = smsBody.objects.all()
    count = smsbody_list.count()
    context = {
        'smsbody_list': smsbody_list,
    }
    smsbody_list = smsbody_list
    page = request.GET.get('page', 1)
    paginator = Paginator(smsbody_list, 10)
    try:
        smsbody_list = paginator.page(page)
    except PageNotAnInteger:
        smsbody_list = paginator.page(1)
    except EmptyPage:
        smsbody_list = paginator.page(paginator.num_pages)

    index = smsbody_list.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['smsbody_list'] = smsbody_list
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'notification/SMS/SMScontent_list.html', context)


def sms_edit(request, smsBody_id):
    sms_update = smsBody.objects.get(id=smsBody_id)
    if request.method == 'POST':
        sms_update.smskey = request.POST['smskey']
        sms_update.smscontent = request.POST['smscontent']
        sms_update.save()
        return HttpResponseRedirect(reverse('koscientific:sms_message_list'))
    context = {
        'sms_update': sms_update,
    }
    return render(request, 'notification/SMS/SMScontent_edit.html', context)


def addMainConfi(request):
    mailsettings = MailSettings.objects.first()
    if request.method == 'POST':
        if mailsettings is None:
            mailsettings = MailSettings()
        mailsettings.from_email = request.POST['from_email']
        mailsettings.mail_server = request.POST['mail_server']
        mailsettings.mail_port = request.POST['mail_port']
        mailsettings.use_ssl = request.POST['use_ssl']
        mailsettings.username = request.POST['username']
        mailsettings.password = request.POST['password']
        mailsettings.save()
        messages.success(request, 'Mail Settings Updated Successfully')

    context = {
        'mail_settings': mailsettings
    }
    return render(request, 'master/Mailsetting/mail_setting.html', context)


def addnotification(request):
    if request.method == 'POST':
        subject = request.POST['subject']
        body = request.POST['body']
        if subject == '' or body == '':
            messages.error(request, 'Please fill all the fields!')
        else:
            add_pushNotification = pushNotification(subject=subject, body=body)
            add_pushNotification.save()
        messages.success(request, 'Push notification added Successfully')
        return HttpResponseRedirect(reverse('koscientific:list_Notification'))

    notification_data = pushNotification.objects.get(id=1)
    context = {
        'notification_data': notification_data
    }
    return render(request, 'notification/Push notification/add_PushNotiMsg.html', context)


def notification_edit(request, id):
    notification_update = pushNotification.objects.get(id=id)
    if request.method == 'POST':
        notification_update.subject = request.POST['subject']
        notification_update.imgsub = request.POST['imgsub']
        notification_update.body = request.POST['body']
        notification_update.save()
        return HttpResponseRedirect(reverse('koscientific:list_Notification'))
    context = {
        'notification_update': notification_update,
    }
    return render(request, 'notification/Push notification/edit_notification.html', context)


def Notificationlist(request):
    notificationbody_list = pushNotification.objects.all()
    count = notificationbody_list.count()
    context = {
        'notificationbody_list': notificationbody_list,
    }
    notificationbody_list = notificationbody_list
    page = request.GET.get('page', 1)
    paginator = Paginator(notificationbody_list, 10)
    try:
        notificationbody_list = paginator.page(page)
    except PageNotAnInteger:
        notificationbody_list = paginator.page(1)
    except EmptyPage:
        notificationbody_list = paginator.page(paginator.num_pages)

    index = notificationbody_list.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['notificationbody_list'] = notificationbody_list
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'notification/Push notification/NotificationMsg_list.html', context)


def addserverkey(request):
    serverskey = serverKey.objects.get(id=1)
    if request.method == 'POST':
        serverskey.server_key = request.POST['server_key']
        serverskey.save()
        messages.success(request, 'Server key Updated Successfully')

    serverkey = serverKey.objects.get(id=1)
    context = {
        'serverkey': serverkey
    }
    return render(request, 'notification/Push notification/notificationsetting.html', context)


import json
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models.fields.files import ImageFieldFile
import base64
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout


def Push_notfication(id, subject, body, image, fcms=[]):
    url = 'https://fcm.googleapis.com/fcm/send'

    # img = json.dumps(str(image))
    # image = img

    payload = {'registration_ids': fcms,
               # To send FCM to multiple device you use the key "registration_ids" instead of "to" "registration_ids": ["fcm_token1", "fcm_token2"]
               'notification': {
                   "title": subject,
                   "body": body,
                   "image": image,

               },
               "data": {"title": subject,
                        "notification_id": id,
                        "notification_title": subject,
                        "notification_description": body,
                        "notification_image": image,
                        },
               }
    headers = {'content-type': 'application/json',
               'authorization': "key=" + serverKey.objects.latest("id").server_key,
               'cache-control': "no-cache"}
    logger.info(payload)
    r = requests.post(url, data=json.dumps(payload), headers=headers)
    logger.info(r.text)
    return True


def Push_notfication(id, subject, image, body, fcms=[]):
    url = 'https://fcm.googleapis.com/fcm/send'

    # img = json.dumps(str(image))
    # image = img

    payload = {'registration_ids': fcms,
               # To send FCM to multiple device you use the key "registration_ids" instead of "to" "registration_ids": ["fcm_token1", "fcm_token2"]
               'notification': {
                   "title": subject,
                   "body": body,
                   "image": image,

               },
               "data": {"title": subject,
                        "notification_id": id,
                        "notification_title": subject,
                        "notification_description": body,
                        # "notification_image": image,
                        },
               }
    headers = {'content-type': 'application/json',
               'authorization': "key=" + serverKey.objects.latest("id").server_key,
               'cache-control': "no-cache"}
    logger.info(payload)
    r = requests.post(url, data=json.dumps(payload), headers=headers)
    logger.info(r.text)
    return True


def send_push_notification(request, id):
    sub = pushNotification.objects.get(id=id)
    subject = sub.subject
    body = sub.body
    # if 'imgsub' in request.FILES:
    image = sub.imgsub.url
    image = "http://" + str(get_current_site(request).domain) + str(image)
    allkey = fcmkey.objects.all()
    fcms = []
    for each in allkey:
        fcms.append(each.fcm_key)
    Push_notfication(2, subject, body, image, fcms=fcms)
    messages.success(request, 'Notification sent successfully!')
    return HttpResponseRedirect(reverse('koscientific:list_Notification'))


def registered_user(request):
    name = request.user
    return render(request, 'RegisteredUser/registered_user.html', {'name': name})


@login_required
def update_notification(request):
    # make all user message to readed once drop down open
    Message.objects.filter(user=request.user).update(is_readed=True)

    context = {
        'messages': Message.objects.filter(user=request.user).order_by('-created_at')[:5],
        'message_count': Message.objects.filter(user=request.user).count(),
    }
    html = render_to_string('main/notification.html', context)
    return HttpResponse(html)


def payment_final(request):
    context = {
        'user_name': request.user.username,
        'first_name': request.user.first_name,
        'last_name': request.user.last_name,
    }
    return render(request, 'member/payment_done.html', context)


def edit_member(request, mem_id):
    """
    membership form edit by admin
    """
    membership = get_object_or_404(MemberShip, id=mem_id)
    qualificationFormset = formset_factory(QualificationForm, extra=0, max_num=5, min_num=1)
    if request.method == 'POST':
        try:
            membership.user.profile.updated_by = request.user
            membership.user.profile.save()
            if 'registred_mobile_number' in request.POST:
                membership.user.profile.mobile_number = request.POST['registred_mobile_number']
                membership.user.profile.save()
            if 'registered_email' in request.POST:
                membership.user.email = request.POST['registered_email']
                membership.user.username = request.POST['registered_email']
                membership.user.save()
            if 'first_name' in request.POST:
                membership.user.first_name = request.POST['first_name']
            if 'last_name' in request.POST:
                membership.user.last_name = request.POST['last_name']
            if 'dob' in request.POST and request.POST['dob']:
                membership.dob = request.POST['dob']
            if 'gender' in request.POST:
                membership.gender = request.POST['gender']
            if 'recidence_Street_address' in request.POST:
                membership.recidence_Street_address = request.POST['recidence_Street_address']
            if 'recidence_address_line_2' in request.POST:
                membership.recidence_address_line_2 = request.POST['recidence_address_line_2']
            if 'recidencecountry' in request.POST:
                membership.recidencecountry_id = request.POST['recidencecountry']
            if 'recidencesstate' in request.POST:
                membership.recidencestate_id = request.POST['recidencesstate']
            if 'recidencecity' in request.POST:
                membership.recidencecity_id = request.POST['recidencecity']
            if 'recidence_pincode' in request.POST:
                membership.recidence_pincode = request.POST['recidence_pincode']
            if 'address_condition' in request.POST:
                membership.address_condition = request.POST['address_condition']
                membership.office_Street_address = request.POST['recidence_Street_address']
                membership.office_address_line_2 = membership.recidence_address_line_2
                membership.office_city_id = membership.recidencecity_id
                membership.office_state_id = membership.recidencestate_id
                membership.office_pincode = membership.recidence_pincode
                membership.office_country_id = membership.recidencecountry_id
            else:
                if 'office_Street_address' in request.POST:
                    membership.office_Street_address = request.POST['office_Street_address']
                if 'office_address_line_2' in request.POST:
                    membership.office_address_line_2 = request.POST['office_address_line_2']
                if 'office_country' in request.POST:
                    membership.office_country_id = request.POST['office_country']
                if 'office_state' in request.POST:
                    membership.office_state_id = request.POST['office_state']
                if 'office_city' in request.POST:
                    membership.office_city_id = request.POST['office_city']

                if 'office_pincode' in request.POST:
                    membership.office_pincode = request.POST['office_pincode']
            if 'office_Street_address' in request.POST:
                membership.office_Street_address = request.POST['office_Street_address']
            if 'office_address_line_2' in request.POST:
                membership.office_address_line_2 = request.POST['office_address_line_2']
            if 'mobile' in request.POST:
                membership.mobile = request.POST['mobile']
            if request.POST['home_phone'] == '' or None:
                membership.home_phone = None
            else:
                membership.home_phone = request.POST['home_phone']
               
            if request.POST['office_phone'] == '' or None:
                membership.office_phone = None
            else:
                membership.office_phone = request.POST['office_phone']
            
            if 'cheque_no' in request.POST:
                membership.cheque_no = request.POST['cheque_no']
            if 'bank' in request.POST:
                membership.bank = request.POST['bank']
            if 'medical_registration_no' in request.POST:
                membership.medical_registration_no = request.POST['medical_registration_no']
            
            if 'reg_country' in request.POST:
                membership.reg_country_id = request.POST['reg_country']
            if 'reg_state' in request.POST:
                membership.reg_state_id = request.POST['reg_state']
            if 'date' in request.POST:
                membership.date = request.POST['date']
            if 'photo' in request.FILES:
                membership.photo = request.FILES['photo']
            if 'certificate' in request.FILES:
                membership.certificate = request.FILES['certificate']
            if 'agree' in request.POST:
                membership.agree = request.POST['agree']
            if 'non-mem-introducer' in request.POST:
                membership.non_mem_introducer = request.POST['non-mem-introducer']
            membership.date = timezone.now().date()
            membership.save()
            membership.user.save()

            formset = qualificationFormset(request.POST)
            # Now save the data for each form in the formset
            new_qualifications = []
            if formset.is_valid():
                Qualification.objects.filter(membership=membership).delete()
                for qualification in formset.cleaned_data:
                    degree = qualification['degree']
                    year = qualification['year']
                    college = qualification['college']
                    new_qualifications.append(
                        Qualification(membership=membership, degree=degree, year=year, college=college))

            Qualification.objects.bulk_create(new_qualifications)

            membership.status = 'updated'
            membership.save()
            if request.is_ajax():
                return JsonResponse({"message": 'saved to draft'}, status=200)
            else:
                return HttpResponseRedirect(reverse("koscientific:member_list"))

        except Exception as e:
            messages.error(request, '{}'.format(e))
            
            kwargs = {'mem_id': mem_id}
            return HttpResponseRedirect(reverse('koscientific:member_edit', kwargs=kwargs))

    qualification_formset = qualificationFormset(
            initial=membership.qualifications.all().values('college', 'degree', 'year'))

    user = request.user
    number = Profile.objects.get(user=request.user)
    countries = Country.objects.all()

    if membership.office_country:
        office_states = Region.objects.filter(country=membership.office_country)
    else:
        office_states = None

    if membership.office_state:
        office_cities = City.objects.filter(region=membership.office_state)
    else:
        office_cities = None

    if membership.recidencecountry:
        residence_states = Region.objects.filter(country=membership.recidencecountry)
    else:
        residence_states = None

    if membership.recidencestate:
        residence_cities = City.objects.filter(region=membership.recidencestate)
    else:
        residence_cities = None

    if membership.reg_country:
        reg_states = Region.objects.filter(country=membership.reg_country)
    else:
        reg_states = None

    context = {}
    context['qualification_formset'] = qualification_formset
    context['country'] = countries
    context['city'] = office_cities
    context['region'] = office_states

    context['residence_cities'] = residence_cities
    context['residence_states'] = residence_states

    context['reg_states'] = reg_states

    context['members'] = MemberShip.objects.filter(is_member=True)
    context['first_name'] = user.first_name
    context['last_name'] = user.last_name
    context['mobile_number'] = number.mobile_number
    context['email'] = user.email
    context['profile'] = user.profile
    context['auto_save_in'] = settings.AUTO_SAVE_IN
    context['membership'] = membership
    return render(request, 'member/member_edit.html', context)
        


def member_list(request):
    context = {}
    member_list = MemberShip.objects.filter(is_member=True).values('user__first_name', 'user__last_name', 'kos_no')
    count = member_list.count()
    search = request.GET.get('search')
    if search != '' and search is not None:
        member_list = member_list.filter(
            Q(user__first_name__icontains=search) | Q(user__last_name__icontains=search)
            | Q(kos_no__icontains=search)).distinct()
    else:
        member_list = member_list

    page = request.GET.get('page', 1)
    paginator = Paginator(member_list, 10)
    try:
        member_list = paginator.page(page)
    except PageNotAnInteger:
        member_list = paginator.page(1)
    except EmptyPage:
        member_list = paginator.page(paginator.num_pages)

    index = member_list.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    logger.info(count)
    context['count'] = count
    context['member_list'] = member_list
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'member/member_list_read_only.html', context)


def FAQ(request):
    return render(request, 'FAQ/FAQ.html')


def addMail(request):
    if request.method == 'POST':
        mail = Mail()
        mail.name = request.POST['name']
        mail.email_subject = request.POST['email_subject']
        mail.email_body = request.POST['email_body']
        mail.email_attachment = request.POST['email_attachment']

        if mail.email_subject == '' or mail.email_body == '':
            messages.error(request, 'Please fill all the fields!')
        else:
            mail.save()
            messages.success(request, 'Mail content added successfully!')
            # go to list view
        return HttpResponseRedirect(reverse('koscientific:mail_list'))
    return render(request, 'notification/Email/addEmail_content.html')


class CreateMail(CreateView):
    ''' Create the mail '''
    model = Mail
    form_class = MailForm
    template_name = 'notification/Email/create_mail.html'
    success_url = reverse_lazy('koscientific:mail_list')


@login_required
def add_mail(request):
    """
    Add mail using key
    """
    if request.method == 'POST':
        mail_form = MailForm(request.POST)
        if mail_form.is_valid():
            mail_form.save()
            messages.success(request, 'Mail {} added successfully'.format(mail_form.cleaned_data['name']))
            return HttpResponseRedirect(reverse('koscientific:mail_list'))
    else:
        mail_form = MailForm()
    
    context = {
        'form': mail_form
    }
    return render(request, 'notification/Email/create_mail.html', context)


@login_required
def edit_mail(request, mail_id=None):
    """
    Edit mail using key
    """
    mail_obj = get_object_or_404(Mail, pk=mail_id)
    mail_form = MailEditForm(request.POST or None, instance=mail_obj)
    if request.method == 'POST':
        if mail_form.is_valid():
            mail_form.save()
            messages.success(request, 'Mail updated successfully')
            return HttpResponseRedirect(reverse('koscientific:mail_list'))
    context = {
        'form': mail_form
    }
    return render(request, 'notification/Email/edit_mail.html', context)


def mail_list(request):
    mail_list = Mail.objects.all()
    count = mail_list.count()
    context = {
        'mail_list': mail_list,
    }
    mail_list = mail_list
    page = request.GET.get('page', 1)
    paginator = Paginator(mail_list, 10)
    try:
        mail_list = paginator.page(page)
    except PageNotAnInteger:
        mail_list = paginator.page(1)
    except EmptyPage:
        mail_list = paginator.page(paginator.num_pages)

    index = mail_list.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['mail_list'] = mail_list
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'notification/Email/MailList.html', context)




def Registered_user(request):
    context = {}
    sdate = request.GET.get('sdate', '')
    edate = request.GET.get('edate', '')
    enddate = pd.to_datetime(edate) + pd.DateOffset(days=1)

    search = request.GET.get('search', '')
    user = User.objects.all().order_by('-id')

    if search != '' and search is not None:
        user = user.filter(
            Q(first_name__icontains=search) | Q(last_name__icontains=search)
            | Q(email__icontains=search)).distinct()

    elif sdate > edate:
        messages.error(request, ' start date is Greater than end date')

    elif sdate < edate:
        user = User.objects.filter(date_joined__range=[sdate, enddate])

    else:
        user = User.objects.all().order_by('-id')

    page = request.GET.get('page', 1)
    paginator = Paginator(user, 10)
    try:
        user = paginator.page(page)
    except PageNotAnInteger:
        user = paginator.page(1)
    except EmptyPage:
        user = paginator.page(paginator.num_pages)

    index = user.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index

    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    context['user'] = user
    context['sdate'] = sdate
    context['edate'] = edate
    context['search'] = search

    return render(request, 'RegisteredUser/registered_user_list.html', context)


def help(request):
    help_list = Help.objects.all().order_by('-created_at')
    context = {
        'help_list': help_list,
    }
    return render(request, 'member/help.html', context)


def help_add(request):
    if request.method == 'POST':
        ask_helps = Help()
        ask_helps.title = request.POST['title']
        ask_helps.description = request.POST['description']
        ask_helps.save()
        messages.success(request, 'Help added successfully!')
        return HttpResponseRedirect(reverse('koscientific:help'))
    return render(request, 'member/help_add.html')


def ins_guidelines(request):
    return render(request, 'guidelines/Instruction-Course-Guidelines.html')


def freePaper_guidelines(request):
    return render(request, 'guidelines/Free-Paper-Guidelines.html')


def Poster_guidelines(request):
    return render(request, 'guidelines/E-Poster-Guidelines.html')


def PhysicalPoster_guidelines(request):
    return render(request, 'guidelines/Physical-Poster-Guidelines.html')


def Video_guidelines(request):
    return render(request, 'guidelines/Video-Submission-Guidelines.html')


def registered_member(request):
    user = request.user
    number = Profile.objects.get(user=request.user)
    context = {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'mobile_number': number.mobile_number,
        'email': user.email,
        'profile': user.profile,
        'RAZOR_PAY_CURRENCY': settings.RAZOR_PAY_CURRENCY,
        'member_count': MemberShip.objects.filter(is_member=True).count()
    }
    return render(request, 'dashboard/registered_member.html', context)


def InvitedEvaluatorList(request):
    InvitedEvaluator = EvaluatorInvite.objects.all()
    context = {
        'InvitedEvaluator': InvitedEvaluator,
    }
    count = InvitedEvaluator.count()
    InvitedEvaluator = InvitedEvaluator
    page = request.GET.get('page', 1)
    paginator = Paginator(InvitedEvaluator, 10)
    try:
        InvitedEvaluator = paginator.page(page)
    except PageNotAnInteger:
        InvitedEvaluator = paginator.page(1)
    except EmptyPage:
        InvitedEvaluator = paginator.page(paginator.num_pages)

    index = InvitedEvaluator.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['InvitedEvaluator'] = InvitedEvaluator
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'evalutor/invited_evaluators.html', context)


def showform(request):
    ''' dummy fuction for django forms'''
    form = DemoForm(request.POST or None)
    if form.is_valid():
        emailhere = form.cleaned_data.get('email')
        if Demo.objects.filter(email=emailhere):
            messages.info(request, "this email already exist in database")
            return render(request=request,
                          template_name="demo/demo.html",
                          context={"form": form})
        else:
            form.save()
            context = {'form': form}

            return render(request, 'demo/demo.html', context)

    return render(request=request,
                  template_name="demo/demo.html",
                  context={"form": form})


def invited_session(request):
    i_received_sessions = InvitedSession.objects.filter(send_to=request.user).order_by('-created_at')
    context = {
        'i_received_sessions': i_received_sessions
    }
    count = i_received_sessions.count()
    i_received_sessions = i_received_sessions
    page = request.GET.get('page', 1)
    paginator = Paginator(i_received_sessions, 10)
    try:
        i_received_sessions = paginator.page(page)
    except PageNotAnInteger:
        i_received_sessions = paginator.page(1)
    except EmptyPage:
        i_received_sessions = paginator.page(paginator.num_pages)

    index = i_received_sessions.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['i_received_sessions'] = i_received_sessions
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'invited_session/invited_session_list.html', context=context)


def invited_session_detail(request, id):
    i_received_session_detail = InvitedSession.objects.get(send_to=request.user, pk=id)
    context = {
        'received_session': i_received_session_detail
    }
    return render(request, 'invited_session/invited_session_detail.html', context=context)


def invited_session_opinion(request, id, opinion):
    invited_session = get_object_or_404(InvitedSession, pk=id)
    if opinion.lower() == 'accept':
        invited_session.is_accepted = True
        invited_session.is_rejected = False
        messages.success(request, 'Paper accepted')
    elif opinion.lower() == 'reject':
        invited_session.is_rejected = True
        invited_session.is_accepted = False
        if invited_session.is_ic_paper:
            ic_paper = InstructionCourse.objects.get(unique_id=invited_session.paper_id)
            ic_paper.co_instructor_ic_paper.filter(co_instructor__user=request.user).delete()
        elif invited_session.is_free_paper:
            free_paper = FreePaper.objects.get(unique_id=invited_session.paper_id)
            free_paper.coauther_name.remove(MemberShip.objects.get(user=request.user))
        elif invited_session.is_video_paper:
            video_paper = Video.objects.get(unique_id=invited_session.paper_id)
            video_paper.coauther_video_name.remove(MemberShip.objects.get(user=request.user))
        messages.success(request, 'Paper rejected')
    invited_session.save()
    return HttpResponseRedirect(reverse('koscientific:invited_session'))


def is_admin(user):
    return user.groups.filter(name__iexact='admin').exists()


from django.contrib.auth.decorators import user_passes_test
from django.utils.html import strip_tags


@login_required
def event_list(request):
    events = Event.objects.all().order_by('-created_at')

    context = {
        'events': events,
    }
    count = events.count()
    events = events
    page = request.GET.get('page', 1)
    paginator = Paginator(events, 10)
    try:
        events = paginator.page(page)
    except PageNotAnInteger:
        events = paginator.page(1)
    except EmptyPage:
        events = paginator.page(paginator.num_pages)

    index = events.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['events'] = events
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index

    return render(request, 'events/list.html', context)


@user_passes_test(is_admin)
def event_add(request):
    if request.method == "POST":
        form = EventForm(request.POST)
        if form.is_valid():
            form = form.save(commit=False)
            form.created_by = request.user
            form.save()

            messages.success(request, 'Event created')
            return HttpResponseRedirect(reverse("koscientific:event_list"))
        else:
            return render(request=request,
                          template_name='events/add.html',
                          context={"form": form})

    form = EventForm()
    return render(request=request,
                  template_name="events/add.html",
                  context={"form": form})


@user_passes_test(is_admin)
def event_edit(request, event_id):
    event = get_object_or_404(Event, pk=event_id)
    form = EventForm(request.POST or None, instance=event)
    if request.method == "POST":

        if form.is_valid():
            form = form.save(commit=False)
            form.created_by = request.user
            form.save()

            messages.success(request, 'Event updated created')
            return HttpResponseRedirect(reverse("koscientific:event_list"))
        else:
            return render(request=request,
                          template_name='events/add.html',
                          context={"form": form, "is_edit": True})

    return render(request=request,
                  template_name="events/add.html",
                  context={"form": form, "is_edit": True})


@user_passes_test(is_admin)
def event_detail(request, event_id):
    try:
        event = get_object_or_404(Event, pk=event_id)
    except Exception as identifier:
        event = Event.objects.none()
        messages.error(request, 'Event not found')
        return HttpResponseRedirect(reverse("koscientific:event_list"))
    context = {
        'event': event,
    }
    return render(request, 'events/detail.html', context)


def Feedback_list(request):
    if is_admin(request.user):
        list_of_feedback = Feedback.objects.all().order_by('-created_at')

    else:
        list_of_feedback = Feedback.objects.filter(created_by=request.user).order_by('-created_at')
    context = {
        'list_of_feedback': list_of_feedback,
    }
    count = list_of_feedback.count()
    list_of_feedback = list_of_feedback
    page = request.GET.get('page', 1)
    paginator = Paginator(list_of_feedback, 10)
    try:
        list_of_feedback = paginator.page(page)
    except PageNotAnInteger:
        list_of_feedback = paginator.page(1)
    except EmptyPage:
        list_of_feedback = paginator.page(paginator.num_pages)

    index = list_of_feedback.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['list_of_feedback'] = list_of_feedback
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'Feedback/feedback_list.html', context)


def Feedback_add(request):
    if request.method == "POST":
        form = FeedbackForm(request.POST)
        if form.is_valid():
            form = form.save(commit=False)
            form.created_by = request.user
            form.save()

            messages.success(request, 'Feedback created')
            # try:
            #     mail_dict = {
            #         'subject': 'hi',
            #         'plain_message': "Hi. your account has",
            #         'html_message': "Hi. your account has",
            #         'recipient_list': '{}'.format('hemanth@entityvibes.com'),
            #     }
            #     KosEmail.send_mail(**mail_dict)
            #
            # except Exception as e:
            #     logger.info('unable to send the invite email', str(e))
        return HttpResponseRedirect(reverse("koscientific:feedback_list"))

    form = FeedbackForm()
    return render(request=request,
                  template_name="Feedback/feedback_add.html",
                  context={"form": form})


def Feedback_detail(request, feedback_id):
    try:
        event = get_object_or_404(Feedback, pk=feedback_id)
    except Exception as identifier:
        event = Feedback.objects.none()
        messages.error(request, 'Feedback not found')
        return HttpResponseRedirect(reverse("koscientific:feedback_list"))
    context = {
        'feedback': event,
    }
    return render(request, 'Feedback/feedback_detail.html', context)


@login_required
def provisional_members(request):
    ''' 
    admin willratify members with documents attached
    and mail to go AGM for confirmation
    '''

    if request.method == 'POST':
        if 'approval_file' not in request.FILES:
            messages.error(request, 'Please select approval file to upload')
            return HttpResponseRedirect(reverse("koscientific:provisional_member"))
        if 'selected_members' not in request.POST and len(request.POST.getlist('selected_members')) <= 0:
            messages.error(request, 'Please select at least one provisional member')
            return HttpResponseRedirect(reverse("koscientific:provisional_member"))
        random_token = id_generator(8)
        new_approvals = []
        for member in request.POST.getlist('selected_members'):

            if hasattr(get_object_or_404(MemberShip, id=member), 'provisional_membership_approval'):
                provisional_membership_approval = get_object_or_404(ProvisionalMembershipApproval, membership_id=member)
            else:
                provisional_membership_approval = ProvisionalMembershipApproval()
                provisional_membership_approval.membership_id = member

            provisional_membership_approval.agm = get_object_or_404(MemberShip, user=request.user)
            provisional_membership_approval.document = request.FILES['approval_file']
            provisional_membership_approval.status = ProvisionalMembershipApproval.NO_ANSWER
            provisional_membership_approval.random_token = random_token
            provisional_membership_approval.approved_at = timezone.now()
            provisional_membership_approval.save()
            provisional_membership_approval.membership.is_ratifying = True
            provisional_membership_approval.membership.save()

        messages.success(request, 'Mail sent to Secretary to review the membership')
        try:
            oneTimeLink = OneTimeLink()
            oneTimeLink.name = "Secretary link to accept and reject the ratified member"
            oneTimeLink.token = id_generator(50)
            oneTimeLink.save()

            kwargs = {
                "random_token": urlsafe_base64_encode(force_bytes(random_token)),
                "token": oneTimeLink.token,
                "opinion": 'accept'
            }

            accept_link = reverse("koscientific:confirm_ratify_membership", kwargs=kwargs)
            accept_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), accept_link)
            kwargs['opinion'] = 'reject'
            reject_link = reverse("koscientific:confirm_ratify_membership", kwargs=kwargs)
            reject_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), reject_link)

            recent_ratified_member = ProvisionalMembershipApproval.objects.all().order_by('-created_at').first()
            members_full_name = ','.join(
                                get_object_or_404(MemberShip, pk=id).user.email for id in request.POST.getlist('selected_members'))
            officials_mails = [settings.SECRETARY_MAIL, settings.INFO_KOS_ONLINE_MAIL, settings.PRESIDENT_MAIL,
                               settings.ELECTION_PRESIDENT_MAIL, settings.VICE_PRESIDENT_MAIL, settings.TREASURER_MAIL]
            mailcontent = Mail.objects.get(name__iexact=MailForm.RATIFY_MEMBERSHIP_BY_AGM_TO_AGM)
            subject = mailcontent.email_subject
            email_body = mailcontent.email_body.replace('{{members_full_name}}', members_full_name)
            email_body = email_body.replace('{{accept}}', accept_url)
            email_body = email_body.replace('{{reject}}', reject_url)
            
            mail_dict = {
                'subject': subject,
                'plain_message': strip_tags(email_base_template(email_body)),
                'html_message': email_base_template(email_body),
                'to': ['{}'.format(settings.AGM_MAIL)],
                'cc': officials_mails,
                'file_path': recent_ratified_member.document.path,
                'mimetype': 'file/pdf',
            }
            KosEmail.send_multi_alternatives_email(**mail_dict)
            logger.info('Email send to AGM')
        except Exception as e:
            logger.info('unable to send mail to AGM {}'.format(e))
        return HttpResponseRedirect(reverse("koscientific:provisional_member"))

    member = MemberShip.all_objects.filter(is_provisional=True,
                                           membership_detail__introducer_one_status=MembershipDetail.ACCEPT,
                                           membership_detail__introducer_two_status=MembershipDetail.ACCEPT,
                                           membership_detail__admin_status=MembershipDetail.ACCEPT).order_by(
        '-created_at')
    count = member.count()
    context = {}
    member = member
    page = request.GET.get('page', 1)
    paginator = Paginator(member, 10)
    try:
        member = paginator.page(page)
    except PageNotAnInteger:
        member = paginator.page(1)
    except EmptyPage:
        member = paginator.page(paginator.num_pages)

    index = member.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    context['member'] = member
    context['membership_detail_constants'] = MembershipDetail
    return render(request, 'provisional_members/list.html', context)


@permission_required('koscientific.approve_user', raise_exception=True)
def member_deceased(request, id):
    """ member account freeze on AGM upload document"""
    if request.method == 'POST':
        document = None
        if request.FILES:
            document = request.FILES['document']
        else:
            messages.error(request, 'select document to account deceased')
            return HttpResponseRedirect(reverse('koscientific:member_list'))
        membership = MemberShip.all_objects.get(id=id)
        membership.is_active = False
        membership.is_member = False
        membership.user.is_active = False
        membership.status = 'deceased'
        membership.save()
        membership.user.save()
        deceased_membership = DeceasedMembership()
        deceased_membership.membership = membership
        deceased_membership.agm = get_object_or_404(MemberShip, user=request.user)
        deceased_membership.document = document
        deceased_membership.status = DeceasedMembership.DECEASED
        deceased_membership.deceased_at = timezone.now()
        deceased_membership.save()
        
        try:
            # deceased mail
            officials_mails = [settings.INFO_KOS_ONLINE_MAIL, settings.SECRETARY_MAIL, settings.PRESIDENT_MAIL]
            member_full_name = "{} {}".format(membership.user.first_name, membership.user.last_name)
            mailcontent = Mail.objects.get(name__iexact=MailForm.MEMBER_DECEASED)
            subject = mailcontent.email_subject.replace('{{member_full_name}}', member_full_name)
            email_body = mailcontent.email_body.replace('{{member_full_name}}', member_full_name)
            email_body = email_body.replace('{{kos_number}}', str(membership.kos_no))
        
            mail_dict = {
                'subject': subject,
                'plain_message': strip_tags(email_base_template(email_body)),
                'html_message': email_base_template(email_body),
                'to': officials_mails,
                'file_path': deceased_membership.document.path,
                'mimetype': 'file/pdf',
            }
            KosEmail.send_multi_alternatives_email(**mail_dict)
        except Exception as e:
            logger.warning('deceased mail not sent {e}'.format(e))
        else:
            logger.info('deceased mail sent')

        messages.success(request, 'member: {} account deceased'.format(membership))
    return HttpResponseRedirect(reverse('koscientific:member_list'))


def member_resign(request, id):
    """ member resign and freeze account on AGM upload document"""
    if request.method == 'POST':
        document = None
        if request.FILES:
            document = request.FILES['document']
        else:
            messages.error(request, 'select document to member resign')
            return HttpResponseRedirect(reverse('koscientific:member_list'))
        membership = MemberShip.all_objects.get(id=id)
        membership.is_active = False
        membership.user.is_active = False
        membership.status = 'freeze'
        membership.save()
        membership.user.save()
        if hasattr(membership, 'resign_membership'):
            resign_membership = membership.resign_membership
        else:
            resign_membership = MemberResign()
            resign_membership.membership = membership
        resign_membership.agm = get_object_or_404(MemberShip, user=request.user)
        resign_membership.document = document
        resign_membership.status = MemberResign.RESIGN_ACCEPTED
        resign_membership.resign_at = timezone.now()
        resign_membership.save()

        try:
            # resigned mail
            officials_mails = [settings.INFO_KOS_ONLINE_MAIL, settings.SECRETARY_MAIL, settings.PRESIDENT_MAIL]
            member_full_name = "{} {}".format(membership.user.first_name, membership.user.last_name)
            mailcontent = Mail.objects.get(name__iexact=MailForm.MEMBER_RESIGN)
            subject = mailcontent.email_subject.replace('{{member_full_name}}', member_full_name)
            email_body = mailcontent.email_body.replace('{{member_full_name}}', member_full_name)
            email_body = email_body.replace('{{kos_number}}', str(membership.kos_no))
        
            mail_dict = {
                'subject': '{} {} resigned'.format(membership.user.first_name, membership.user.last_name),
                'plain_message': strip_tags(email_base_template(email_body)),
                'html_message': email_base_template(email_body),
                'to': ['{}'.format(membership.user.email)],
                'cc': officials_mails,
                'file_path': resign_membership.document.path,
                'mimetype': 'file/pdf',
            }
            KosEmail.send_multi_alternatives_email(**mail_dict)
        except Exception as e:
            logger.error('resigned mail not sent {}'.format(e))
        else:
            logger.info('resigned mail sent')
        

        messages.success(request,'member: {} {} made resigned'.format(membership.user.first_name, membership.user.last_name))
    return HttpResponseRedirect(reverse('koscientific:member_list'))


@login_required
def application_form(request):
    qualificationFormset = formset_factory(QualificationForm, extra=0, max_num=5, min_num=1)
    order = None
    if request.method == 'POST':
        try:
            if not hasattr(request.user, 'membership'):
                member = MemberShip()
                member.user = request.user
            else:
                member = get_object_or_404(MemberShip, user=request.user)

            if 'first_name' in request.POST:
                member.user.first_name = request.POST['first_name']
            if 'last_name' in request.POST:
                member.user.last_name = request.POST['last_name']
            if 'dob' in request.POST and request.POST['dob']:
                member.dob = request.POST['dob']
            if 'gender' in request.POST:
                member.gender = request.POST['gender']
            if 'recidence_Street_address' in request.POST:
                member.recidence_Street_address = request.POST['recidence_Street_address']
            if 'recidence_address_line_2' in request.POST:
                member.recidence_address_line_2 = request.POST['recidence_address_line_2']
            if 'recidencecountry' in request.POST:
                member.recidencecountry_id = request.POST['recidencecountry']
            if 'recidencesstate' in request.POST:
                member.recidencestate_id = request.POST['recidencesstate']
            if 'recidencecity' in request.POST:
                member.recidencecity_id = request.POST['recidencecity']
            if 'recidence_pincode' in request.POST:
                member.recidence_pincode = request.POST['recidence_pincode']
            if 'address_condition' in request.POST:
                member.address_condition = request.POST['address_condition']
                member.office_Street_address = request.POST['recidence_Street_address']
                member.office_address_line_2 = member.recidence_address_line_2
                member.office_city_id = member.recidencecity_id
                member.office_state_id = member.recidencestate_id
                member.office_pincode = member.recidence_pincode
                member.office_country_id = member.recidencecountry_id
            else:
                if 'office_Street_address' in request.POST:
                    member.office_Street_address = request.POST['office_Street_address']
                if 'office_address_line_2' in request.POST:
                    member.office_address_line_2 = request.POST['office_address_line_2']
                if 'office_country' in request.POST:
                    member.office_country_id = request.POST['office_country']
                if 'office_state' in request.POST:
                    member.office_state_id = request.POST['office_state']
                if 'office_city' in request.POST:
                    member.office_city_id = request.POST['office_city']

                if 'office_pincode' in request.POST:
                    member.office_pincode = request.POST['office_pincode']
            if 'office_Street_address' in request.POST:
                member.office_Street_address = request.POST['office_Street_address']
            if 'office_address_line_2' in request.POST:
                member.office_address_line_2 = request.POST['office_address_line_2']
            if 'mobile' in request.POST:
                member.mobile = request.POST['mobile']
            if request.POST['home_phone'] == '' or None:
                member.home_phone = None
            else:
                member.home_phone = request.POST['home_phone']
                # member.home_phone = request.POST['home_phone']
                # if member.home_phone=='' or None:
                #     member.
            if request.POST['office_phone'] == '' or None:
                member.office_phone = None
            else:
                member.office_phone = request.POST['office_phone']
            # if 'email' in request.POST:
            #     member.email = request.POST['email']
            if 'cheque_no' in request.POST:
                member.cheque_no = request.POST['cheque_no']
            if 'bank' in request.POST:
                member.bank = request.POST['bank']
            if 'medical_registration_no' in request.POST:
                member.medical_registration_no = request.POST['medical_registration_no']
            # if 'state_registration' in request.POST:
            #     member.state_registration = request.POST['state_registration']
            if 'reg_country' in request.POST:
                member.reg_country_id = request.POST['reg_country']
            if 'reg_state' in request.POST:
                member.reg_state_id = request.POST['reg_state']
            if 'date' in request.POST:
                member.date = request.POST['date']
            if 'photo' in request.FILES:
                member.photo = request.FILES['photo']
            if 'certificate' in request.FILES:
                member.certificate = request.FILES['certificate']
            if 'agree' in request.POST:
                member.agree = request.POST['agree']
            if 'non-mem-introducer' in request.POST:
                member.non_mem_introducer = request.POST['non-mem-introducer']
            member.date = timezone.now().date()
            member.save()
            member.user.save()

            formset = qualificationFormset(request.POST)
            # Now save the data for each form in the formset
            new_qualifications = []
            if formset.is_valid():
                Qualification.objects.filter(membership=member).delete()
                for qualification in formset.cleaned_data:
                    degree = qualification['degree']
                    year = qualification['year']
                    college = qualification['college']
                    new_qualifications.append(
                        Qualification(membership=member, degree=degree, year=year, college=college))

            Qualification.objects.bulk_create(new_qualifications)

            if 'membership_introducedby' in request.POST and 'membership_introducedby2' in request.POST:
                # introducer part
                introducer_one = MemberShip.objects.get(pk=request.POST['membership_introducedby'])
                introducer_two = MemberShip.objects.get(pk=request.POST['membership_introducedby2'])
                if hasattr(member, 'membership_detail'):
                    membership_detail = member.membership_detail
                else:
                    membership_detail = MembershipDetail()
                    membership_detail.membership = member
                membership_detail.introducer_one = introducer_one
                membership_detail.introducer_two = introducer_two
                membership_detail.save()

            if 'submit' in request.POST:

                # initialize payment gateway
                order_amount = settings.RAZOR_PAY_AMOUNT
                order_currency = settings.RAZOR_PAY_CURRENCY
                order_receipt = 'order_rcptid_{}'.format(generate_random_number(6))
                client = razorpay.Client(auth=(settings.RAZOR_PAY_KEY, settings.RAZOR_PAY_SECRET))
                data = {
                    'amount': order_amount,
                    'currency': order_currency,
                    'receipt': order_receipt,
                    'payment_capture': 1
                }
                order = client.order.create(data=data)

                # save payment info in our model
                razor_payment_order = Order()
                razor_payment_order.amount = settings.RAZOR_PAY_AMOUNT
                razor_payment_order.amount_paid = order['amount_paid']
                razor_payment_order.amount_due = order['amount_due']
                razor_payment_order.membership = member
                razor_payment_order.status = order['status']
                razor_payment_order.order_id = order['id']
                razor_payment_order.order_receipt = order_receipt
                razor_payment_order.save()

                member.status = 'submitted'
                member.save()

                if hasattr(member, 'membership_status'):
                    membership_status = member.membership_status
                else:
                    membership_status = MembershipStatus()
                    membership_status.membership = member
                membership_status.status = "Please pay your membersip fees"
                membership_status.save()

                # try:
                #     # web socket notification to introducer
                #     message = "{} {} user selected you as introducer".format(request.user.first_name,
                #                                                              request.user.last_name)
                #     introducer_users = [introducer_one.user, introducer_two.user]
                #     WebNotification(request.user).send_only_notification_to_user(introducer_users, message)
                # except Exception as e:
                #     logger.info('unable to send socket notification introducer')

                
            else:
                member.status = 'draft'
                member.save()
                if request.is_ajax():
                    return JsonResponse({"message": 'saved to draft'}, status=200)

        except Exception as e:
            messages.error(request, '{}'.format(e))
            return HttpResponseRedirect(reverse("koscientific:application_form"))

        context = {
            'name': '{} {}'.format(request.user.first_name, request.user.last_name),
            'gender': request.user.membership.gender,
            'mobile': request.user.membership.mobile,
            'email': request.user.email,
            'kos_no': request.user.membership.kos_no,
            'date': request.user.membership.date,
            'auto_save_in': settings.AUTO_SAVE_IN,
            'RAZOR_PAY_KEY': settings.RAZOR_PAY_KEY,
            'RAZOR_PAY_AMOUNT': settings.RAZOR_PAY_AMOUNT,
            'RAZOR_PAY_CURRENCY': settings.RAZOR_PAY_CURRENCY,
            'razor_payment_order_id': order.get('id', None)
        }
        return render(request, 'member/payment_view.html', context)
    if hasattr(request.user, 'membership'):
        qualification_formset = qualificationFormset(
            initial=request.user.membership.qualifications.all().values('college', 'degree', 'year'))
    else:
        qualification_formset = qualificationFormset()

    user = request.user
    number = Profile.objects.get(user=request.user)
    countries = Country.objects.all()
    # used to enable show data which is saved during the draft
    if hasattr(request.user, 'membership'):
        membership = request.user.membership
        if request.user.membership.office_country:
            office_states = Region.objects.filter(country=request.user.membership.office_country)
        else:
            office_states = None

        if request.user.membership.office_state:
            office_cities = City.objects.filter(region=request.user.membership.office_state)
        else:
            office_cities = None

        if request.user.membership.recidencecountry:
            residence_states = Region.objects.filter(country=request.user.membership.recidencecountry)
        else:
            residence_states = None

        if request.user.membership.recidencestate:
            residence_cities = City.objects.filter(region=request.user.membership.recidencestate)
        else:
            residence_cities = None

        if request.user.membership.reg_country:
            reg_states = Region.objects.filter(country=request.user.membership.reg_country)
        else:
            reg_states = None
    else:
        # no membership associated
        office_states = None
        office_cities = None
        residence_states = None
        residence_cities = None
        reg_states = None
        membership = None
    context = {}
    context['qualification_formset'] = qualification_formset
    context['country'] = countries
    context['city'] = office_cities
    context['region'] = office_states

    context['residence_cities'] = residence_cities
    context['residence_states'] = residence_states

    context['reg_states'] = reg_states

    context['members'] = MemberShip.objects.filter(is_member=True)
    context['first_name'] = user.first_name
    context['last_name'] = user.last_name
    context['mobile_number'] = number.mobile_number
    context['email'] = user.email
    context['profile'] = user.profile
    context['RAZOR_PAY_CURRENCY'] = settings.RAZOR_PAY_CURRENCY
    context['RAZOR_PAY_AMOUNT'] = settings.RAZOR_PAY_AMOUNT
    context['auto_save_in'] = settings.AUTO_SAVE_IN
    context['membership'] = membership
    return render(request, 'dashboard/application_form.html', context)


def field_validation(request, field):
    ''' validate mobile number and email '''

    if field == 'mobile_number':
        mobile_number = request.GET.get('mobile_number', None)
        data = {
            'is_taken': Profile.objects.filter(mobile_number=mobile_number).exists()
        }
        return JsonResponse(data)
    if field == 'email':
        email = request.GET.get('email', None)
        data = {
            'is_taken': User.objects.filter(email__iexact=email).exists()
        }
        return JsonResponse(data)


@login_required
def profile_update(request, id):
    ''' Ask user to update their profile '''

    membership = get_object_or_404(MemberShip, pk=id)
    profile_watcher = ProfileWatcher()
    profile_watcher.is_sms_sent = True
    profile_watcher.is_mail_sent = True
    profile_watcher.user = membership.user
    try:
        # send user sms
        message = smsBody.objects.get(smskey__iexact=SmsForm.FORCE_USER_TO_PROFILE_UPDATE)
        user_full_name = "{} {}".format(membership.user.first_name, membership.user.last_name)
        message = message.smscontent.replace('{{user_full_name}}', user_full_name)
        result, response = send_sms(message, membership.user.profile.mobile_number)
    except Exception as e:
        logger.info('unable to send sms the user to update profile {}'.format(e))
        messages.error(request, 'SMS not sent {}'.format(e))
        profile_watcher.is_sms_sent = False

    try:
        # send mail to user
        mailcontent = Mail.objects.get(name__iexact=MailForm.FORCE_USER_TO_PROFILE_UPDATE)
        email_body = mailcontent.email_body
        # reverse_link = reverse("koscientific:profile")
        # link = "{0}://{1}{2}".format(request.scheme, request.get_host(), reverse_link)
        
        mail_dict = {
            'subject': mailcontent.email_subject,
            'plain_message': strip_tags(email_base_template(email_body)),
            'html_message': email_base_template(email_body),

            'recipient_list': '{}'.format(membership.user.email),
        }
        KosEmail.send_mail(**mail_dict)
        messages.success(request, 'Mail sent')
    except Exception as e:
        profile_watcher.is_mail_sent = False
        logger.info('unable to send email the user to update profile {}'.format(e))
        messages.error(request, 'Mail not sent {}'.format(e))

    profile_watcher.save()
    return HttpResponseRedirect(reverse("koscientific:profile_view", args=[membership.id]))


def profile_view(request, id):
    ''' show member profile activities details'''

    membership = get_object_or_404(MemberShip, pk=id)

    context = {
        'membership': membership,
        'profile': membership.user.profile,
        'profile_watchers': ProfileWatcher.objects.filter(user=membership.user).order_by('-created_at')
    }

    return render(request, 'request_profile/view.html', context)


@login_required
def confirm_membership(request, uidb64=None, introducer_id=None, token=None, opinion=None):
    ''' confirm membership by introducers and send mail to secretary '''

    if OneTimeLink.objects.filter(token=token).exists() and not is_token_expired(token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            membership = MemberShip.objects.get(pk=uid)
        except MemberShip.DoesNotExist:
            return HttpResponse("This link is not associated with anything")

        try:
            introducer_id = int(force_text(urlsafe_base64_decode(introducer_id)))
            if membership.membership_detail.introducer_one_id == introducer_id and membership.membership_detail.introducer_one_status == MembershipDetail.NO_ANSWER:
                if opinion == 'accept' or opinion == 'reject':
                    if opinion == 'accept':
                        membership.membership_detail.introducer_one_status = MembershipDetail.ACCEPT
                        membership.membership_detail.introducer_one_action_date = timezone.now()
                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "introducer one {} is accepted".format(
                                membership.membership_detail.introducer_one)
                            membership.membership_status.save()
                    elif opinion == 'reject':
                        membership.membership_detail.introducer_one_status = MembershipDetail.REJECT
                        membership.membership_detail.introducer_one_action_date = timezone.now()
                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "introducer one {} is rejected".format(
                                membership.membership_detail.introducer_one)
                            membership.membership_status.save()

                    OneTimeLink.objects.filter(token=token).delete()
                    membership.membership_detail.save()
                    try:
                        mailcontent = Mail.objects.get(name__iexact=MailForm.INTRODUCER_ACCEPT_OR_REJECT_RESPONSE_TO_USER)
                        introducer_full_name = "{} {}".format(membership.membership_detail.introducer_one.user.first_name,
                                                              membership.membership_detail.introducer_one.user.last_name)
                        email_body = mailcontent.email_body.replace('{{introducer_full_name}}', introducer_full_name)
                        email_body = email_body.replace('{{opinion}}', membership.membership_detail.get_introducer_one_status_display())
                        
                        mail_dict = {
                            'subject': mailcontent.email_subject,
                            'plain_message': strip_tags(email_base_template(email_body)),
                            'html_message': email_base_template(email_body),
                            'recipient_list': '{}'.format(membership.user.email)
                        }
                        KosEmail.send_mail(**mail_dict)

                    except Exception as e:
                        logger.warning('unable to send mail from introducer first membership response to applicant {}'.format(e))

            elif membership.membership_detail.introducer_two_id == introducer_id and membership.membership_detail.introducer_two_status == MembershipDetail.NO_ANSWER:
                if opinion == 'accept' or opinion == 'reject':
                    if opinion == 'accept':
                        membership.membership_detail.introducer_two_status = MembershipDetail.ACCEPT
                        membership.membership_detail.introducer_two_action_date = timezone.now()
                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "introducer two {} is accepted".format(
                                membership.membership_detail.introducer_two)
                            membership.membership_status.save()
                    elif opinion == 'reject':
                        membership.membership_detail.introducer_two_status = MembershipDetail.REJECT
                        membership.membership_detail.introducer_two_action_date = timezone.now()
                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "introducer two {} is rejected".format(
                                membership.membership_detail.introducer_two)
                            membership.membership_status.save()
                    membership.membership_detail.save()
                    OneTimeLink.objects.filter(token=token).delete()
                    try:
                        mailcontent = Mail.objects.get(name__iexact=MailForm.INTRODUCER_ACCEPT_OR_REJECT_RESPONSE_TO_USER)
                        introducer_full_name = "{} {}".format(membership.membership_detail.introducer_two.user.first_name,
                                                              membership.membership_detail.introducer_two.user.last_name)
                        email_body = mailcontent.email_body.replace('{{introducer_full_name}}', introducer_full_name)
                        email_body = email_body.replace('{{opinion}}', membership.membership_detail.get_introducer_two_status_display())
                        
                        mail_dict = {
                            'subject': mailcontent.email_subject,
                            'plain_message': strip_tags(email_base_template(email_body)),
                            'html_message': email_base_template(email_body),
                            'recipient_list': '{}'.format(membership.user.email)
                        }
                        KosEmail.send_mail(**mail_dict)
                    except Exception as e:
                        logger.warning('unable to send mail from introduc seconder membership response to applicant {}'.format(e))

        except Evaluator.DoesNotExist:
            return HttpResponse("This link is not associated with anything")

        if membership.membership_detail.introducer_one_status in [MembershipDetail.ACCEPT,
                                                                  MembershipDetail.REJECT] and membership.membership_detail.introducer_two_status in [
            MembershipDetail.ACCEPT, MembershipDetail.REJECT]:
            try:
                # send membership atuo mail to secretary
                oneTimeLink = OneTimeLink()
                oneTimeLink.name = "membership confirmation to secretary"
                oneTimeLink.token = id_generator(50)
                oneTimeLink.save()

                kwargs = {
                    "uidb64": urlsafe_base64_encode(force_bytes(membership.id)),
                    "token": oneTimeLink.token,
                    "opinion": 'accept'
                }

                accept_link = reverse("koscientific:confirm_membership_secretary", kwargs=kwargs)
                accept_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), accept_link)
                kwargs['opinion'] = 'reject'
                reject_link = reverse("koscientific:confirm_membership_secretary", kwargs=kwargs)
                reject_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), reject_link)

                email_context = {
                    'membership': membership,
                    'accept_url': accept_url,
                    'reject_url': reject_url,
                    'introducer1': membership.membership_detail.introducer_one,
                    'introducer2': membership.membership_detail.introducer_two
                }

                # html_message = render_to_string('emails/secretary/secretary_mem_accept_or_reject_mail.html',
                #                                 email_context)
                # plain_message = strip_tags(html_message)
                
                mailcontent = Mail.objects.get(name__iexact=MailForm.MEMBERSHIP_FORM_CONFIRAMTION_TO_SECRETARY)
                
                user_full_name = '{} {}'.format(membership.user.first_name, membership.user.last_name)
                introducer_one_full_name = '{} {}'.format(membership.membership_detail.introducer_one.user.first_name, membership.membership_detail.introducer_one.user.last_name)
                introducer_two_full_name = '{} {}'.format(membership.membership_detail.introducer_two.user.first_name, membership.membership_detail.introducer_two.user.last_name)
                
                email_subject = mailcontent.email_subject.replace('{{user_full_name}}', user_full_name)
                email_body = mailcontent.email_body.replace('{{user_full_name}}', user_full_name)
                email_body = email_body.replace('{{introducer_one_full_name}}', introducer_one_full_name)
                email_body = email_body.replace('{{introducer_two_full_name}}', introducer_two_full_name)
                email_body = email_body.replace('{{accept}}', accept_url)
                email_body = email_body.replace('{{reject}}', reject_url)

                mail_dict = {
                    'subject': email_subject,
                    'plain_message': strip_tags(email_base_template(email_body)),
                    'html_message': email_base_template(email_body),
                    'recipient_list': '{}'.format(settings.SECRETARY_MAIL)
                }
                logger.info("mail sending to applicant membership_form_confiramtion_to_secretary")
                KosEmail.send_mail(**mail_dict)
            except Exception as e:
                logger.error("unable to send mail to membership_form_confiramtion_to_secretary {}".format(e))

            else:
                membership.admin = "secretary"
                membership.save()

        messages.success(request, 'Thank you for selecting the option')
        return redirect('koscientific:home')
    else:
        return HttpResponse("Activation link has expired")


def confirm_membership_secretary(request, uidb64=None, token=None, opinion=None):
    ''' confirm applicant membership by secretary and screatary authentication is not required'''

    if OneTimeLink.objects.filter(token=token).exists() and not is_token_expired(token):
        try:
            id = force_text(urlsafe_base64_decode(uidb64))
            membership = MemberShip.objects.get(pk=id)
        except MemberShip.DoesNotExist:
            return HttpResponse("This link is not associated with anything")

        try:
            if membership.membership_detail.admin_status == MembershipDetail.NO_ANSWER:
                if opinion == 'accept' or opinion == 'reject':
                    if opinion == 'accept':
                        membership.membership_detail.admin_status = MembershipDetail.ACCEPT
                        membership.membership_detail.admin_action_date = timezone.now()
                        max_membership = MemberShip.objects.aggregate(Max('kos_no'))
                        membership.kos_no = max_membership['kos_no__max'] + 1
                        membership.is_provisional = True
                        membership.is_member = False
                        membership.is_active = True
                        membership.is_iis_signed = True
                        membership.save()
                        membership.user.roles.clear()
                        membership.user.roles.add(Role.MEMBER)
                        member_group = Group.objects.get(name__iexact='member')
                        membership.user.groups.clear()
                        membership.user.groups.add(member_group)

                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "Congratulations. Your Membership is provisionally approved. Your membership number is {} You have access to all resources of the society. Your Voting rights will get activated only after ratification of your membership in the AGM. Thanks".format(
                                membership.kos_no)
                            membership.membership_status.save()
                    elif opinion == 'reject':
                        membership.membership_detail.admin_status = MembershipDetail.REJECT
                        membership.membership_detail.admin_action_date = timezone.now()
                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "secretary is rejected your membership"
                            membership.membership_status.save()

                    OneTimeLink.objects.filter(token=token).delete()
                    membership.membership_detail.save()
                    try:
                        if opinion == 'accept':
                            mailcontent = Mail.objects.get(name__iexact=MailForm.AFTER_SECRETARY_APPROVE_KOS_NUMBER_TO_USER)
                            email_body = mailcontent.email_body.replace('{{kos_number}}', str(membership.kos_no))

                            mail_dict = {
                                'subject': mailcontent.email_subject,
                                'plain_message': strip_tags(email_base_template(email_body)),
                                'html_message': email_base_template(email_body),
                                'recipient_list': '{}'.format(membership.user.email)
                            }
                        elif opinion == 'reject':
                            mailcontent = Mail.objects.get(name__iexact=MailForm.AFTER_SECRETARY_NOT_APPROVE_MEMBERSHIP_TO_USER)
                            email_body = mailcontent.email_body
                            mail_dict = {
                                'subject': mailcontent.email_subject,
                                'plain_message': strip_tags(email_base_template(email_body)),
                                'html_message': email_base_template(email_body),
                                'recipient_list': '{}'.format(membership.user.email)
                            }
                        KosEmail.send_mail(**mail_dict)

                    except Exception as e:
                        logger.error("unable to send mail from to secretary membership status to applicant {}".format(e))

        except Exception as e:
            return HttpResponse("This link is not associated with anything {}".format(e))

        else:
            messages.success(request, 'Thank you for selecting the option')
            return redirect('koscientific:home')
    else:
        return HttpResponse("Activation link has expired")


def confirm_ratify_membership(request, token=None, random_token=None, opinion=None):
    ''' confirm membership by ratify '''

    if OneTimeLink.objects.filter(token=token).exists() and not is_token_expired(token):
        try:
            random_token = force_text(urlsafe_base64_decode(random_token))
            provisional_members = ProvisionalMembershipApproval.objects.filter(random_token=random_token)
        except MemberShip.DoesNotExist:
            return HttpResponse("This link is not associated with anything")

        try:
            if opinion == 'accept' or opinion == 'reject':
                if opinion == 'accept':
                    for provisional_member in provisional_members:
                        membership = get_object_or_404(MemberShip, id=provisional_member.membership.id)
                        provisional_member.status = ProvisionalMembershipApproval.ACCEPT
                        provisional_member.approved_at = timezone.now()
                        provisional_member.save()
                        membership.is_provisional = False
                        membership.is_member = True
                        membership.save()
                        # membership.user.roles.clear()
                        # membership.user.roles.add(Role.MEMBER)
                        # member_group = Group.objects.get(name__iexact='member')
                        # membership.user.groups.clear()
                        # membership.user.groups.add(member_group)
                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "AGM ratified your membership"
                            membership.membership_status.save()
                        try:
                            # web socket notification to applicant
                            message = "AGM ratified your membership"
                            applicant_user = [membership.user]
                            WebNotification(request.user).send_only_notification_to_user(applicant_user, message)
                        except Exception as e:
                            logger.info('unable to send socket notification applicant of the AGM ratification {}'.format(e))
                        try:
                            mailcontent = Mail.objects.get(name__iexact=MailForm.RATIFY_MEMBERSHIP_BY_AGM_APPROVE_TO_USER)
                            email_body = mailcontent.email_body
                            mail_dict = {
                                'subject': mailcontent.email_subject,
                                'plain_message': strip_tags(email_base_template(email_body)),
                                'html_message': email_base_template(email_body),
                                'recipient_list': '{}'.format(membership.user.email)
                            }
                            KosEmail.send_mail(**mail_dict)
                        except Exception as e:
                            logger.warning('mail not send to user on Agm ratification accept status {}'.format(e))
                            
                elif opinion == 'reject':
                    for provisional_member in provisional_members:
                        membership = get_object_or_404(MemberShip, id=provisional_member.membership.id)
                        provisional_member.status = ProvisionalMembershipApproval.REJECT
                        provisional_member.approved_at = timezone.now()
                        provisional_member.save()
                        membership.is_member = False
                        membership.save()
                        if hasattr(membership, 'membership_status'):
                            membership.membership_status.status = "AGM is rejected your membership"
                            membership.membership_status.save()
                        try:
                            mailcontent = Mail.objects.get(name__iexact=MailForm.RATIFY_MEMBERSHIP_BY_AGM_UNAPPROVE_TO_USER)
                            email_body = mailcontent.email_body
                            mail_dict = {
                                'subject': mailcontent.email_subject,
                                'plain_message': strip_tags(email_base_template(email_body)),
                                'html_message': email_base_template(email_body),
                                'recipient_list': '{}'.format(membership.user.email)
                            }
                            KosEmail.send_mail(**mail_dict)
                        except Exception as e:
                            logger.warning('mail not send to user on Agm ratification reject status {}'.format(e))
                        
                OneTimeLink.objects.filter(token=token).delete()
                
                
                
        except Exception as e:
            return HttpResponse("This link is not associated with anything {}".format(e))

        else:
            messages.success(request, 'Thank you for selecting the option')
            return redirect('koscientific:home')
    else:
        return HttpResponse("Activation link has expired")


def export_members(request):
    """ export members as csv"""
    response = HttpResponse(content_type='text/csv')
    csv_writer = csv.writer(response)
    csv_writer.writerow(['first_name',
                         'last_name',
                         'email',
                         'mobile_number',
                         'kos_no',
                         'dob',
                         'gender',
                         'home phone',
                         'office phone',
                         'medical registration no',
                         'residence street address',
                         'residence street address 2',
                         'residence country',
                         'residence state',
                         'residence city',
                         'residence pincode',
                         'office street address',
                         'office street address 2',
                         'office country',
                         'office state',
                         'office city',
                         'office pincode',
                         'introducer 1',
                         'introducer 1 status',
                         'introducer 1 date',
                         'introducer 2',
                         'introducer 2 status',
                         'introducer 2 date',
                         'admin approve',
                         'admin date',
                         'is active',
                         'is member',
                         'AGM',
                         'AGM status',
                         'is deceased',
                         'Reg country',
                         'Reg city',
                         'Last profile edited at',
                         'Last profile edited by',
                          ])
    for member in MemberShip.all_objects.filter(is_member=True).order_by('kos_no').values(
            'user__first_name',
            'user__last_name',
            'user__email',
            'user__profile__mobile_number',
            'kos_no',
            'dob',
            'gender',
            'home_phone',
            'office_phone',
            'medical_registration_no',
            'recidence_Street_address',
            'recidence_address_line_2',
            'recidencecountry',
            'recidencestate',
            'recidencecity',
            'recidence_pincode',
            'office_Street_address',
            'office_address_line_2',
            'office_country',
            'office_state',
            'office_city',
            'office_pincode',
            'membership_detail__introducer_one',
            'membership_detail__introducer_one_status',
            'membership_detail__introducer_one_action_date',
            'membership_detail__introducer_two',
            'membership_detail__introducer_two_status',
            'membership_detail__introducer_two_action_date',
            'membership_detail__admin_status',
            'membership_detail__admin_action_date',
            'is_active',
            'is_member',
            'provisional_membership_approval',
            'provisional_membership_approval__status',
            'deceased_memberships',
            'reg_country',
            'reg_state',
            'user__profile__updated_at',
            'user__profile__updated_by'
    ):  
        if member['recidencecountry']:
            member['recidencecountry'] = get_object_or_404(Country, pk=member['recidencecountry'])
        
        if member['recidencestate']:
            member['recidencestate'] = get_object_or_404(Region, pk=member['recidencestate']).name
        
        if member['recidencecity']:
            member['recidencecity'] = get_object_or_404(City, pk=member['recidencecity']).name
            
        if member['office_country']:
            member['office_country'] = get_object_or_404(Country, pk=member['office_country'])
        
        if member['office_state']:
            member['office_state'] = get_object_or_404(Region, pk=member['office_state']).name
        
        if member['office_city']:
            member['office_city'] = get_object_or_404(City, pk=member['office_city']).name
        
        if member['provisional_membership_approval__status']:
            try:
                member['provisional_membership_approval__status'] = get_object_or_404(ProvisionalMembershipApproval, pk=member['provisional_membership_approval']).get_status_display()
            except Exception as e:
                pass
            
        if member['provisional_membership_approval']:
            try:
                member['provisional_membership_approval'] = get_object_or_404(ProvisionalMembershipApproval, pk=member['provisional_membership_approval']).membership.user.email
            except Exception as e:
                pass
                        
        if member['deceased_memberships']:
            member['deceased_memberships'] = get_object_or_404(DeceasedMembership, pk=member['deceased_memberships']).get_status_display()
        
        if member['reg_country']:
            member['reg_country'] = get_object_or_404(Country, pk=member['reg_country'])
        
        if member['reg_state']:
            member['reg_state'] = get_object_or_404(Region, pk=member['reg_state']).name
            
        if member['user__profile__updated_at']:
            member['user__profile__updated_at'] = member['user__profile__updated_at'].strftime('%Y-%m-%d %H:%M:%S %p')
        if member['user__profile__updated_by']:
            member['user__profile__updated_by'] = get_object_or_404(User, pk=member['user__profile__updated_by']).email
        member = list(member.values())
        csv_writer.writerow(member)
    file_name = datetime.now().strftime("%d_%m_%Y_%I_%M_%S_%p")

    response['Content-Disposition'] = 'attachment; filename="kos_members_{}.csv"'.format(file_name)
    return response


def voter_list(request):
    """ just show ratified active members in the list"""

    memberships = MemberShip.objects.filter(is_member=True, is_provisional=False).order_by('-created_at')

    context = {
        'memberships': memberships
    }
    count = memberships.count()
    memberships = memberships
    page = request.GET.get('page', 1)
    paginator = Paginator(memberships, 10)
    try:
        memberships = paginator.page(page)
    except PageNotAnInteger:
        memberships = paginator.page(1)
    except EmptyPage:
        memberships = paginator.page(paginator.num_pages)

    index = memberships.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['memberships'] = memberships
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'voter_list/list.html', context)


def export_voter_list(request):
    """ export voter list as csv"""
    response = HttpResponse(content_type='text/csv')
    csv_writer = csv.writer(response)
    csv_writer.writerow(['first_name',
                         'last_name',
                         'email',
                         'mobile_number',
                         'kos_no',
                         'dob',
                         'gender',
                         'home phone',
                         'office phone',
                         'medical registration no',
                         'residence street address',
                         'residence street address 2',
                         'residence country',
                         'residence state',
                         'residence city',
                         'residence pincode',
                         'office street address',
                         'office street address 2',
                         'office country',
                         'office state',
                         'office city',
                         'office pincode',
                         'introducer 1',
                         'introducer 1 status',
                         'introducer 1 date',
                         'introducer 2',
                         'introducer 2 status',
                         'introducer 2 date',
                         'admin approve',
                         'admin date',
                         'is active',
                         'is member',
                         'AGM',
                         'AGM status',
                         'is deceased',
                         'Reg country',
                         'Reg city',
                         'Last profile edited at',
                         'Last profile edited by',
                          ])
    # active, member, approved
    for member in MemberShip.objects.filter(is_member=True, is_provisional=False).order_by('kos_no').values(
            'user__first_name',
            'user__last_name',
            'user__email',
            'user__profile__mobile_number',
            'kos_no',
            'dob',
            'gender',
            'home_phone',
            'office_phone',
            'medical_registration_no',
            'recidence_Street_address',
            'recidence_address_line_2',
            'recidencecountry',
            'recidencestate',
            'recidencecity',
            'recidence_pincode',
            'office_Street_address',
            'office_address_line_2',
            'office_country',
            'office_state',
            'office_city',
            'office_pincode',
            'membership_detail__introducer_one',
            'membership_detail__introducer_one_status',
            'membership_detail__introducer_one_action_date',
            'membership_detail__introducer_two',
            'membership_detail__introducer_two_status',
            'membership_detail__introducer_two_action_date',
            'membership_detail__admin_status',
            'membership_detail__admin_action_date',
            'is_active',
            'is_member',
            'provisional_membership_approval',
            'provisional_membership_approval__status',
            'deceased_memberships',
            'reg_country',
            'reg_state',
            'user__profile__updated_at',
            'user__profile__updated_by'
    ):  
        if member['recidencecountry']:
            member['recidencecountry'] = get_object_or_404(Country, pk=member['recidencecountry'])
        
        if member['recidencestate']:
            member['recidencestate'] = get_object_or_404(Region, pk=member['recidencestate']).name
        
        if member['recidencecity']:
            member['recidencecity'] = get_object_or_404(City, pk=member['recidencecity']).name
            
        if member['office_country']:
            member['office_country'] = get_object_or_404(Country, pk=member['office_country'])
        
        if member['office_state']:
            member['office_state'] = get_object_or_404(Region, pk=member['office_state']).name
        
        if member['office_city']:
            member['office_city'] = get_object_or_404(City, pk=member['office_city']).name
        
        if member['provisional_membership_approval__status']:
            try:
                member['provisional_membership_approval__status'] = get_object_or_404(ProvisionalMembershipApproval, pk=member['provisional_membership_approval']).get_status_display()
            except Exception as e:
                pass
            
        if member['provisional_membership_approval']:
            try:
                member['provisional_membership_approval'] = get_object_or_404(ProvisionalMembershipApproval, pk=member['provisional_membership_approval']).membership.user.email
            except Exception as e:
                pass
                        
        if member['deceased_memberships']:
            member['deceased_memberships'] = get_object_or_404(DeceasedMembership, pk=member['deceased_memberships']).get_status_display()
        
        if member['reg_country']:
            member['reg_country'] = get_object_or_404(Country, pk=member['reg_country'])
        
        if member['reg_state']:
            member['reg_state'] = get_object_or_404(Region, pk=member['reg_state']).name
            
        if member['user__profile__updated_at']:
            member['user__profile__updated_at'] = member['user__profile__updated_at'].strftime('%Y-%m-%d %H:%M:%S %p')
        if member['user__profile__updated_by']:
            member['user__profile__updated_by'] = get_object_or_404(User, pk=member['user__profile__updated_by']).email
        member = list(member.values())
        csv_writer.writerow(member)
    file_name = datetime.now().strftime("%d_%m_%Y_%I_%M_%S_%p")

    response['Content-Disposition'] = 'attachment; filename="kos_members_voters{}.csv"'.format(file_name)
    return response


def billings(request):
    """ show billing """

    paid_memberships = MemberShip.objects.exclude(status__iexact='draft').order_by('-created_at')

    count = paid_memberships.count()
    page = request.GET.get('page', 1)
    paginator = Paginator(paid_memberships, 10)
    try:
        paid_memberships = paginator.page(page)
    except PageNotAnInteger:
        paid_memberships = paginator.page(1)
    except EmptyPage:
        paid_memberships = paginator.page(paginator.num_pages)

    index = paid_memberships.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context = {}
    context['count'] = count
    context['paid_memberships'] = paid_memberships
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'billings/list.html', context)


class BillingDetailView(DetailView):
    model = MemberShip
    template_name = 'billings/detail.html'
    pk_url_kwarg = 'membership_id'
    context_object_name = 'membership'

@login_required
def eye_views(request):
    return render(request, 'eye/about_eye_care.html')


def mass_sms(request, to):
    """
    sending mass sms to user
    """
    sms_to = None
    if to.lower() == 'members':
        sms_to = 'members'
    else:
        sms_to = 'voters'
    if request.method == "POST":
        form = MassSmsForm(request.POST)
        if form.is_valid():
            sms_form = form.save(commit=False)
            if to.lower() == 'voters':
                sms_form.comment = "mass sms sending for voters"
                sms_form.to = MassSms.VOTERS
            elif to.lower() == 'members':
                sms_form.comment = "mass sms sending for members"
                sms_form.to = MassSms.MEMBERS
            sms_form.sender = request.user
            sms_form.status = MassSms.SENDING
            sms_form.save()

            try:
                # send mass sms
                message = form.cleaned_data['message']
                if to.lower() == 'voters':
                    mobile_numbers = MemberShip.objects.filter(is_member=True, is_provisional=False).order_by(
                        '-created_at').values_list('user__profile__mobile_number', flat=True)
                elif to.lower() == 'members':
                    # active members
                    mobile_numbers = MemberShip.objects.filter(user__roles__in=[Role.MEMBER, ]).order_by(
                        '-created_at').values_list('user__profile__mobile_number', flat=True)
                
                mobile_numbers = [num for num in mobile_numbers if num is not None]
                # mobile_numbers = ','.join(mobile_numbers)
                result, response = send_mass_sms(message, mobile_numbers)
                
                if response.status_code == 414:
                    messages.error(request, 'Request-URI Too Large')
                    sms_form.status = MassSms.NOT_SENT
                    sms_form.save()
                    logger.warning('Request-URI Too Large')
                    return render(request, 'voter_list/mass_sms.html', context={"form": form, "sms_to":sms_to})
                else:
                    sms_form.status = MassSms.SENT
                    sms_form.save()
                    
            except Exception as e:
                messages.error(request, 'Mass sms not sent {}'.format(e))
                sms_form.status = MassSms.NOT_SENT
                sms_form.save()
                logger.warning('unable to send mass sms to users {}'.format(e))
                return render(request, 'voter_list/mass_sms.html', context={"form": form,"sms_to":sms_to})

            if to.lower() == 'voters':
                messages.success(request, 'Mass sms sent to voters')
                return HttpResponseRedirect(reverse('koscientific:voter_list'))
            elif to.lower() == 'members':
                messages.success(request, 'Mass sms sent to members')
                return HttpResponseRedirect(reverse('koscientific:member_list'))
    else:
        form = MassSmsForm()
    return render(request, 'voter_list/mass_sms.html', context={"form": form,"sms_to":sms_to})


def mass_mail(request, to):
    """
    sending mass mail to user
    """
    email_to = None
    if to.lower() == 'members':
        email_to = 'members'
    else:
        email_to = 'voters'
    if request.method == "POST":
        form = MassMailForm(request.POST)
        if form.is_valid():
            mail_form = form.save(commit=False)
            if to.lower() == 'voters':
                mail_form.comment = "mass mail sending for voters"
                mail_form.to = MassMail.VOTERS
            elif to.lower() == 'members':
                mail_form.comment = "mass mail sending for members"
                mail_form.to = MassMail.MEMBERS
            mail_form.sender = request.user
            mail_form.subject = form.cleaned_data['subject']
            mail_form.body = form.cleaned_data['body']

            mail_form.status = MassMail.SENDING
            mail_form.save()

            try:
                # send mass mail
                if to.lower() == 'voters':
                    mails = MemberShip.objects.filter(is_member=True, is_provisional=False).order_by(
                        '-created_at').values_list('user__email', flat=True)
                elif to.lower() == 'members':
                    # active members
                    mails = MemberShip.all_objects.filter(user__roles__in=[Role.MEMBER, ]).order_by(
                        '-created_at').values_list('user__email', flat=True)
                import re 
                valid_mails = []
                regex = '(\w+[.|\w])*@(\w+[.])*\w+'
                for mail in mails:
                    if(re.search(regex,mail)):  
                        valid_mails.append(mail)
                        logger.info(mail)
                        logger.info('all emails count is {}'.format(mail))
                        
                mail_dict = {
                    'subject': form.cleaned_data['subject'],
                    'plain_message': strip_tags(form.cleaned_data['body']),
                    'html_message': form.cleaned_data['body'],
                    'recipient_list': valid_mails
                }
                logger.info('valid emails count is {}'.format(valid_mails))
                logger.info('all emails count is {}'.format(len(mails)))
                
                KosEmail.mass_mail(**mail_dict)
                mail_form.status = MassMail.SENT
                mail_form.save()
            except Exception as e:
                messages.error(request, 'Mass mail not due to error sent {}'.format(e))
                mail_form.status = MassMail.NOT_SENT
                mail_form.save()
                logger.warning('unable to send mass mail to users {}'.format(e))
                return render(request, 'voter_list/mass_mail.html', context={"form": form})

            if to.lower() == 'voters':
                messages.success(request, 'Mass mail sent voters')
                return HttpResponseRedirect(reverse('koscientific:voter_list'))
            elif to.lower() == 'members':
                messages.success(request, 'Mass mail sent members')
                return HttpResponseRedirect(reverse('koscientific:member_list'))
    else:
        form = MassMailForm()
    return render(request, 'voter_list/mass_mail.html', context={"form": form,"email_to":email_to})


def service_views(request):
    return render(request, 'eye/service.html')


@login_required
def invite_non_members_evaluator(request):
    """
    invite non kos member as evaluator
    admin will invite via mail sms and email if accept then redirect to mobile otp page
    send cc mail to kos officials
    """
    if request.method == 'POST':
        evaluator_invite_form = EvaluatorInviteForm(request.POST)
        if evaluator_invite_form.is_valid():
            invited_evaluator = evaluator_invite_form.save(commit=True)
            invited_evaluator.invited_by = request.user
            invited_evaluator.save()
            
            evaluator = Evaluator()
            evaluator.status = "inactive"
            evaluator.mail_status = Evaluator.NOT_SENT
            evaluator.save()
            evaluator.section.set(evaluator_invite_form.cleaned_data['sections'])
            evaluator.save()
            invited_evaluator.evaluator = evaluator
            invited_evaluator.save()

            try:
                # send sms to non kos member evaluator
                message = smsBody.objects.get(smskey__iexact=SmsForm.NON_KOS_EVALUATOR_INVITE)
                send_sms(message.smscontent, invited_evaluator.mobile_number)
            except Exception as e:
                logger.warning('unable to send evaluator invite sms to non kos user {}'.format(e))

            try:
                oneTimeLink = OneTimeLink()
                oneTimeLink.name = "non kos member evaluator invite link"
                oneTimeLink.token = id_generator(50)
                oneTimeLink.save()

                kwargs = {
                    "evaluator_invite_id": urlsafe_base64_encode(force_bytes(invited_evaluator.pk)),
                    "token": oneTimeLink.token,
                    "opinion": 'accept'
                }

                confirm_url = reverse("koscientific:confirm_non_member_evaluator_invite", kwargs=kwargs)
                confirm_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), confirm_url)

                kwargs['opinion'] = 'reject'
                reject_link = reverse("koscientific:confirm_non_member_evaluator_invite", kwargs=kwargs)
                reject_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), reject_link)

                email_context = {
                    'invited_evaluator': invited_evaluator,
                    'sections': evaluator.section.all(),
                    'accept_url': confirm_url,
                    'reject_url': reject_url
                }
                html_message = render_to_string('emails/evaluator/non_kos_evaluator_invite.html', email_context)
                plain_message = strip_tags(html_message)
                officials_mails = [settings.INFO_KOS_ONLINE_MAIL, settings.SCIENTIFIC_CHAIRMAN]
                # send cc mail to member to become evaluator
                mail_dict = {
                    'subject': "Invitation to Evaluator",
                    'plain_message': plain_message,
                    'html_message': html_message,
                    'to': ['{}'.format(evaluator_invite_form.cleaned_data['email'])],
                    'cc': officials_mails,
                }
                KosEmail.send_multi_alternatives_email(**mail_dict)
                logger.info('mail sent to invite non kos evaluator')
                evaluator.mail_status = Evaluator.NO_ANSWER
                evaluator.save()
            except Exception as e:
                logger.warning('unable to send mail to invite non kos evaluator {}'.format(e))

            messages.success(request, 'Invitation sent successfully!')
            return HttpResponseRedirect(reverse('koscientific:evaluter_list'))
    else:
        evaluator_invite_form = EvaluatorInviteForm()
    return render(request, 'evalutor/non_member/invite_add_edit.html', {'form': evaluator_invite_form})


def evaluator_non_member_list(request):
    """
    show bootstrap table for non kos evaluator
    """
    all_evaluator = EvaluatorInvite.objects.all().order_by('-created_at')
    count = all_evaluator.count()
    context = {
        'all_evaluator': all_evaluator,
    }
    all_evaluator = all_evaluator
    page = request.GET.get('page', 1)
    paginator = Paginator(all_evaluator, 10)
    try:
        all_evaluator = paginator.page(page)
    except PageNotAnInteger:
        all_evaluator = paginator.page(1)
    except EmptyPage:
        all_evaluator = paginator.page(paginator.num_pages)

    index = all_evaluator.number - 1
    # This value is maximum index of pages, so the last page - 1
    max_index = len(paginator.page_range)
    # range of 7, calculate where to slice the list
    start_index = index - 3 if index >= 3 else 0
    end_index = index + 4 if index <= max_index - 4 else max_index
    # new page range
    page_range = paginator.page_range[start_index:end_index]

    # showing first and last links in pagination
    if index >= 4:
        start_index = 4
    if end_index - index >= 1 and end_index != max_index:
        end_index = max_index
    else:
        end_index = max_index
    context['count'] = count
    context['all_evaluator'] = all_evaluator
    context['page_range'] = page_range
    context['start_index'] = start_index
    context['end_index'] = end_index
    return render(request, 'evalutor/non_member/invite_list.html', context)


def confirm_non_member_evaluator_invite(request, evaluator_invite_id, token, opinion):
    """
    Take non member evaluator opinion to become evaluator
    if accepted create user and assigin role and create profile and make status active
    and send otp to verify 
    """
    if OneTimeLink.objects.filter(token=token).exists() and not is_token_expired(token):
        try:
            invited_evaluator_id = force_text(urlsafe_base64_decode(evaluator_invite_id))
            invited_evaluator = EvaluatorInvite.objects.get(pk=invited_evaluator_id)
        except User.DoesNotExist:
            logger.warning("given non member evaluator not present")
            return HttpResponse("This link is not associated with anything")

        if opinion.lower() == 'accept':
            
            
            # create user
            user = User.objects.create_user(invited_evaluator.email, invited_evaluator.email)
            user.first_name = invited_evaluator.first_name
            user.last_name = invited_evaluator.last_name
            user.save()
            
            # updated evaluator
            evaluator = get_object_or_404(Evaluator, pk=invited_evaluator.evaluator.pk)
            evaluator.mail_status = Evaluator.ACCEPT
            evaluator.status = "active"
            evaluator.user = user
            evaluator.save()

            # create profile
            user_profile, is_created = Profile.objects.get_or_create(user=user)
            user_profile.mobile_number = invited_evaluator.mobile_number
            user_profile.save()
            
            # assign role
            evaluator_group = Group.objects.get(name__iexact='Evaluator_non_member')
            user.groups.add(evaluator_group)
            user.roles.add(Role.EVALUATOR)
            
            # message
            messages.success(request, """Thank you, for accept the request to become kos evaluator,
                            You can login to account """)
            
            OneTimeLink.objects.filter(token=token).delete()
            
            # send transactional otp message
            otp = generate_otp()
            try:
                message = smsBody.objects.get(smskey__iexact=SmsForm.NON_KOS_EVALUATOR_INVITE_OTP_MESSAGE)
                message = message.smscontent.replace('{{otp}}', otp)
                result, response = send_otp_sms(message, int(user.profile.mobile_number), otp)
            except Exception as e:
                messages.info(request, "error while sending OTP {}".format(e))
                form = OtpForm()  
                return render(request=request,
                                template_name="accounts/otp_verify.html",
                                context={"form": form})

            OTP.objects.create(
                sms_transaction_id=response['request_id'],
                user=user,
                otp=otp,
            )
            return HttpResponseRedirect(reverse('koscientific:otp_verify', kwargs={'sms_trans_id':response['request_id']}))
        elif opinion.lower() == 'reject':
            # invited_evaluator.evaluator_status = EvaluatorInvite.INACTIVE
            invited_evaluator.mail_status = EvaluatorInvite.REJECTED
            invited_evaluator.save()
            messages.success(request, "Thank you, for your opinion")
            OneTimeLink.objects.filter(token=token).delete()
            return HttpResponseRedirect(reverse('koscientific:main_login'))
        
        
        return redirect('koscientific:main_register_non')
    else:
        return HttpResponse("Activation link has expired")

