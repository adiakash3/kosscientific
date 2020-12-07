from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import *
from django_select2 import forms as s2forms
from django_select2.forms import Select2MultipleWidget
from django.forms import ModelChoiceField
from django.core.exceptions import ValidationError


class NewUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    mobile_number = forms.CharField(max_length=13)

    class Meta:
        model = User
        fields = ("email", "password1", "password2", 'mobile_number')

    def save(self, commit=True):
        user = super(NewUserCreationForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        user.username = self.cleaned_data["email"]
        mobile_number = self.cleaned_data["mobile_number"]
        if commit:
            user.save()
            Profile.objects.get_or_create(user=user, mobile_number=mobile_number)
        return user



class OtpForm(forms.ModelForm):
    class Meta:
        model = OTP
        fields = ['otp']


class MobileNumberForm(forms.Form):
    mobile_number = forms.CharField(max_length=13)

class ResetPasswordForm(forms.Form):
    input_text = forms.CharField(max_length=250)
    
class NewPasswordForm(forms.Form):
    password1 = forms.CharField(max_length=20, min_length=8)
    password2 = forms.CharField(max_length=20, min_length=8)

    def clean(self):
        cleaned_data = super(NewPasswordForm, self).clean()
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("passwords do not match")

class PlaceholderSelect(forms.Select):
    def create_option(self, *args,**kwargs):
        option = super().create_option(*args,**kwargs)
        if not option.get('value'):
            option['disabled'] = True
            option['selected'] = True
            option['label'] = "Select degree"
            option['attrs']['disabled'] = True
            option['attrs']['selected'] = True
            option['attrs']['label'] = "Select degree"
        # else:
        #     option['attrs']['selected'] = False
        #     option['selected'] = False
        return option
    
class QualificationForm(forms.ModelForm):
    DEGREE_STATUS = (
        ("",'Select degree'),
        ('MBBS', 'MBBS'),
        ('DOMS', 'DOMS'),
        ('MS', 'MS'),
        ('MD', 'MD'),
        ('FRCS', 'FRCS'),
        ('FRCOG', 'FRCOG'),
    )
    degree = PlaceholderSelect(choices=DEGREE_STATUS)
    class Meta:
        model = Qualification

        fields = [
            'degree',
            'year',
            'college',
        ]

        widgets = {
            'degree': PlaceholderSelect(attrs={'class': 'formset-field col-10', 'required': 'true'}),
            'year': forms.TextInput(attrs={'class': 'formset-field', 'required': 'true'}),
            'college': forms.TextInput(attrs={'class': 'formset-field', 'required': 'true'})
        }
        
        
#dummy django form
class DemoForm(forms.ModelForm):
    class Meta:
        model= Demo
        fields= ["firstname", "lastname", "email", "comment"]


class EventForm(forms.ModelForm):
    
    class Meta:
        model = Event
        exclude =['created_by']
        
    def __init__(self, *args, **kwargs):
        super(EventForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
        self.fields['start_date'].widget.attrs['required autocomplete'] = "off"
        self.fields['end_date'].widget.attrs['required autocomplete'] = "off"
        self.fields['status'].widget.attrs['class'] = "select2_demo_1"
        


class ProfileInterestForm(forms.ModelForm):
    area_of_interests = forms.ModelMultipleChoiceField(queryset=AreaOfInterest.objects.filter(status = AreaOfInterest.ACTIVE),
                                                        widget=Select2MultipleWidget,
                                                        required=False)

    class Meta:
        model = Profile
        fields = ['area_of_interests',]
        
    def __init__(self, *args, **kwargs):
        super(ProfileInterestForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
        
        
class FeedbackForm(forms.ModelForm):

    class Meta:
        model = Feedback
        exclude =['created_by']
   
class MyModelChoiceField(ModelChoiceField):
    def label_from_instance(self, obj):
        return "%s %s | %s"%(obj.user.first_name,
                              obj.user.last_name,
                              obj.kos_no)
    
class EvaluatorAddForm(forms.ModelForm):
    """ invite the member to become evalutor"""
    membership = MyModelChoiceField(queryset=MemberShip.objects.none(),
                                         empty_label='Select the member')
    section = forms.ModelMultipleChoiceField(queryset=Section.objects.filter(status__iexact='ACTIVE'),
                                            widget=Select2MultipleWidget,
                                            required=True,
                                            label="Choose section",
                                            help_text='select upto 3 sections',)
    class Meta:
        model = Evaluator
        fields = ['membership', 'section']
        
    def __init__(self, *args, **kwargs):
        super(EvaluatorAddForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
        self.fields['membership'].widget.attrs['class'] = "select2_demo_1"
        # self.fields['membership'].label_from_instance = lambda obj: "%s" % obj.get_full_name()

    
    def clean_section(self):
        value = self.cleaned_data['section']
        if len(value) > 3:
            raise forms.ValidationError("You can't select more than 3 sections.")
        return value
    
    def save(self, commit=True):
        user_author = super(EvaluatorAddForm, self).save(commit=False)
        if commit:
            user_author.save()
            user_author.section.set(self.cleaned_data['section'])
        return user_author


class EvaluatorEditForm(forms.ModelForm):
    """ invite the member to become evalutor"""
    section = forms.ModelMultipleChoiceField(queryset=Section.objects.filter(status__iexact='ACTIVE'),
                                            widget=Select2MultipleWidget,
                                            required=True,
                                            label="Choose section",
                                            help_text='select upto 3 sections')
    class Meta:
        model = Evaluator
        fields = ['section']
        
    def __init__(self, *args, **kwargs):
        super(EvaluatorEditForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
            
    def clean_section(self):
        value = self.cleaned_data['section']
        if len(value) > 3:
            raise forms.ValidationError("You can't select more than 3 sections.")
        return value

class MassSmsForm(forms.ModelForm):
    message = forms.CharField(max_length=160, required=True)
    
    class Meta:
        model = MassSms
        fields = ['message']
    
class MassMailForm(forms.ModelForm):
    
    class Meta:
        model = MassMail
        fields = ['subject', 'body']
        
        
class AuthorLimitForm(forms.Form):
    limit = forms.IntegerField(min_value=3, required=True,
                               label="Total number of authors",
                                help_text='minimum 3 co-authors required')
    max_non_kos_member_limit = forms.IntegerField(required=True,
                               label="Maximum permitted non KOS authors")
    
    def __init__(self, *args, **kwargs):
        super(AuthorLimitForm, self).__init__(*args, **kwargs)
        # self.fields['limit'].widget.attrs['class'] = "form-control"
        # self.fields['max_non_kos_member_limit'].widget.attrs['class'] = "form-control"
    
    def clean(self):
        cleaned_data = super().clean()
        limit = cleaned_data.get("limit")
        max_non_kos_member_limit = cleaned_data.get("max_non_kos_member_limit")

        if not limit >= (max_non_kos_member_limit+3):
            self.add_error('max_non_kos_member_limit', "Maximum permitted non KOS authors limit and total number of authors minimum difference should be 3, hint make less than or equal to {}".format(limit-3))
            
        
class AuthorIcLimitForm(forms.Form):
    limit = forms.IntegerField(min_value=3, max_value=20, required=True,
                               label="Total number of co-instructors",
                                help_text='minimum 2 co-instructors required')
    max_non_kos_member_limit = forms.IntegerField(required=True,
                               label="Maximum permitted non KOS instructors")
        
    def clean(self):
        cleaned_data = super().clean()
        limit = cleaned_data.get("limit")
        max_non_kos_member_limit = cleaned_data.get("max_non_kos_member_limit")

        if not limit >= (max_non_kos_member_limit+2):
            self.add_error('max_non_kos_member_limit', "Maximum permitted non KOS instructors limit and total number of instructors minimum difference should be 2, hint make less than or equal to {}".format(limit-2))
            
    
class EvaluatorInviteForm(forms.ModelForm):
    """
    Invite the non kos member to become evaluator
    """
    sections = forms.ModelMultipleChoiceField(queryset=Section.objects.filter(status__iexact='ACTIVE'),
                                             widget=Select2MultipleWidget,
                                             required=True,
                                             label="Choose section",
                                             help_text='select upto 3 sections', )
    class Meta:
        model = EvaluatorInvite
        fields = ['first_name', 'last_name', 'email', 'mobile_number', 'sections']

    def __init__(self, *args, **kwargs):
        super(EvaluatorInviteForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
        self.fields['sections'].widget.attrs['class'] = "select2_demo_1"
        for key in self.fields:
            self.fields[key].required = True 

    def clean_sections(self):
        value = self.cleaned_data['sections']
        if len(value) > 3:
            raise forms.ValidationError("You can't select more than 3 sections.")
        return value
    
    def clean_email(self):
        email = self.cleaned_data['email']
        # validation1
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email already registered in member database")
        # validation2
        elif EvaluatorInvite.objects.filter(email=email).exists():
            raise forms.ValidationError("This email user already invited")
        return email
    
    def clean_mobile_number(self):
        mobile_number = self.cleaned_data['mobile_number']
        # validation1
        if Profile.objects.filter(mobile_number=mobile_number).exists():
            raise forms.ValidationError("This mobile number already registered in member database")
        # validation2
        elif EvaluatorInvite.objects.filter(mobile_number=mobile_number).exists():
            raise forms.ValidationError("This mobile number user already invited")
        return mobile_number


class SmsForm(forms.ModelForm):
    
    USER_REGISTRATION = 'user_registration'
    USER_REGISTRATION_OTP_VERIFICATION = 'user_registration_otp_verification'
    USER_RESEND_OTP = 'user_resend_otp'
    COMMON_OTP_MESSAGE = 'common_otp_message'
    USER_FORGOT_PASSWORD_OTP_REQUEST = 'user_forgot_otp_request'
    USER_MEMBERSHIP_SUBMISSION_INTRODUCER_MESSAGE = 'user_membership_submission_introducer_message'
    USER_MEMBERSHIP_SUBMISSION = 'user_membership_submission'
    FREE_PAPER_SUBMISSION_TO_APPLICANT = 'free_paper_submission_to_applicant'
    IC_PAPER_SUBMISSION_TO_APPLICANT = 'ic_paper_submission_to_applicant'
    VIDEO_PAPER_SUBMISSION_TO_APPLICANT = 'video_paper_submission_to_applicant'
    FREE_PAPER_SUBMISSION_TO_EVALUATOR = 'free_paper_submission_to_evaluator'
    IC_PAPER_SUBMISSION_TO_EVALUATOR = 'ic_paper_submission_to_evaluator'
    VIDEO_PAPER_SUBMISSION_TO_EVALUATOR = 'video_paper_submission_to_evaluator'
    
    FREE_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER = 'free_paper_submission_to_preseting_co_author_non_kos_member'
    IC_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER = 'ic_paper_submission_to_preseting_co_author_non_kos_member'
    VIDEO_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER = 'video_paper_submission_to_preseting_co_author_non_kos_member'
    
    KOS_EVALUATOR_INVITE = 'kos_evaluator_invite'
    NON_KOS_EVALUATOR_INVITE = 'non_kos_evaluator_invite'
    NON_KOS_EVALUATOR_INVITE_OTP_MESSAGE = 'non_kos_evaluator_invite_otp_message'
    PAYMENT_CAPTURE_TO_USER = 'payment_capture_to_user'
    FORCE_USER_TO_PROFILE_UPDATE = 'force_user_to_profile_update'
    
    SMS_KEY_CONSTANTS = (
        (USER_REGISTRATION, 'User registration message'),
        (USER_REGISTRATION_OTP_VERIFICATION, 'User registration otp verification message'),
        (USER_RESEND_OTP, 'User resend otp message'),
        (COMMON_OTP_MESSAGE, 'User common otp message'),
        (USER_FORGOT_PASSWORD_OTP_REQUEST, 'User forgot new otp request message'),
        (USER_MEMBERSHIP_SUBMISSION_INTRODUCER_MESSAGE, 'Introducer will get the message when user submitted the membership form'),
        (USER_MEMBERSHIP_SUBMISSION, 'User membership submission confirmation message'),
        (FREE_PAPER_SUBMISSION_TO_APPLICANT, 'User will get message when free paper submitted message'),
        (IC_PAPER_SUBMISSION_TO_APPLICANT, 'User will get message when IC paper submitted message'),
        (VIDEO_PAPER_SUBMISSION_TO_APPLICANT, 'User will get message when video paper submitted message'),
        
        (FREE_PAPER_SUBMISSION_TO_EVALUATOR, 'Evaluator will get the message when free paper submitted by the user'),
        (IC_PAPER_SUBMISSION_TO_EVALUATOR, 'Evaluator will get the message when ic paper submitted by the user'),
        (VIDEO_PAPER_SUBMISSION_TO_EVALUATOR, 'Evaluator will get the message when video paper submitted by the user'),
        
        (FREE_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER, 'Presenting and co author and non kos member author will get the message when free paper submitted by the user'),
        (IC_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER, 'Presenting and co author and non kos member author will get the message when ic paper submitted by the user'),
        (VIDEO_PAPER_SUBMISSION_TO_PRESETING_CO_AUTHOR_NON_KOS_MEMBER, 'Presenting and co author and non kos member author will get the message when video paper submitted by the user'),
        
        (KOS_EVALUATOR_INVITE, 'Evaluator will get the message when admin invites'),
        (NON_KOS_EVALUATOR_INVITE, 'Evaluator will get the message when admin invites'),
        (NON_KOS_EVALUATOR_INVITE_OTP_MESSAGE, 'Non kos evaluator will get the message when accpet link click and recieve otp'),
        (PAYMENT_CAPTURE_TO_USER, 'User will get the successful payment capture message'),
        (FORCE_USER_TO_PROFILE_UPDATE, 'Force user to update thier profile'),
        
    )
    
    smskey = forms.ChoiceField(widget=forms.Select())
    class Meta:
        model = smsBody
        fields = ['smskey', 'smscontent']
        
    def __init__(self, *args, **kwargs):
        super(SmsForm, self).__init__(*args, **kwargs)
        self.fields['smskey'].choices = get_sms_remaining_content()
      
def get_sms_remaining_content():
    return [(o[0], o[1])  for o in SmsForm.SMS_KEY_CONSTANTS if o[0] not in smsBody.objects.all().values_list('smskey', flat=True)]
    
    
class SmsEditForm(forms.ModelForm):
    smskey = forms.ChoiceField(choices=SmsForm.SMS_KEY_CONSTANTS, disabled=True)
    class Meta:
        model = smsBody
        fields = ['smskey', 'smscontent']
        
        
class MailForm(forms.ModelForm):
    USER_REGISTRATION = 'user_registration'
    FORGOT_PASSWORD_OTP_REQUEST = 'forgot_password_otp_request'
    RESEND_OTP_REQUEST = "resend_otp_request"
    USER_MEMBERSHIP_SUBMISSION_INTRODUCER_MESSAGE = 'user_membership_submission_introducer_message'
    MEMBERSHIP_CONFIRMATION_SUBMISSION_TO_USER = 'membership_confirmation_submission_to_user'
    
    FREE_PAPER_SUBMISSION_TO_APPLICANT = 'free_paper_submission_to_applicant'
    IC_PAPER_SUBMISSION_TO_APPLICANT = 'ic_paper_submission_to_applicant'
    VIDEO_PAPER_SUBMISSION_TO_APPLICANT = 'video_paper_submission_to_applicant'
    FREE_PAPER_SUBMISSION_TO_EVALUATOR = 'free_paper_submission_to_evaluator'
    IC_PAPER_SUBMISSION_TO_EVALUATOR = 'ic_paper_submission_to_evaluator'
    VIDEO_PAPER_SUBMISSION_TO_EVALUATOR = 'video_paper_submission_to_evaluator'
    
    KOS_EVALUATOR_INVITE = 'kos_evaluator_invite'
    NON_KOS_EVALUATOR_INVITE = 'non_kos_evaluator_invite'
    
    PAYMENT_CAPTURE_TO_USER = 'payment_capture_to_user'
    PAYMENT_CAPTURE_TO_KOS_INFO = 'payment_capture_to_kos_info'
    
    FORCE_USER_TO_PROFILE_UPDATE = 'force_user_to_profile_update'
    
    INTRODUCER_ACCEPT_OR_REJECT_RESPONSE_TO_USER = 'introducer_accept_or_reject_response_to_user'
    MEMBERSHIP_FORM_CONFIRAMTION_TO_SECRETARY = 'membership_form_confiramtion_to_secretary'
    AFTER_SECRETARY_APPROVE_KOS_NUMBER_TO_USER = 'after_sceretary_approve_kos_number_to_user'
    AFTER_SECRETARY_NOT_APPROVE_MEMBERSHIP_TO_USER = 'after_sceretary_not_approve_membership_to_user'
    
    RATIFY_MEMBERSHIP_BY_AGM_TO_AGM = 'ratify_membership_by_agm_to_agm'
    RATIFY_MEMBERSHIP_BY_AGM_APPROVE_TO_USER = 'ratify_membership_by_agm_approve_to_user'
    RATIFY_MEMBERSHIP_BY_AGM_UNAPPROVE_TO_USER = 'ratify_membership_by_agm_unapprove_to_user'
    
    MEMBER_DECEASED = 'member_deceased'
    MEMBER_RESIGN = 'member_resign'
    MARKS_DIFFERENCE_TO_ADMIN = 'marks_difference_to_admin'
    
    MAIL_KEY_CONSTANTS = (
        (USER_REGISTRATION, 'User will receive mail when account successful created'),
        (USER_MEMBERSHIP_SUBMISSION_INTRODUCER_MESSAGE, 'Introducer will receive mail when user submitted the membership form'),
        (MEMBERSHIP_CONFIRMATION_SUBMISSION_TO_USER, 'Applicant will receive mail when membership submission form at first level'),
        
        (FREE_PAPER_SUBMISSION_TO_APPLICANT, 'Applicant will receive mail when free paper submitted'),
        (IC_PAPER_SUBMISSION_TO_APPLICANT, 'Applicant will receive mail when IC paper submitted'),
        (VIDEO_PAPER_SUBMISSION_TO_APPLICANT, 'Applicant will receive mail when video paper submitted'),
        (FREE_PAPER_SUBMISSION_TO_EVALUATOR, 'Evaluator will receive mail when free paper submitted by the user'),
        (IC_PAPER_SUBMISSION_TO_EVALUATOR, 'Evaluator will receive mail when ic paper submitted by the user'),
        (VIDEO_PAPER_SUBMISSION_TO_EVALUATOR, 'Evaluator will receive mail when video paper submitted by the user'),
        
        (KOS_EVALUATOR_INVITE, 'Evaluator will receive mail when admin invites'),
        (NON_KOS_EVALUATOR_INVITE, 'Non Evaluator will receive mail when admin invites'),
        
        (PAYMENT_CAPTURE_TO_USER, 'User will receive mail when successful payment done'),
        (PAYMENT_CAPTURE_TO_KOS_INFO, 'Kos@info  will receive mail when successful payment capture'),
        
        (FORCE_USER_TO_PROFILE_UPDATE, 'Applicant will receive mail when admin Force  to user update thier profile'),
        
        (INTRODUCER_ACCEPT_OR_REJECT_RESPONSE_TO_USER, 'Applicant will receive mail from introducers as response'),
        (MEMBERSHIP_FORM_CONFIRAMTION_TO_SECRETARY, 'Secreatory will receive mail after 2 introducer accepted the membership'),
        (AFTER_SECRETARY_APPROVE_KOS_NUMBER_TO_USER, 'Applicant will receive mail when secretory approve with kos number'),
        (AFTER_SECRETARY_NOT_APPROVE_MEMBERSHIP_TO_USER, 'Applicant will receive mail when secretory unapprove with membership'),
        
        (RATIFY_MEMBERSHIP_BY_AGM_TO_AGM, 'Agm will receive mail whenever admin ratify the provisional member'),
        (RATIFY_MEMBERSHIP_BY_AGM_APPROVE_TO_USER, 'Member will receive mail whenever AGM approve'),
        (RATIFY_MEMBERSHIP_BY_AGM_UNAPPROVE_TO_USER, 'Member will receive mail whenever AGM unapproved'),
        
        (MEMBER_DECEASED, 'Info@kos will receive To mail when member deceased'),
        (MEMBER_RESIGN, 'Member will receive To mail and Info@kos will receive CC mail when member resign'),
        (MARKS_DIFFERENCE_TO_ADMIN, 'Admin will receive mail marks differnece 30%'),
        (FORGOT_PASSWORD_OTP_REQUEST, 'User will receive mail when they request forgot password otp'),
        (RESEND_OTP_REQUEST, 'User will receive mail when when they request resend otp'),
    )
    
    name = forms.ChoiceField(widget=forms.Select())
    class Meta:
        model = Mail
        fields = '__all__'
        
    def __init__(self, *args, **kwargs):
        super(MailForm, self).__init__(*args, **kwargs)
        self.fields['name'].choices = get_mail_remaining_content()
      
def get_mail_remaining_content():
    return [(o[0], o[1])  for o in MailForm.MAIL_KEY_CONSTANTS if o[0] not in Mail.objects.all().values_list('name', flat=True)]
    
        
class MailEditForm(forms.ModelForm):
    name = forms.ChoiceField(choices=MailForm.MAIL_KEY_CONSTANTS, disabled=True)
    class Meta:
        model = Mail
        fields = ['name', 'email_subject','email_body']
        