from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from ckeditor.widgets import CKEditorWidget
from .models import *
from django import forms
from cities_light.models import City, Country, Region
from django.contrib.admin.sites import NotRegistered
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django import forms
from django.contrib.auth.forms import (
    AdminPasswordChangeForm, UserChangeForm, UserCreationForm,
)


class MemberShipAdmin(admin.ModelAdmin):
    list_display = ('user', 'kos_no')
    search_fields = ('user__username', 'user__email', 'kos_no', 'mobile')
    raw_id_fields = (
    'user', 'recidencecity', 'recidencestate', 'office_city', 'office_state', 'reg_country', 'reg_state')


admin.site.register(MemberShip, MemberShipAdmin)


class ProfileAdmin(admin.ModelAdmin):
    search_fields = ('user__username', 'mobile_number')
    list_display = ('user', 'mobile_number')


admin.site.register(Profile, ProfileAdmin)
admin.site.register(Role)
# admin.site.register(MemberShip)
admin.site.register(Qualification)
# admin.site.register(Introduced_by)
admin.site.register(Section)
admin.site.register(FreePaper)
admin.site.register(Evaluator)
admin.site.register(InstructionCourse)
admin.site.register(Video)
admin.site.register(Order)
admin.site.register(MailSettings)
admin.site.register(AssignedTo)
admin.site.register(AssignedFreePaper)
admin.site.register(AssignedVideo)
admin.site.register(smsBody)
admin.site.register(pushNotification)
admin.site.register(serverKey)
admin.site.register(fcmkey)
admin.site.register(OneTimeLink)
admin.site.register(ChiefInstructorICPaper)
admin.site.register(CoInstructorICPaper)
admin.site.register(InvitedSession)
admin.site.register(Event)
admin.site.register(Feedback)
admin.site.register(MembershipDetail)
admin.site.register(ProvisionalMembershipApproval)
admin.site.register(AreaOfInterest)
admin.site.register(ProfileWatcher)
admin.site.register(MembershipStatus)
admin.site.register(EmailMembershipAduit)
admin.site.register(IcEvalMarks)
admin.site.register(DeceasedMembership)
admin.site.register(MemberResign)

admin.site.register(EvaluatorEmailAduit)
admin.site.register(PaperCoAuthorLimit)
admin.site.register(EvaluatorInvite)

class MailAdminForm(forms.ModelForm):
    email_body = forms.CharField(widget=CKEditorWidget())
    class Meta:
        model = Mail
        fields = '__all__'

class MailAdmin(admin.ModelAdmin):
    form = MailAdminForm

admin.site.register(Mail, MailAdmin)

admin.site.register(Help)
admin.site.register(OTP)
admin.site.register(Demo)
from django.utils.translation import gettext, gettext_lazy as _


# Define a new User admin
class CustomUserAdmin(BaseUserAdmin):
    add_form_template = 'admin/auth/user/add_form.html'
    change_user_password_template = None
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'roles', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2'),
        }),
    )
    form = UserChangeForm
    add_form = UserCreationForm
    change_password_form = AdminPasswordChangeForm
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('-date_joined',)
    filter_horizontal = ('groups', 'user_permissions',)


admin.site.register(User, CustomUserAdmin)