from django.db import models
from datetime import datetime
from cities_light.models import City, Country,Region
from ckeditor.fields import RichTextField
from ckeditor_uploader.fields import RichTextUploadingField
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxLengthValidator, MinLengthValidator
from django.utils.translation import ugettext_lazy as _
from notification.models import Message

# Create your models here.


class Role(models.Model):
    ADMIN = 1
    EVALUATOR = 2
    MEMBER = 3
    REGISTERED = 4
    ATTENDEE = 5
    SCIENTIFIC_ADMIN = 6

    ROLE_CHOICES = (
        (ADMIN, 'Admin'),
        (EVALUATOR, 'Evaluator'),
        (MEMBER, 'Member'),
        (REGISTERED, 'Registered'),
        (ATTENDEE,'Attendee'),
        (SCIENTIFIC_ADMIN, 'Scientific admin')

    )
    id = models.PositiveSmallIntegerField(('select role'), choices=ROLE_CHOICES, primary_key=True)

    def __str__(self):
        return self.get_id_display()


class User(AbstractUser):
    ''' Main User '''
    roles = models.ManyToManyField(Role, related_name="users", blank=True)
    email = models.EmailField(_('email address'), unique=True)

    def un_read_message_count(self):
        return Message.objects.filter(user=self.pk, is_readed=False).count()


class AreaOfInterest(models.Model):
    """ area of interest of the users """
    ACTIVE = 1
    INACTIVE = 2
    HOLD = 3
    STATUS_CHOICES = ((ACTIVE, 'Active'),
                      (INACTIVE, 'Inactive'),
                      (HOLD, 'Hold')
                      )
    name = models.CharField(max_length=250)
    description = models.TextField(blank=True, null=True)
    status = models.IntegerField(choices=STATUS_CHOICES)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='area_of_interests', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    area_of_interests = models.ManyToManyField(AreaOfInterest, related_name='area_of_interets', blank=True)
    photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True)
    mobile_number = models.CharField(max_length=13, unique=True, blank=True, null=True)
    is_otp_verified = models.BooleanField(default=False)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True, related_name='profile_updater')
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return str(self.user)


class ProfileWatcher(models.Model):
    """ admin will keep track the user profile update"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='profile_watchers')
    is_sms_sent = models.BooleanField(default=False)
    is_mail_sent = models.BooleanField(default=False)
    is_recently_updated = models.BooleanField(default=False)
    comment = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    
    def __str__(self):
        return str(self.user)
    
    
class Event(models.Model):
    """ event created by admin """
    ACTIVE = 1
    INACTIVE = 2
    SCHEDULE = 3
    STATUS_CHOICES = ((ACTIVE, 'Active'),
                      (INACTIVE, 'Inactive'),
                      (SCHEDULE, 'Schedule')
                      )
    name = models.CharField(max_length=250)
    description = models.TextField()
    start_date = models.DateField(auto_now=False, auto_now_add=False)
    end_date = models.DateField(auto_now=False, auto_now_add=False)
    status = models.IntegerField(choices=STATUS_CHOICES)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='events', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    
class MembershipActiveManager(models.Manager):
    """ active membership """
    def get_queryset(self):
        return super().get_queryset().filter(user__is_active=True)
    
class MembershipInactiveManager(models.Manager):
    """ inactive membership """
    def get_queryset(self):
        return super().get_queryset().filter(user__is_active=False)
    
     
class MemberShip(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=True, null=True)
    # name = models.CharField(max_length=100, null=True, blank=True)
    dob = models.DateField( null=True, blank=True)
    gender=models.CharField(max_length=20,blank=True,null=True)
    #residence address details
    recidence_Street_address=models.CharField(max_length=100,null=True,blank=True)
    recidence_address_line_2=models.CharField(max_length=100,null=True,blank=True)
    recidencecity=models.ForeignKey(City,on_delete=models.CASCADE,null=True,blank=True,related_name='recidencecity')
    recidencestate=models.ForeignKey(Region,on_delete=models.CASCADE,null=True,blank=True,related_name='recidencestate')
    recidence_pincode=models.CharField(max_length=100,null=True,blank=True)
    recidencecountry=models.ForeignKey(Country,on_delete=models.CASCADE,null=True,blank=True,related_name='recidencecountry')
    #office address details
    address_condition=models.BooleanField(default=False)
    office_Street_address = models.CharField(max_length=100, null=True, blank=True)
    office_address_line_2 = models.CharField(max_length=100, null=True, blank=True)
    office_city = models.ForeignKey(City, on_delete=models.CASCADE, null=True, blank=True,related_name='office_city')
    office_state = models.ForeignKey(Region, on_delete=models.CASCADE, null=True, blank=True,related_name='office_state')
    office_pincode = models.CharField(max_length=100, null=True, blank=True)
    office_country = models.ForeignKey(Country, on_delete=models.CASCADE, null=True, blank=True,related_name='office_country')
    #contacts
    mobile=models.BigIntegerField(null=True,blank=True)
    home_phone=models.BigIntegerField(null=True,blank=True)
    office_phone=models.BigIntegerField(null=True,blank=True)
    # email=models.EmailField(max_length=50,blank=True,null=True)
    #Deposit details
    cheque_no=models.CharField(max_length=30,null=True,blank=True)
    bank=models.CharField(max_length=20,null=True,blank=True)
    date=models.DateField(max_length=9,null=True,blank=True)
    #photograph
    photo=models.FileField(null=True,blank=True)
    #Photocopy of Medical Council Registration Certificate
    certificate=models.FileField(null=True,blank=True)
    #Membership*
    price=models.IntegerField(null=True,blank=True)
    #Consent
    agree=models.BooleanField(default=False)

    #introduced_by

    non_mem_introducer = models.CharField(max_length=250, null=True, blank=True)
    kos_no = models.PositiveIntegerField(blank=True, null=True)
    is_active = models.BooleanField(default=False)
    status = models.CharField(max_length=250, blank=True, null=True)
    is_member = models.BooleanField(default=False)
    medical_registration_no = models.CharField(max_length=50, blank=True, null=True)
    # state_registration = models.CharField(max_length=50, blank=True, null=True)
    reg_country = models.ForeignKey(Country, on_delete=models.CASCADE, null=True, blank=True,
                                    related_name='reg_country')
    reg_state = models.ForeignKey(Region, on_delete=models.CASCADE, null=True, blank=True,
                                  related_name='reg_state')
    
    is_provisional = models.BooleanField(blank=True, null=True)
    is_iis_signed = models.BooleanField(default=False)

    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True, related_name='membership_updater')
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    
    objects = MembershipActiveManager()
    inactive_objects = MembershipInactiveManager()
    all_objects = models.Manager() # The default manager.

    def __str__(self):
        return str(self.user.first_name)

class EmailMembershipAduit(models.Model):
    """ email membership aduit used to send Membership incomplete' reminder"""
    MEMBERSHIP_INCOMPLETE = 1
    MEM_STATUS = (
                (MEMBERSHIP_INCOMPLETE, 'Membership incomplete'),
    )
    membership = models.ForeignKey(MemberShip, on_delete=models.CASCADE, related_name='email_membership_aduits')
    name = models.TextField()
    mem_status = models.IntegerField(choices=MEM_STATUS, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name


class MembershipStatus(models.Model):
    """ membership all approval status"""
    membership = models.OneToOneField(MemberShip, on_delete=models.CASCADE, blank=True, null=True, related_name="membership_status")
    status = models.CharField(max_length=250)
    comment = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.membership)
    
    
class MembershipDetail(models.Model):
    """ membership approved and reject details """
    ACCEPT = 1
    REJECT = 2
    NO_ANSWER = 3
    MEMBERSHIP_STATUS = ((ACCEPT, 'Accepted'),
                         (REJECT, 'Rejected'),
                         (NO_ANSWER, 'No answer')
                         )
    membership = models.OneToOneField(MemberShip, on_delete=models.CASCADE, blank=True, null=True, related_name="membership_detail")
    introducer_one = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True, related_name="membership_details_as_first")
    introducer_one_status = models.IntegerField(choices=MEMBERSHIP_STATUS, default=3, blank=True, null=True)
    introducer_one_action_date = models.DateField(blank=True, null=True)
    introducer_two = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True, related_name="membership_details_as_second")
    introducer_two_status = models.IntegerField(choices=MEMBERSHIP_STATUS, default=3, blank=True, null=True)
    introducer_two_action_date = models.DateField(blank=True, null=True)
    admin_status = models.IntegerField(choices=MEMBERSHIP_STATUS, default=3, blank=True, null=True)
    admin = models.CharField(max_length=250, blank=True, null=True)
    admin_action_date = models.DateField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.membership)
    
def provisional_approve_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/provisional_approve_documents/user_<id>/<filename>
    return 'provisional_approve_documents/user_{0}/{1}'.format(instance.membership.user.id, filename)
    
class ProvisionalMembershipApproval(models.Model):
    """ provisional membership AGM approval status """
    ACCEPT = 1
    REJECT = 2
    NO_ANSWER = 3
    PROVISIONAL_STATUS = (
        (ACCEPT, 'Accept'),
        (REJECT, 'Reject'),
        (NO_ANSWER, 'No answer')
    )
    membership = models.OneToOneField(MemberShip, on_delete=models.CASCADE, blank=True, null=True, related_name="provisional_membership_approval")
    agm = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True, related_name="provisional_membership_approval_agm")
    document = models.FileField(upload_to=provisional_approve_directory_path, max_length=100)
    status = models.IntegerField(choices=PROVISIONAL_STATUS, default=3, blank=True, null=True)
    random_token = models.CharField(max_length=100, blank=True, null=True)
    approved_at = models.DateTimeField(blank=True, null=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.membership)

def deceased_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/deceased_documents/user_<id>/<filename>
    return 'deceased_documents/user_{0}/{1}'.format(instance.membership.user.id, filename)
    
class DeceasedMembership(models.Model):
    """ 
    deceased membership by AGM
    """
    DECEASED = 1
    REVERT_DECEASED = 2
    DECEASED_STATUS = (
        (DECEASED, 'Deceased'),
        (REVERT_DECEASED, 'Deceased reverted'),
    )
    membership = models.OneToOneField(MemberShip, on_delete=models.CASCADE, blank=True, null=True, related_name="deceased_memberships")
    agm = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True, related_name="deceased_memberships_agm")
    document = models.FileField(upload_to=deceased_directory_path, max_length=100)
    status = models.IntegerField(choices=DECEASED_STATUS, blank=True, null=True)
    deceased_at = models.DateTimeField(blank=True, null=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.membership)
    
def resign_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/deceased_documents/user_<id>/<filename>
    return 'resign_documents/user_{0}/{1}'.format(instance.membership.user.id, filename)


class MemberResign(models.Model):
    """ 
    member resign
    """
    RESIGNED = 1
    RESIGN_ACCEPTED = 2
    RESIGN_REJECTED = 3
    RESIGN_STATUS = (
        (RESIGNED, 'Resigned'),
        (RESIGN_ACCEPTED, 'Resign accepted'),
        (RESIGN_REJECTED, 'Resign rejected'),
    )
    membership = models.OneToOneField(MemberShip, on_delete=models.CASCADE, blank=True, null=True, related_name="resign_membership")
    agm = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True, related_name="resign_membership_agm")
    document = models.FileField(upload_to=resign_directory_path, max_length=100)
    status = models.IntegerField(choices=RESIGN_STATUS, blank=True, null=True)
    resign_at = models.DateTimeField(blank=True, null=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.membership)
    
    
class Qualification(models.Model):
    DEGREE_STATUS = (
        ('MBBS', 'MBBS'),
        ('DOMS', 'DOMS'),
        ('MS', 'MS'),
        ('MD', 'MD'),
        ('FRCS', 'FRCS'),
        ('FRCOG', 'FRCOG'),
    )
    membership = models.ForeignKey(MemberShip, on_delete=models.CASCADE,related_name='qualifications', blank=True, null=True)
    degree=models.CharField(choices=DEGREE_STATUS, max_length=100, blank=True, null=True)
    year=models.CharField(max_length=50,null=True,blank=True)
    college=models.CharField(max_length=50,null=True,blank=True)

    def __str__(self):
        return str(self.membership)
class Section(models.Model):
    section_name = models.CharField(max_length=255,blank=True,null=True)
    status = models.CharField(max_length=25,blank=True,null=True)
    created_at = models.DateTimeField(default=datetime.now)

    def __str__(self):
        return self.section_name

class FreePaper(models.Model):
    PRESENTATION_CHOICES = (
        ('1', 'Paper or E-Poster'),
        ('2', 'Paper only'),
        ('3', 'E-Poster only'),
        ('4', 'Physical Poster'),
        ('5', 'Paper or Physical Poster'),
    )
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='free_papers', blank=True, null=True)
    unique_id = models.CharField(max_length=20,blank=True,null=True)
    ref_id = models.CharField(max_length=250, unique=True, blank=True, null=True)
    type_of_presentation = models.CharField(max_length=3, choices=PRESENTATION_CHOICES, blank=True, null=True)

    # member_name = models.ForeignKey(MemberShip,on_delete=models.SET_NULL,blank=True,null=True)
    chief_author = models.ForeignKey(MemberShip, on_delete=models.CASCADE, blank=True, null=True,related_name='chief_free_papers')
    presenting_auther_name = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True,related_name='presenting_auther')
    coauther_name = models.ManyToManyField(MemberShip, blank=True, related_name='free_papers')
    section = models.ForeignKey(Section,on_delete=models.SET_NULL,blank=True,null=True)
    title = models.TextField(blank=True,null=True)
    status = models.CharField(max_length=25,blank=True,null=True)
    synopsis = models.TextField(blank=True,null=True)
    date = models.DateField(default=datetime.now)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.CharField(max_length=20,blank=True,null=True)
    created_at = models.DateTimeField(default=datetime.now)
    updated_at = models.DateTimeField(default=datetime.now)

    def __str__(self):
        return self.title

class NonMemberFreePaperInstructor(models.Model):
    """ non member free paper instructors"""
    QUALIFICATION_CHOICES = ((1, "MBBS"),
                             (2, "BODMS"),
                             (3, "MD")
                             )
    free_paper = models.ForeignKey(FreePaper, on_delete=models.CASCADE, related_name='non_members_free_paper_instructors', blank=True, null=True)
    first_name = models.CharField(max_length=1250, blank=True, null=True)
    last_name = models.CharField(max_length=1250, blank=True, null=True)
    email = models.EmailField(max_length=254, blank=True, null=True)
    mobile_number = models.CharField(max_length=13, blank=True, null=True)
    qualification = models.IntegerField(choices=QUALIFICATION_CHOICES, blank=True, null=True)

    def __str__(self):
        return self.free_paper.title if self.free_paper.title else 'free paper'

class EvaluatorActiveManager(models.Manager):
    """ active evaluator """
    def get_queryset(self):
        return super().get_queryset().filter(membership__user__is_active=True)
    
    
class EvaluatorInactiveManager(models.Manager):
    """ inactive evaluator """
    def get_queryset(self):
        return super().get_queryset().filter(membership__user__is_active=False)
    
    
class Evaluator(models.Model):
    """
    Main evaluator use membership for kos member else use user for non kos member
    """
    SENT = 1
    ACCEPT = 2
    REJECT = 3
    NO_ANSWER = 4
    NOT_SENT = 5
    MAIL_STATUS = ((SENT, "Sent"),
                   (ACCEPT, "Accept"),
                   (REJECT, "Reject"),
                   (NO_ANSWER, "No answer"),
                   (NOT_SENT, 'Not sent')
                   )
    membership = models.ForeignKey(MemberShip, on_delete=models.CASCADE, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    status = models.CharField(max_length=25, blank=True, null=True)
    section = models.ManyToManyField(Section, related_name="evaluators")
    mail_status = models.IntegerField(choices=MAIL_STATUS, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # objects = EvaluatorActiveManager()
    # inactive_objects = EvaluatorInactiveManager()
    # all_objects = models.Manager() # The default manager.



class EvaluatorEmailAduit(models.Model):
    """
    used to send the reminder to evaluator
    """
    evaluator = models.ForeignKey(Evaluator, on_delete=models.CASCADE, related_name="evaluator_email_audits")
    one_time_link = models.ForeignKey('OneTimeLink', related_name='one_time_link', on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.evaluator)


class EvaluatorInvite(models.Model):
    """
    Invite non kos member as evaluator
    """
    evaluator = models.OneToOneField(Evaluator, on_delete=models.CASCADE, related_name="invite", blank=True, null=True)
    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    email = models.EmailField(max_length=250, blank=True, null=True)
    mobile_number = models.CharField(max_length=13, blank=True, null=True)
    invited_by = models.ForeignKey(User, related_name='i_invited_non_member_evaluators', on_delete=models.CASCADE, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)
    
    def __str__(self):
        return str(self.first_name)

    
class InstructionCourse(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='instruction_courses', blank=True, null=True)
    unique_id = models.CharField(max_length=20, blank=True, null=True)
    ref_id = models.CharField(max_length=250, unique=True, blank=True, null=True)
    title = models.TextField(blank=True, null=True)
    Instruction_course_type = models.CharField(max_length=50, blank=True, null=True)
    section = models.ForeignKey(Section, on_delete=models.SET_NULL, blank=True, null=True)
    resume = models.TextField(blank=True, null=True)
    synopsis = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=30,blank=True,null=True)
    # chief_instructor_name = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True,related_name='chief_auther_ofinst')
    # co_instructors = models.ManyToManyField(MemberShip, blank=True, related_name='coauther_auther_ofinst')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.CharField(max_length=20,blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class NonMemberICPaperInstructor(models.Model):
    """ non member ic paper instructors"""
    QUALIFICATION_CHOICES = ((1, "MBBS"),
                             (2, "BODMS"),
                             (3, "MD")
                             )
    instruction_course = models.ForeignKey(InstructionCourse, on_delete=models.CASCADE, related_name='non_members_ic_paper_instructors', blank=True, null=True)
    first_name = models.CharField(max_length=1250, blank=True, null=True)
    last_name = models.CharField(max_length=1250, blank=True, null=True)
    email = models.EmailField(max_length=254, blank=True, null=True)
    mobile_number = models.CharField(max_length=13, blank=True, null=True)
    qualification = models.IntegerField(choices=QUALIFICATION_CHOICES, blank=True, null=True)

    def __str__(self):
        return self.instruction_course.title


class ChiefInstructorICPaper(models.Model):
    """ instruction course chief instructor duration and top info"""
    instruction_course = models.OneToOneField(InstructionCourse, on_delete=models.CASCADE, related_name='chief_instructor_ic_paper', blank=True, null=True)
    chief_instructor = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, related_name='chief_instructor_ic_papers', blank=True, null=True)
    duration = models.IntegerField(blank=True, null=True)
    topic = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.instruction_course.title +' '+ str(self.chief_instructor)

class CoInstructorICPaper(models.Model):
    """ instruction course co-instructors duration and top info"""
    instruction_course = models.ForeignKey(InstructionCourse, on_delete=models.CASCADE, related_name='co_instructor_ic_paper', blank=True, null=True)
    co_instructor = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, related_name='co_instructor_ic_papers', blank=True, null=True)
    duration = models.IntegerField(blank=True, null=True)
    topic = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.instruction_course.title +' '+ str(self.co_instructor)

class Video(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='videos', blank=True, null=True)
    unique_id = models.CharField(max_length=20, blank=True, null=True)
    ref_id = models.CharField(max_length=250, unique=True, blank=True, null=True)
    title = models.TextField(blank=True, null=True)
    video_type = models.CharField(max_length=50,blank=True, null=True)
    section = models.ForeignKey(Section, on_delete=models.SET_NULL, blank=True, null=True)
    abstract = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=25,blank=True,null=True)
    chief_author = models.ForeignKey(MemberShip, on_delete=models.CASCADE,related_name="chief_author_videos", blank=True, null=True)
    presenting_video_auther_name = models.ForeignKey(MemberShip, on_delete=models.SET_NULL, blank=True, null=True,related_name='video_auther_name')
    coauther_video_name = models.ManyToManyField(MemberShip, blank=True, related_name='video_co_authers')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.CharField(max_length=20,blank=True,null=True)
    created_at = models.DateTimeField(default=datetime.now)
    updated_at = models.DateTimeField(default=datetime.now)

    def __str__(self):
        return self.title if self.title else self.id

class NonMemberVideoPaperInstructor(models.Model):
    """ non member video paper instructors"""
    QUALIFICATION_CHOICES = ((1, "MBBS"),
                             (2, "BODMS"),
                             (3, "MD")
                             )
    video = models.ForeignKey(Video, on_delete=models.CASCADE, related_name='non_members_video_paper_instructors', blank=True, null=True)
    first_name = models.CharField(max_length=1250, blank=True, null=True)
    last_name = models.CharField(max_length=1250, blank=True, null=True)
    email = models.EmailField(max_length=254, blank=True, null=True)
    mobile_number = models.CharField(max_length=13, blank=True, null=True)
    qualification = models.IntegerField(choices=QUALIFICATION_CHOICES, blank=True, null=True)

    def __str__(self):
        return self.video.title

class Order(models.Model):
    razorpay_payment = models.CharField(max_length=100,blank=True,null=True)
    membership = models.ForeignKey(MemberShip, on_delete=models.SET_NULL,related_name="member", blank=True, null=True,)
    invoice = models.CharField(max_length=200, unique=True, blank=True, null=True)
    amount = models.DecimalField(max_digits=9, decimal_places=2, default='0.0')
    amount_due = models.DecimalField(max_digits=9, decimal_places=2, default='0.0')
    amount_paid = models.DecimalField(max_digits=9, decimal_places=2, default='0.0')
    status = models.CharField(max_length=20,blank=True,null=True)
    order_id = models.CharField(max_length=250, blank=True, null=True)
    order_receipt = models.CharField(max_length=250, blank=True, null=True)
    transaction = models.CharField(max_length=100, blank=True, null=True)
    #: Creation date and time
    created = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    #: Date and time of last modification
    modified = models.DateTimeField(auto_now=True, blank=True, null=True)

class MailSettings(models.Model):
    from_email = models.CharField(max_length=250, blank=True, null=True)
    mail_server = models.CharField(max_length=250, blank=True, null=True)
    mail_port = models.IntegerField(blank=True, null=True)
    use_ssl = models.BooleanField(default=True)
    username = models.CharField(max_length=250, blank=True, null=True)
    password = models.CharField(max_length=250, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True,blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True,blank=True, null=True)

class smsBody(models.Model):
    smskey = models.CharField(max_length=250, unique=True)
    smscontent = models.TextField(max_length=250)

class pushNotification(models.Model):
    subject = models.CharField(max_length=250, blank=True, null=True)
    body = models.CharField(max_length=250, blank=True, null=True)
    imgsub = models.FileField(upload_to='notification/',blank=True, null=True)


class serverKey(models.Model):
    server_key = models.CharField(max_length=250, blank=True, null=True)

class fcmkey(models.Model):
    fcm_key = models.CharField(max_length=250, blank=True, null=True)

class AssignedTo(models.Model):
    ic=models.ForeignKey(InstructionCourse,on_delete=models.CASCADE,null=True,blank=True)
    evulator=models.ForeignKey(Evaluator,on_delete=models.CASCADE,blank=True,null=True)
    section = models.ForeignKey(Section, on_delete=models.CASCADE,blank=True,null=True)
    status=models.CharField(max_length=50,blank=True ,null=True)
    marks=models.PositiveIntegerField(null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.ic)
    
class IcEvalMarks(models.Model):
    """ ic paper marks by eval"""
    assigned = models.ForeignKey(AssignedTo,on_delete=models.CASCADE,blank=True,null=True, related_name="ic_marks")
    name = models.CharField(max_length=250)
    marks = models.PositiveIntegerField(null=True,blank=True)
    remarks = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.assigned)


class AssignedFreePaper(models.Model):
    fp=models.ForeignKey(FreePaper,on_delete=models.CASCADE,null=True,blank=True)
    evulator=models.ForeignKey(Evaluator,on_delete=models.CASCADE,blank=True,null=True)
    status=models.CharField(max_length=50,blank=True ,null=True)
    section = models.ForeignKey(Section, on_delete=models.CASCADE,blank=True,null=True)
    marks=models.PositiveIntegerField(null=True,blank=True)
    created_at = models.DateTimeField(default=datetime.now)
    updated_at = models.DateTimeField(default=datetime.now)

    def __str__(self):
        return str(self.fp)

class FreePaperEvalMarks(models.Model):
    """ free  paper marks by eval"""
    assigned = models.ForeignKey(AssignedFreePaper,on_delete=models.CASCADE,blank=True,null=True, related_name="ic_marks")
    name = models.CharField(max_length=250)
    marks = models.PositiveIntegerField(null=True,blank=True)
    remarks = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.assigned)
    
class AssignedVideo(models.Model):
    vd=models.ForeignKey(Video,on_delete=models.CASCADE,null=True,blank=True)
    evaluator=models.ForeignKey(Evaluator,on_delete=models.CASCADE,blank=True,null=True)
    status=models.CharField(max_length=50,blank=True ,null=True)
    marks=models.PositiveIntegerField(null=True,blank=True)
    section = models.ForeignKey(Section, on_delete=models.CASCADE,blank=True,null=True)
    created_at = models.DateTimeField(default=datetime.now)
    updated_at = models.DateTimeField(default=datetime.now)

    def __str__(self):
        return str(self.vd)


class VideoPaperEvalMarks(models.Model):
    """video paper marks by eval"""
    assigned = models.ForeignKey(AssignedVideo,on_delete=models.CASCADE,blank=True,null=True, related_name="ic_marks")
    name = models.CharField(max_length=250)
    marks = models.PositiveIntegerField(null=True,blank=True)
    remarks = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.assigned)
    
    
class Mail(models.Model):
    name = models.CharField(max_length=250, unique=True)
    email_subject = models.CharField(max_length=250)
    email_body = RichTextUploadingField()

class Help(models.Model):
    title = models.CharField(max_length=250, blank=True, null=True)
    description = models.TextField(max_length=250, blank=True, null=True)
    created_at = models.DateTimeField(default=datetime.now)
    updated_at = models.DateTimeField(default=datetime.now)

    def __str__(self):
        return str(self.title)


class OTP(models.Model):
    """sms OTP for user verification """
    sms_transaction_id = models.CharField(max_length=60)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    otp = models.CharField(max_length=6)
    is_otp_verified  = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.sms_transaction_id) + str(self.otp)

class EmailOTP(models.Model):
    """Email OTP for user verification """
    email_transaction_id = models.CharField(max_length=60)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    otp = models.CharField(max_length=6)
    is_otp_verified  = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.email_transaction_id) + str(self.user) + str(self.otp)
    
#dummy django form
class Demo(models.Model):
    firstname= models.CharField(max_length=100)
    lastname= models.CharField(max_length=100)
    email= models.EmailField()
    comment= models.CharField(max_length=10000)

    def __str__(self):
        return str(self.email)


class OneTimeLink(models.Model):
    ''' define one time link token '''
    name = models.CharField(max_length=250)
    token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class InvitedSession(models.Model):
    """ scientific committee invited session """
    abstract_title = models.CharField(max_length=250)
    is_accepted = models.BooleanField(blank=True, null=True)
    is_rejected = models.BooleanField(blank=True, null=True)
    is_ic_paper = models.BooleanField(default=False)
    is_free_paper = models.BooleanField(default=False)
    is_video_paper = models.BooleanField(default=False)
    paper_id = models.CharField(max_length=50, blank=True, null=True)
    submission_type = models.CharField(max_length=250)
    summary = models.TextField()
    send_to = models.ForeignKey(User, on_delete=models.CASCADE, related_name='my_receive_invited_sessions')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='i_sent_invited_sessions')
    session_date = models.DateField(auto_now=False, auto_now_add=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.abstract_title

class Feedback(models.Model):
    """ feedback for members"""
    TYPE_CHOICES = ((1, "Member not found"),
                    (2, "Technical problem"),
                    (3, "Others"),)
    subject = models.IntegerField(choices=TYPE_CHOICES)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='feedbacks')
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.get_subject_display() + ' by ' + str(self.description)


class MassSms(models.Model):
    """ mass sms recoard"""
    SENT = 1
    NOT_SENT = 2
    DARFT = 3
    ERROR = 4
    SENDING = 5
    STATUS_CHOICES = (
        (SENT, "Sent"),
        (NOT_SENT, "Not sent"),
        (DARFT, "Draft"),
        (ERROR, 'Error'),
        (SENDING, 'Sending')
    )
    MEMBERS = 1
    VOTERS = 2
    TO_CHOICES = (
        (MEMBERS, "Members"),
        (VOTERS, "Voters"),
    )
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mass_smses')
    to = models.IntegerField(choices=TO_CHOICES)
    status = models.IntegerField(choices=STATUS_CHOICES)
    message = models.TextField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.sender)


class MassMail(models.Model):
    """ mass sms recoard"""
    SENT = 1
    NOT_SENT = 2
    DARFT = 3
    ERROR = 4
    SENDING = 5
    STATUS_CHOICES = (
        (SENT, "Sent"),
        (NOT_SENT, "Not sent"),
        (DARFT, "Draft"),
        (ERROR, 'Error'),
        (SENDING, 'Sending')
    )
    MEMBERS = 1
    VOTERS = 2
    TO_CHOICES = (
        (MEMBERS, "Members"),
        (VOTERS, "Voters"),
    )
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mass_mails')
    to = models.IntegerField(choices=TO_CHOICES)
    status = models.IntegerField(choices=STATUS_CHOICES)
    subject = models.CharField(max_length=250)
    body = RichTextField(verbose_name='email body')
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.sender)


class PaperCoAuthorLimit(models.Model):
    """
    Adding co author limit while submitting the paper
    """
    FREE_PAPER = 1
    IC_PAPER = 2
    VIDEO_PAPER = 3
    PAPERS_CHOICES = (
        (FREE_PAPER,'Free paper'),
        (IC_PAPER,'Ic paper'),
        (VIDEO_PAPER,'Video paper'),
    )
    paper = models.IntegerField(choices=PAPERS_CHOICES, unique=True)
    max_limit = models.IntegerField(default=3)
    max_kos_member_limit = models.IntegerField(blank=True, null=True)
    max_non_kos_member_limit = models.IntegerField(blank=True, null=True)
    updated_by = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.get_paper_display()
