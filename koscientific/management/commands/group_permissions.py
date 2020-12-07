from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType

# Codename, model

ADMIN_PERMISSIONS = (

    ('view_dash_board', 'user'),
    ('approve_user', 'user'),
    ('view_all_paper','user'),
    ('view_evaluators','user'),
    ('view_assign_paper','user'),
    ('view_master','user'),
    ('view_members','user'),
    ('view_members_application','user'),
    ('view_notification','user'),
    ('reassign','user'),
    ('reassign_evaluator','user'),
    ('registered_member','user'),
    ('export_member','user'),
    ('send_bulk_sms_member','user'),
    ('send_bulk_mail_member','user'),
    ('view_membership','user'),
    ('edit_membership','user'),
    ('add_membership','user'),
    ('update_membership_profile','user'),
    
    ('decease_member','user'),
    ('resign_member','user'),
    
    ('dashboad_exceptMember','user'),
    ('view_billing','user'),
    ('view_status','user'),
    # ('add_ic_paper','user'),
    # ('add_free_paper','user'),
    # ('add_video_paper','user'),
    
    ('view_ic_paper','user'),
    ('view_free_paper','user'),
    ('view_video_paper','user'),
    
    ('add_section','user'),
    ('edit_section','user'),
    ('view_section','user'),
    
    ('base_profile','user'),
    ('paper_authors_limit', 'user'),

)

# scientific admin is simple readonly admin
SCIENTIFIC_ADMIN_PERMISSIONS = (
    ('view_ic_paper','user'),
    ('view_free_paper','user'),
    ('view_video_paper','user'),
    ('view_event','user'),
    
    ('add_evaluator','user'),
    ('edit_evaluator','user'),
    ('view_evaluator','user'),
    
    ('view_assigned_ic_paper','user'),
    ('view_assigned_free_paper','user'),
    ('view_assigned_video_paper','user'),
    

    ('reassign_evaluator','user'),
    ('view_membership','user'),

    
    ('paper_authors_limit', 'user'),
    
)

EVALUATOR_PERMISSIONS = (
    ('view_assign_paper','user'),
    ('view_dash_board', 'user'),
    ('view_assigned_papers', 'user'),
    ('add_marks', 'user'),
    ('make_payment', 'user'),
    ('inc_count', 'user'),
    ('dashboad_exceptMember','user'),
    ('help','user'),
    ('full_profile','user'),

)

EVALUATOR_NON_MEMBER_PERMISSIONS = (
    ('view_assign_paper','user'),
    ('view_dash_board', 'user'),
    ('view_assigned_papers', 'user'),
    ('add_marks', 'user'),
    ('inc_count', 'user'),
    ('dashboad_exceptMember','user'),
    ('help','user'),
    ('base_profile','user'),
)

MEMBER_PERMISSIONS = (
    ('member_dashboard', 'user'),
    ('view_dash_board', 'user'),
    ('view_all_paper_member','user'),
    
    ('add_ic_paper','user'),
    ('add_free_paper','user'),
    ('add_video_paper','user'),
    ('view_ic_paper','user'),
    ('view_free_paper','user'),
    ('view_video_paper','user'),
    ('edit_ic_paper','user'),
    ('edit_free_paper','user'),
    ('edit_video_paper','user'),
    
    ('full_profile','user'),
    ('invited_session','user'),
    ('help','user'),
)

REGISTERED_PERMISSIONS = (
    ('complete_payment','user'),
    ('view_dash_board', 'user'),
    ('registered_dashboard','user'),
    ('base_profile','user'),
)

ATTENDEE_PERMISSIONS = (
    ('conference_attendee','user'),
)


class Command(BaseCommand):
    help = 'create groups with permissions for different roles'

    def handle(self, *args, **kwargs):
        Permission.objects.all().delete()
        self.add_permissions('Admin', ADMIN_PERMISSIONS, 'success - admin group created.')
        self.add_permissions('Evaluator', EVALUATOR_PERMISSIONS, 'success - Evaluator group created.')
        self.add_permissions('Member', MEMBER_PERMISSIONS, 'success - Member group created.')
        self.add_permissions('Registered', REGISTERED_PERMISSIONS, 'success - Registered group created.')
        self.add_permissions('Attendee', ATTENDEE_PERMISSIONS, 'success - Attendee group created.')
        self.add_permissions('Evaluator_non_member', EVALUATOR_NON_MEMBER_PERMISSIONS, 'success - Evaluator non member group created.')
        self.add_permissions('Scientific_admin', SCIENTIFIC_ADMIN_PERMISSIONS, 'success - scientific admin group created.')

    def add_permissions(self, group_name, permissions_tuple, message):
        group, created = Group.objects.get_or_create(name=group_name)

        for codename, model in permissions_tuple:
            content_type = ContentType.objects.get(model=model)
            name = 'Can {}'.format(codename.replace('_', ' '))
            permission, created = Permission.objects.get_or_create(
                codename=codename, name=name, content_type=content_type)
            group.permissions.add(permission)
        self.stdout.write(self.style.SUCCESS(message))
