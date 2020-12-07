from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from koscientific.models import FreePaper, InstructionCourse, Video
from koscientific.constants import PAPER_STATUS


class Command(BaseCommand):
    help = 'update paper status'

    def handle(self, *args, **kwargs):
        FreePaper.objects.filter(status__iexact='pending').update(status=PAPER_STATUS['PENDING'])
        FreePaper.objects.filter(status__iexact='draft').update(status=PAPER_STATUS['DRAFT'])
        FreePaper.objects.filter(status__iexact='final').update(status=PAPER_STATUS['FINAL'])
        FreePaper.objects.filter(status__iexact='Under-Evaluation').update(status=PAPER_STATUS['UNDER_EVALUATION'])
        FreePaper.objects.filter(status__iexact='UnderEvaluation').update(status=PAPER_STATUS['UNDER_EVALUATION'])
        FreePaper.objects.filter(status__iexact='Evaluated').update(status=PAPER_STATUS['EVALUATED'])

        FreePaper.objects.filter(status__iexact='selected').update(status=PAPER_STATUS['SELECTED'])
        FreePaper.objects.filter(status__iexact='rejected').update(status=PAPER_STATUS['REJECTED'])
        FreePaper.objects.filter(status__iexact='ACTIVE').update(status=PAPER_STATUS['ACTIVE'])
        self.stdout.write(self.style.SUCCESS('FREE PAPER DONE'))
        
        InstructionCourse.objects.filter(status__iexact='pending').update(status=PAPER_STATUS['PENDING'])
        InstructionCourse.objects.filter(status__iexact='draft').update(status=PAPER_STATUS['DRAFT'])
        InstructionCourse.objects.filter(status__iexact='final').update(status=PAPER_STATUS['FINAL'])
        InstructionCourse.objects.filter(status__iexact='Under-Evaluation').update(status=PAPER_STATUS['UNDER_EVALUATION'])
        InstructionCourse.objects.filter(status__iexact='UnderEvaluation').update(status=PAPER_STATUS['UNDER_EVALUATION'])
        InstructionCourse.objects.filter(status__iexact='Evaluated').update(status=PAPER_STATUS['EVALUATED'])

        InstructionCourse.objects.filter(status__iexact='selected').update(status=PAPER_STATUS['SELECTED'])
        InstructionCourse.objects.filter(status__iexact='rejected').update(status=PAPER_STATUS['REJECTED'])
        InstructionCourse.objects.filter(status__iexact='ACTIVE').update(status=PAPER_STATUS['ACTIVE'])
        self.stdout.write(self.style.SUCCESS('InstructionCourse PAPER DONE'))
        
        
        Video.objects.filter(status__iexact='pending').update(status=PAPER_STATUS['PENDING'])
        Video.objects.filter(status__iexact='draft').update(status=PAPER_STATUS['DRAFT'])
        Video.objects.filter(status__iexact='final').update(status=PAPER_STATUS['FINAL'])
        Video.objects.filter(status__iexact='Under-Evaluation').update(status=PAPER_STATUS['UNDER_EVALUATION'])
        Video.objects.filter(status__iexact='UnderEvaluation').update(status=PAPER_STATUS['UNDER_EVALUATION'])
        Video.objects.filter(status__iexact='Evaluated').update(status=PAPER_STATUS['EVALUATED'])

        Video.objects.filter(status__iexact='selected').update(status=PAPER_STATUS['SELECTED'])
        Video.objects.filter(status__iexact='rejected').update(status=PAPER_STATUS['REJECTED'])
        Video.objects.filter(status__iexact='ACTIVE').update(status=PAPER_STATUS['ACTIVE'])
        self.stdout.write(self.style.SUCCESS('video PAPER DONE'))
        
