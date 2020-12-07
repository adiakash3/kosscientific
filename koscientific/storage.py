import os
from datetime import datetime
from urllib.parse import urljoin

from django.conf import settings
from django.core.files import File, locks
from django.core.files.move import file_move_safe
from django.core.signals import setting_changed
from django.utils import timezone
from django.utils._os import safe_join
from django.utils.deconstruct import deconstructible
from django.utils.encoding import filepath_to_uri
from django.utils.functional import LazyObject, cached_property

from django.core.files.storage import FileSystemStorage

@deconstructible
class FileSystemStoragee(FileSystemStorage):
    """
    Standard filesystem storage
    """

    @cached_property
    def base_url(self):
        if self._base_url is not None and not self._base_url.endswith('/'):
            self._base_url += '/'
        return self._value_or_setting(self._base_url, settings.CKEDITOR_MEDIA_URL)