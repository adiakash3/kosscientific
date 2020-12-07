from django.contrib import admin
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static
from ckeditor_uploader import views


urlpatterns = [
    path('', include('koscientific.urls')),
    path('admin/', admin.site.urls),

    path('api/', include('kosmemberapi.urls')),
    path('notification/', include('notification.urls')),
    # path('ckeditor/', include('ckeditor_uploader.urls')),
    path('ckeditor/upload/', views.upload, name='ckeditor_upload'),
    path('ckeditor/browse/', views.browse, name='ckeditor_browse'),

    path("select2/", include("django_select2.urls")),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

