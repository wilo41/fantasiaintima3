from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('appsexshop.urls')),
    path('', include('social_django.urls', namespace='social')),  # <-- esta línea
]
