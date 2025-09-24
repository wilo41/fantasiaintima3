from django.apps import AppConfig


class AppsexshopConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'appsexshop'

    def ready(self):
        import appsexshop.signals
