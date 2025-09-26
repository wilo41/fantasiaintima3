from pathlib import Path
import os
from dotenv import load_dotenv
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

# # 👇 Cargar variables del archivo .env al entorno
# load_dotenv(os.path.join(BASE_DIR.parent, ".env"))

def get_env_variable(var_name):
    """Obtiene una variable de entorno o lanza error si no existe."""
    try:
        return os.environ[var_name]
    except KeyError:
        raise ImproperlyConfigured(f"La variable de entorno {var_name} no está configurada.")

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

SECRET_KEY = 'django-insecure-g=^shdgaccc+=*k9*^)mz@e)tzdq5^wnj7q3-in%7-)(pn+4c%'

DEBUG = True

ALLOWED_HOSTS = ["fantasiaintima2.onrender.com", "localhost", "127.0.0.1"]
# Aplicaciones instaladas
INSTALLED_APPS = [
    'sexshop',
    'appsexshop.apps.AppsexshopConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'social_django',  # Nuevo: social-auth-app-django
    'paypal.standard.ipn',  # PayPal IPN
]

# Middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'sexshop.urls'



# Templates
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            'sexshop/templates'
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',

                # Nuevos para social-auth
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
            ],
        },
    },
]

WSGI_APPLICATION = 'sexshop.wsgi.application'

# Base de datos
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'fantasiaintima2',
        'USER': 'root',
        'PASSWORD': 'kvJibdWPhRZoKczMrkydrMcqqzdWiWHH',
        'HOST': 'gondola.proxy.rlwy.net',
        'PORT': '32568',
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"
        }
    }
}



# Validación de contraseñas
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internacionalización
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'America/Bogota'
USE_I18N = True
USE_TZ = True

# Archivos estáticos
STATIC_URL = 'static/'

STATICFILES_DIRS = [
    'appsexshop/static',
]

# Archivos multimedia
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Sesiones
SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # Usa la base de datos para almacenar sesiones
SESSION_COOKIE_HTTPONLY = True                         # Evita que JavaScript acceda a las cookies de sesión (más seguro)
SESSION_COOKIE_SECURE = False                          # Está bien para desarrollo (usa True en producción con HTTPS)
SESSION_COOKIE_AGE = 1209600                           # Opcional: duración de la sesión (en segundos, aquí son 2 semanas)
SESSION_SAVE_EVERY_REQUEST = True    

# Login/logout
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

# Autenticación con Google (social-auth)
AUTHENTICATION_BACKENDS = (
    'social_core.backends.google.GoogleOAuth2',
    'django.contrib.auth.backends.ModelBackend',
)

# Autenticación con Google: leer desde variables de entorno
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "")


# Clave por defecto para modelos
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',

    'social_core.pipeline.user.create_user',

    'appsexshop.pipeline.create_user_in_custom_table',  # Crea en tu tabla personalizada

    'social_core.pipeline.social_auth.associate_user',  # 🔄 Aquí debe ir antes de guardar sesión
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',

    'appsexshop.pipeline.save_custom_session',  # ✅ Esto debe ir al final, cuando ya hay user asociado
)

EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587

EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "store.fantasia.intima@gmail.com")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "").replace(" ", "")
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
SERVER_EMAIL = EMAIL_HOST_USER


# Configuración de PayPal en modo sandbox:
PAYPAL_RECEIVER_EMAIL = 'sb-ryrqh45119542@business.example.com'  # Tu correo de sandbox
PAYPAL_TEST = True


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console':{'class':'logging.StreamHandler'},
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {'handlers': ['console'], 'level': 'INFO', 'propagate': False},
        # tu módulo
        'tu_aplicacion': {'handlers': ['console'], 'level': 'DEBUG', 'propagate': False},
    },
}
