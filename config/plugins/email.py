import os

SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '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')

ANYMAIL = {
    "SENDGRID_API_KEY": SENDGRID_API_KEY,
}

EMAIL_BACKEND = "anymail.backends.sendgrid.EmailBackend"

SERVER_EMAIL = os.environ.get('SERVER_EMAIL', 'stephan@skyrockprojects.com')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'info@skyrockprojects.com')

# if os.environ.get('DEBUG', True) in ('True', 'true', True,):
#     EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
