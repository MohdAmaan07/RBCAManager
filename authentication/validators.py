from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _  

class CustomPasswordValidator:  

    def __init__(self, min_length=8):
        self.min_length = min_length

    def validate(self, password, user=None):
        special_characters = "[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]"
        
        if not any(char.isdigit() for char in password):
            raise ValidationError(_('Password must contain at least one digit.'))

        if not any(char.isalpha() for char in password):
            raise ValidationError(_('Password must contain at least one letter.'))

        if not any(char in special_characters for char in password):
            raise ValidationError(_('Password must contain at least one special character.'))

        if len(password) < self.min_length:
            raise ValidationError(_('Password must be at least %(min_length)d characters long.') % {'min_length': self.min_length})

    def get_help_text(self):
        return _('Your password must be at least %(min_length)d characters long, contain at least one digit, '
                 'one letter, and one special character.') % {'min_length': self.min_length}
