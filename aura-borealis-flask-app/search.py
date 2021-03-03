from wtforms import Form, StringField, SelectField
from wtforms.validators import DataRequired

class PackageSearch(Form):
    package = StringField('package', validators=[DataRequired()])
