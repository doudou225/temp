from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail


app = Flask(__name__)

app.config['SECRET_KEY'] = '1f2f1fdad1833afacc37d1d0723423878de8634a61164f69a013961572eb3ebf'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/doudou/myapp/mysite/database.db'

db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

login_manager = LoginManager()


login_manager.login_view = 'login'
login_manager.login_message_category = 'info' # add style to "Please log in to access this page."
login_manager.init_app(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'letsbeready225@gmail.com'
app.config['MAIL_PASSWORD'] = 'erviaupqfhyllcwu'
app.config['MAIL_DEFAULT_SENDER '] = 'NoReply@gmail.com'

mail = Mail(app)

from mysite import route
