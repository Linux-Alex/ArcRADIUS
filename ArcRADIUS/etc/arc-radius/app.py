from flask import Flask, render_template, redirect, session, url_for, request, flash
from flask_admin import Admin, AdminIndexView, BaseView, expose
from flask_admin.menu import MenuLink
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user

from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
import os
from flask_basicauth import BasicAuth
from views import UserView, PanelAdminView, SettingsView, LogViewer, PackageAnalyseView
from flask_bcrypt import check_password_hash, generate_password_hash
import json




from pprint import pprint
import requests

app = Flask(__name__)

LOG_DIR = 'logs'

# Set the secret key to enable sessions
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Set optional bootswatch theme
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

# Customized navigation menu
class MyAdminIndexView(AdminIndexView):
    def is_visible(self):
        # Override this method to control the visibility of the index view
        # For example, return True if you want the index view to be visible
        # Return False if you want to hide it from the navigation menu
        return True

    def _menu(self):
        menu = super(MyAdminIndexView, self)._menu()

        # Remove all existing menu links
        menu.clear()

        # Add "Login" link if user is not logged in
        if not current_user.is_authenticated:
            menu.append(MenuLink(name='Login', url='/login'))

        # Add "Logout" link if user is logged in
        else:
            menu.append(MenuLink(name='Logout', url='/logout'))

        return menu


basic_auth = BasicAuth(app)
db = SQLAlchemy(app)
admin = Admin(app, name='ArcRADIUS', template_mode='bootstrap3', index_view=MyAdminIndexView())
login = LoginManager(app)

@login.user_loader
def load_user(user_id):
    return PanelAdmin.query.get(int(user_id))

#Define PanelAdmin model
class PanelAdmin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    _password = db.Column(db.String(256))
    otp_secret = db.Column(db.String(256))
    is_otp_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    @property
    def password(self):
        # raise AttributeError('Password is not readable')
        return self._password

    @password.setter
    def password(self, password):
        self._password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self._password, password)

    def __str__(self):
        return self.username

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(256))
    otp_secret = db.Column(db.String(256))

    def __str__(self):
        return self.username

# Add administrative views for User model
admin.add_view(UserView(User, db.session))
admin.add_view(PanelAdminView(PanelAdmin, db.session))

# Update Admin index view
admin.index_view = MyAdminIndexView(name='ArcRADIUS', template='admin/index.html')

class LogoutMenuLink(MenuLink):
    def is_accessible(self):
        return current_user.is_authenticated

class LoginMenuLink(MenuLink):
    def is_accessible(self):
        return not current_user.is_authenticated

# check if user logged in
admin.add_link(LoginMenuLink(name='Login', url='/login'))
admin.add_link(LogoutMenuLink(name='Logout', url='/logout'))

# Function to create database if it doesn't exist
def create_database():
    if not os.path.exists('db.sqlite3'):
        with app.app_context():
            db.create_all()

# Create the database if it doesn't exist
create_database()

@app.route('/')
def index():
    return redirect('/admin/')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = PanelAdmin.query.filter_by(username=username, is_active=True).first()
        print("User: ", type(user))
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))  # Redirect back to the login page
    return render_template("login/index.html")


# Logout route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('admin.index'))

class AddressEditView(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        address_filePath = "./clients/address.yml"
        # Handle form submission to edit the address.yml file
        if request.method == 'POST':
            # Retrieve form data
            new_address = request.form['address']
            # Update the address.yml file with the new address
            with open(address_filePath, 'w') as file:
                file.write(new_address)
            # Redirect back to the edit page
            return redirect(url_for('addressedit.index'))

        # Render the address edit page
        with open(address_filePath, 'r') as file:
            current_address = file.read()
        return self.render('admin/address_edit.html', address=current_address)
    
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        # return super().inaccessible_callback(name, **kwargs)
        return redirect(url_for('login'))


admin.add_view(AddressEditView(name='Edit Address', endpoint='addressedit'))


admin.add_view(LogViewer(name='View Log', endpoint='logviewer'))


admin.add_view(PackageAnalyseView(name='Package Analyse', endpoint='package_analyse'))


admin.add_view(SettingsView(name='Settings', endpoint='settings'))


# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=4048)
