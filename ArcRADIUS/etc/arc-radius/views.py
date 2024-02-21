from flask import redirect, flash, url_for, send_file, request
from flask_admin import expose, BaseView
from flask_admin.contrib import sqla
from flask_admin.helpers import get_form_data
from flask_admin.babel import gettext
from markupsafe import Markup
import pyotp
import qrcode
import requests
import os
import json
import subprocess
from io import BytesIO
from flask_login import UserMixin, LoginManager, current_user
from flask_admin.form import SecureForm
from flask_admin.form import rules
from wtforms import PasswordField

from flask_admin.form import SecureForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Optional
from flask_bcrypt import generate_password_hash

from helper import createAddressFileIfNotExists, get_unique_username
import sqlite3
import re


LOG_DIR = 'logs'


class UserView(sqla.ModelView):

    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        # return super().inaccessible_callback(name, **kwargs)
        return redirect(url_for('login'))

    page_size = 5

    column_list = ('id', 'username', 'password', 'otp_secret', 'show_otp')
    column_editable_list = ['username']

    # override the column labels
    column_labels = {
        'id': 'ID',
        'username': 'Username',
        'password': 'Password',
        'otp_secret': 'OTP secret',
        'show_otp': 'Tools'
    }

    list_template = 'admin/user_list.html'


    # Add this method to your UserView class
    @expose('/sample-view', methods=['GET'])
    def sample_view(self):
        # Get data from ./samples/db.sqlite3 from table user
        conn = sqlite3.connect('samples/db.sqlite3')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user')
        sample_data = cursor.fetchall()

        return self.render('admin/user_samples.html', sample_data=sample_data)
    
    # Import sample data to the current database
    @expose('/import-sample', methods=['POST'])
    def import_sample(self):
        # Get data from current database and make all usernames into a list
        conn = sqlite3.connect('instance/db.sqlite3')
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM user')
        current_usernames = [row[0] for row in cursor.fetchall()]
        conn.close()

        # Get data from ./samples/db.sqlite3 from table user
        conn = sqlite3.connect('samples/db.sqlite3')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user')
        sample_data = cursor.fetchall()
        conn.close()

        # Insert sample data to the current database
        conn = sqlite3.connect('instance/db.sqlite3')
        cursor = conn.cursor()
        for row in sample_data:
            row = (row[0], get_unique_username(row[1], current_usernames), row[2], row[3])

            cursor.execute('INSERT INTO user (username, password, otp_secret) VALUES (?, ?, ?)', row[1:])
        conn.commit()
        conn.close()

        return redirect(url_for('user.index_view'))


    def create_form(self, obj=None):
        form = super(UserView, self).create_form(obj=obj)
        
        # Set default value for the otp_secret field
        form.otp_secret.data = pyotp.random_base32()

        return form

    def _format_show_otp(view, context, model, name):

        qr_display_url = url_for('.qr_display_view')

        _html = '''
            <form action="{qr_display_url}" method="POST">
                <input id="otp_secret" name="otp_secret" type="hidden" value="{otp_secret}">
                <input id="username" name="username" type="hidden" value="{username}">
                <button type='submit' class='btn btn-default'>Show QR code</button>
            </form>
        '''.format(qr_display_url=qr_display_url, otp_secret=model.otp_secret, username=model.username)

        return Markup(_html)

    column_formatters = {
        'show_otp': _format_show_otp
    }

    @expose('qr-code', methods=['POST'])
    def qr_display_view(self):

        return_url = self.get_url('.index_view')

        form = get_form_data()

        if not form:
            flash(gettext('Could not get form from request.'), 'error')
            return redirect(return_url)

        otp_secret = form['otp_secret']
        username = form['username']

        totp = pyotp.TOTP(otp_secret)
        issuer_name = "ArcRADIUS"  # Your organization or app name
        account_name = username  # Your account name or label
        qr_code_url = totp.provisioning_uri(account_name, issuer_name=issuer_name)

        # Generate the QR code image
        qr = qrcode.make(qr_code_url)

        # Convert the QR code image to bytes
        qr_bytes = BytesIO()
        qr.save(qr_bytes)

        # Return the QR code image
        qr_bytes.seek(0)
        return send_file(qr_bytes, mimetype='image/png')


class PanelAdminForm(SecureForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[Optional()])
    otp_secret = StringField('OTP Secret')
    is_otp_enabled = BooleanField('Is OTP enabled')
    is_active = BooleanField('Is active')

    # Override populate_obj method to conditionally set password field
    def populate_obj(self, obj):
        if self.password.data:
            setattr(obj, 'password', generate_password_hash(self.password.data))

        # Call the parent populate_obj method with the provided arguments
        super().populate_obj(obj)

class PanelAdminView(sqla.ModelView):
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))
    
    column_list = ('id', 'username', 'is_otp_enabled', 'is_active')
    column_labels = {
        'id': 'ID',
        'username': 'Username',
        'password': 'Password',
        'is_otp_enabled': 'Is OTP enabled [not implemented]',
        'is_active': 'Is active'
    }

    form = PanelAdminForm


class LogViewer(BaseView):
    @expose('/')
    def index(self):
        # Read the contents of the log file
        log_file_path = os.path.join(LOG_DIR, 'radius_server.log')
        with open(log_file_path, 'r') as log_file:
            log_contents = log_file.read()

        # Render the log viewer template with the log contents
        return self.render('admin/log_viewer.html', log_contents=log_contents)

    @expose('/clear', methods=['POST'])
    def clear_log(self):
        # Remove the contents of the log file
        log_file_path = os.path.join(LOG_DIR, 'radius_server.log')
        open(log_file_path, 'w').close()

        # Redirect back to the log viewer page
        return redirect(url_for('logviewer.index'))
    
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        # return super().inaccessible_callback(name, **kwargs)
        return redirect(url_for('login'))


# Settings page
class SettingsView(BaseView):
    def __init__(self, name=None, category=None, endpoint=None, url=None, **kwargs):
        super(SettingsView, self).__init__(name, category, endpoint, url, **kwargs)
        self.config_file_path = 'config.json'
        self.settings = self.load_settings()
            
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        # return super().inaccessible_callback(name, **kwargs)
        return redirect(url_for('login'))


    def load_settings(self):
        try:
            with open(self.config_file_path, 'r') as config_file:
                return json.load(config_file)
        except FileNotFoundError:
            # If the config file doesn't exist, return default settings
            return {
                "save_last_package": False,
                "enable_debug_mode": False,
                "password_and_otp_same_field": False,
                "otp_pin_field": "",
                "check_otp": True,
                "check_password": True
            }

    def save_settings(self):
        with open(self.config_file_path, 'w') as config_file:
            json.dump(self.settings, config_file, indent=4)

    @expose('/', methods=['GET', 'POST'])
    def index(self):
        if request.method == 'POST':
            self.settings['save_last_package'] = 'save_last_package' in request.form
            self.settings['enable_debug_mode'] = 'enable_debug_mode' in request.form
            self.settings['password_and_otp_same_field'] = 'password_and_otp_same_field' in request.form
            self.settings['otp_pin_field'] = request.form.get('otp_pin_field', '')
            self.settings['check_otp'] = 'check_otp' in request.form  # Update check_otp based on form data
            self.settings['check_password'] = 'check_password' in request.form  # Update check_password based on form data
            self.save_settings()
            return redirect(url_for('settings.index'))

        return self.render('admin/settings.html', settings=self.settings)

class PackageAnalyseView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        # return super().inaccessible_callback(name, **kwargs)
        return redirect(url_for('login'))

    @expose('/')
    def index(self):
        file_path = "last_package.txt"
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                package_content = file.read()
        else:
            package_content = "No package content available."     

        return self.render('admin/package_analyse.html', package_content=package_content)

    @expose('/remove-content', methods=['POST'])
    def remove_content(self):
        file_path = "last_package.txt"
        if os.path.exists(file_path):
            os.remove(file_path)
            flash("Last package content has been removed.", "success")
        else:
            flash("No last package content to remove.", "error")
        return redirect(url_for('package_analyse.index'))
    

class ServiceManagement(BaseView):
    @expose('/')
    def index(self):
        try:
            # Execute the shell command to check the service status
            output = subprocess.check_output(["systemctl", "status", "arc-radius.service"])

            # Convert the output to string and set it as the service status
            service_status = output.decode("utf-8")
        except subprocess.CalledProcessError as e:
            # If an error occurs, set an error message as the service status
            if e.returncode == 3:
                service_status = "Service is not running"
            else:
                service_status = f"Error: {e}"

        # Render the service management template with the service status
        return self.render('admin/service_management.html', service_status=service_status)

    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))  # Redirect to the login page if the user is not authenticated
    
    @expose('/restart_service', methods=['POST'])
    def restart_service(self):
        try:
            # Execute the shell command to restart the service
            subprocess.run(["sudo", "systemctl", "restart", "arc-radius.service"], check=True)
        except subprocess.CalledProcessError as e:
            # If an error occurs, redirect back to the service management page with an error message
            return redirect(url_for('service_management.index', message=f"Error restarting service: {e}"))

        # Redirect back to the service management page
        return redirect(url_for('service_management.index'))

    @expose('/start_service', methods=['POST'])
    def start_service(self):
        try:
            # Execute the shell command to start the service
            subprocess.run(["sudo", "systemctl", "start", "arc-radius.service"], check=True)
        except subprocess.CalledProcessError as e:
            # If an error occurs, redirect back to the service management page with an error message
            return redirect(url_for('service_management.index', message=f"Error starting service: {e}"))

        # Redirect back to the service management page
        return redirect(url_for('service_management.index'))

    @expose('/stop_service', methods=['POST'])
    def stop_service(self):
        try:
            # Execute the shell command to stop the service
            subprocess.run(["sudo", "systemctl", "stop", "arc-radius.service"], check=True)
        except subprocess.CalledProcessError as e:
            # If an error occurs, redirect back to the service management page with an error message
            return redirect(url_for('service_management.index', message=f"Error stopping service: {e}"))

        # Redirect back to the service management page
        return redirect(url_for('service_management.index'))

    @expose('/refresh_status', methods=['POST'])
    def refresh_status(self):
        # Redirect back to the service management page to refresh the status
        return redirect(url_for('service_management.index'))
    

class RadiusClientsView(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        createAddressFileIfNotExists()
        address_filePath = "./clients/address.yml"
        # Handle form submission to edit the address.yml file
        if request.method == 'POST':
            # Retrieve form data
            new_address = request.form['address']
            # Update the address.yml file with the new address
            with open(address_filePath, 'w') as file:
                file.write(new_address)
            # Redirect back to the edit page
            try:
                # Execute the shell command to restart the service
                subprocess.run(["sudo", "systemctl", "restart", "arc-radius.service"], check=True)
            except subprocess.CalledProcessError as e:
                # If an error occurs, redirect back to the service management page with an error message
                return redirect(url_for('radius_clients.index', message=f"Error restarting service: {e}"))

            # Redirect back to the service management page
            return redirect(url_for('radius_clients.index'))

        # Render the address edit page
        with open(address_filePath, 'r') as file:
            current_address = file.read()
        return self.render('admin/radius_clients_edit.html', address=current_address)
    
    @expose('/sample1', methods=['POST'])
    def sample1(self):
        address_filePath = "./samples/address.yml"

        if request.method == 'POST':
            # Retrieve data from sample file
            with open(address_filePath, 'r') as file:
                new_address = file.read()

            # Display the sample data
            return self.render('admin/radius_clients_edit.html', address=new_address)
    
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self, name, **kwargs):
        # return super().inaccessible_callback(name, **kwargs)
        return redirect(url_for('login'))
