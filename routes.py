from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import os
import datetime

from . import db
from .models import User, AutomobileInsurance, TravelInsurance
from .forms import RegisterForm, LoginForm, AutomobileInsuranceForm, TravelInsuranceForm, ChangePasswordForm

from flask_mail import Message
from . import mail
from flask import abort

main = Blueprint('main', __name__)

def send_email(recipient, subject, body):
    try:
        msg = Message(
            subject,
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[recipient]
        )
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email to {recipient}: {str(e)}")
        return False

@main.route('/')
def home():
    return render_template('base.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html', form=form)
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please use a different email.', 'danger')
            return render_template('register.html', form=form)
        
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role='client'
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()

        # Send welcome email
        email_sent = send_email(
            new_user.email,
            'Welcome to BInsurance!',
            f"""Dear {new_user.username},
            
Thank you for registering with BInsurance!
            
Your account has been successfully created.
            
If you didn't request this, please contact our support team immediately.
            
Best regards,
BInsurance Team"""
        )

        if email_sent:
            flash('Registration successful! A welcome email has been sent.', 'success')
        else:
            flash('Registration successful! Welcome email could not be sent.', 'warning')

        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            
            # Send login notification
            send_email(
                user.email,
                'Successful Login Notification',
                f"""Hello {user.username},
                
You have successfully logged into your BInsurance account at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}.
                
If this wasn't you, please secure your account immediately.
                
Best regards,
BInsurance Security Team"""
            )
            
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    user_email = current_user.email
    logout_user()
    flash('You have been logged out.', 'info')
    
    # Send logout notification
    send_email(
        user_email,
        'Logout Notification',
        f"""You have been logged out of your BInsurance account at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}.
        
If this wasn't you, please secure your account immediately."""
    )
    
    return redirect(url_for('main.login'))

@main.route('/dashboard')
@login_required
def dashboard():
    automobile_records = current_user.automobile_insurances
    travel_records = current_user.travel_insurances
    return render_template(
        'dashboard.html',
        user=current_user,
        automobile_records=automobile_records,
        travel_records=travel_records
    )

@main.route('/automobile', methods=['GET', 'POST'])
@login_required
def automobile_insurance():
    form = AutomobileInsuranceForm()
    if form.validate_on_submit():
        carte_rose_filename = None
        ancient_card_filename = None

        if form.carte_rose.data and form.carte_rose.data.filename != '':
            carte_rose_filename = secure_filename(form.carte_rose.data.filename)
            form.carte_rose.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], carte_rose_filename))

        if form.ancient_card.data and form.ancient_card.data.filename != '':
            ancient_card_filename = secure_filename(form.ancient_card.data.filename)
            form.ancient_card.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], ancient_card_filename))

        submission = AutomobileInsurance(
            user_id=current_user.id,
            carte_rose_filename=carte_rose_filename,
            ancient_card_filename=ancient_card_filename,
            phone=form.phone.data,
            city=form.city.data,
            province=form.province.data
        )
        db.session.add(submission)
        db.session.commit()
        
        # Send confirmation to user
        send_email(
            current_user.email,
            'Automobile Insurance Request Received',
            f"""Dear {current_user.username},
            
We have received your automobile insurance request (ID: {submission.id}).
            
Our team will process your request shortly. Please contact +25762555777 for more information.
            
Thank you for choosing BInsurance."""
        )
        
        # Send notification to admin
        send_email(
            'mugishapc1@gmail.com',
            'New Automobile Insurance Request',
            f"""User {current_user.username} (Email: {current_user.email}) has submitted a new automobile insurance request.
            
Request ID: {submission.id}
Phone: {submission.phone}
Location: {submission.city}, {submission.province}"""
        )
        
        flash('Your automobile insurance request was submitted successfully! A confirmation has been sent to your email.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('automobile_insurance.html', form=form)

@main.route('/travel', methods=['GET', 'POST'])
@login_required
def travel_insurance():
    form = TravelInsuranceForm()
    if form.validate_on_submit():
        passport_filename = None
        if form.passport.data and form.passport.data.filename != '':
            passport_filename = secure_filename(form.passport.data.filename)
            form.passport.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], passport_filename))
        
        submission = TravelInsurance(
            user_id=current_user.id,
            passport_filename=passport_filename,
            email=form.email.data,
            phone=form.phone.data,
            destination=form.destination.data,
            days=form.days.data,
            city=form.city.data,
            province=form.province.data
        )
        db.session.add(submission)
        db.session.commit()
        
        # Send confirmation to user
        send_email(
            current_user.email,
            'Travel Insurance Request Received',
            f"""Dear {current_user.username},
            
We have received your travel insurance request (ID: {submission.id}).
            
Destination: {submission.destination}
Duration: {submission.days} days
            
Our team will process your request shortly. Please contact +25762555777 for more information.
            
Thank you for choosing BInsurance."""
        )
        
        # Send notification to admin
        send_email(
            'mugishapc1@gmail.com',
            'New Travel Insurance Request',
            f"""User {current_user.username} (Email: {current_user.email}) has submitted a new travel insurance request.
            
Request ID: {submission.id}
Destination: {submission.destination}
Duration: {submission.days} days
Phone: {submission.phone}"""
        )
        
        flash('Your travel insurance request was submitted successfully! A confirmation has been sent to your email.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('travel_insurance.html', form=form)

@main.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('main.dashboard'))
    all_auto = AutomobileInsurance.query.all()
    all_travel = TravelInsurance.query.all()
    return render_template('admin_dashboard.html', all_auto=all_auto, all_travel=all_travel)

@main.route('/delete_request/<string:request_type>/<int:request_id>', methods=['POST'])
@login_required
def delete_request(request_type, request_id):
    if request_type == 'auto':
        req = AutomobileInsurance.query.get_or_404(request_id)
    elif request_type == 'travel':
        req = TravelInsurance.query.get_or_404(request_id)
    else:
        abort(404)

    if req.user_id != current_user.id:
        abort(403)

    # Send deletion notification
    send_email(
        current_user.email,
        f'Your {request_type} Insurance Request Was Deleted',
        f"""Dear {current_user.username},
        
Your {request_type} insurance request (ID: {request_id}) has been deleted.
        
If this wasn't you, please contact our support team immediately."""
    )
    
    db.session.delete(req)
    db.session.commit()
    flash('Request deleted successfully. A confirmation has been sent to your email.', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/admin/delete_request/<request_type>/<int:request_id>', methods=['POST'])
@login_required
def admin_delete_request(request_type, request_id):
    if current_user.role != 'admin':
        abort(403)
    
    if request_type == 'auto':
        request = AutomobileInsurance.query.get_or_404(request_id)
    elif request_type == 'travel':
        request = TravelInsurance.query.get_or_404(request_id)
    else:
        abort(404)
    
    # Send notification to user
    send_email(
        request.user.email,
        f'Your {request_type} Insurance Request Was Deleted by Admin',
        f"""Dear {request.user.username},
        
Your {request_type} insurance request (ID: {request_id}) has been deleted by an administrator.
        
Please contact support if you have any questions."""
    )
    
    db.session.delete(request)
    db.session.commit()
    flash('Request deleted successfully. The user has been notified.', 'success')
    return redirect(url_for('main.admin_dashboard'))

@main.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            
            # Send password change notification
            try:
                msg = Message(
                    'Password Changed',
                    sender='noreply@binsurance.com',
                    recipients=[current_user.email]
                )
                msg.body = f"""
                Hello {current_user.username},
                
                Your BInsurance account password was recently changed.
                
                If you didn't make this change, please contact support immediately.
                
                Time of change: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}
                
                Best regards,
                BInsurance Security Team
                """
                mail.send(msg)
                flash('Password updated successfully! Notification sent to your email.', 'success')
            except Exception as e:
                flash('Password updated successfully! Notification email failed to send.', 'warning')
            
            return redirect(url_for('main.dashboard'))
        else:
            flash('Incorrect current password.', 'danger')
    return render_template('change_password.html', form=form)