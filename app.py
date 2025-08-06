import os
import logging
from datetime import datetime, timedelta, date
from functools import wraps
import secrets
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import json

# Flask imports
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate

# PDF generation
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, blue
    from reportlab.lib.styles import getSampleStyleSheet
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Initialize Flask app
app = Flask(__name__)

# Timezone conversion utility
from datetime import timezone, timedelta

def utc_to_sast(utc_dt):
    """Convert UTC datetime to South African Standard Time (SAST)"""
    if utc_dt is None:
        return None
    # SAST is UTC+2
    sast = timezone(timedelta(hours=2))
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(sast)

# Add to Jinja2 template globals
@app.template_global()
def to_sast(utc_dt):
    """Template function to convert UTC to SAST"""
    return utc_to_sast(utc_dt)

# Configuration - Updated with new SMTP settings
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'secret-key-change-this-in-production'

# Supabase PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres.xwxeyzwmbypzzlmgfkcq:ash1951@aws-0-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_timeout': 20,
    'max_overflow': 0,
    'connect_args': {
        'sslmode': 'require'
    }
}
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Updated Email configuration with SMTP credentials
app.config['MAIL_SERVER'] = 'mail.lis-demos.co.za'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'techassess@lis-demos.co.za'
app.config['MAIL_PASSWORD'] = 'Test@12345#TTf'
app.config['MAIL_DEFAULT_SENDER'] = 'techassess@lis-demos.co.za'

# Certificate settings
app.config['CERTIFICATE_VALIDITY_YEARS'] = 3


db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'documents'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'certificates'), exist_ok=True)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# DATABASE MODELS
# =============================================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    is_internal = db.Column(db.Boolean, default=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_group(self, group_name):
        try:
            from sqlalchemy import and_
            assignment = UserGroupAssignment.query.join(Group).filter(
                and_(UserGroupAssignment.user_id == self.id, Group.name == group_name)
            ).first()
            return assignment is not None
        except Exception as e:
            db.session.rollback()  # Rollback the failed transaction
            logger.error(f'Error checking user group: {e}')
            return False

    def get_groups(self):
        assignments = UserGroupAssignment.query.filter_by(user_id=self.id).all()
        return [assignment.group for assignment in assignments]

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

class Group(db.Model):
    __tablename__ = 'groups'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserGroupAssignment(db.Model):
    __tablename__ = 'user_group_assignments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    assigned_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships with explicit foreign_keys
    user = db.relationship('User', foreign_keys=[user_id])
    group = db.relationship('Group', foreign_keys=[group_id])
    assigned_by = db.relationship('User', foreign_keys=[assigned_by_user_id])

class Stage(db.Model):
    __tablename__ = 'stages'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    stage_number = db.Column(db.Float, unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    is_review_stage = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    parent_stage_id = db.Column(db.Integer, db.ForeignKey('stages.id'))
    next_stage_id = db.Column(db.Integer, db.ForeignKey('stages.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Self-referencing relationships with explicit foreign_keys
    parent_stage = db.relationship('Stage', remote_side=[id], foreign_keys=[parent_stage_id])
    next_stage = db.relationship('Stage', remote_side=[id], foreign_keys=[next_stage_id])

class StageGroupAssignment(db.Model):
    __tablename__ = 'stage_group_assignments'

    id = db.Column(db.Integer, primary_key=True)
    stage_id = db.Column(db.Integer, db.ForeignKey('stages.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    stage = db.relationship('Stage', foreign_keys=[stage_id])
    group = db.relationship('Group', foreign_keys=[group_id])

class StageNotificationRule(db.Model):
    __tablename__ = 'stage_notification_rules'

    id = db.Column(db.Integer, primary_key=True)
    stage_id = db.Column(db.Integer, db.ForeignKey('stages.id'), nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)  # 'approved', 'review', 'both'
    notify_groups = db.Column(db.Boolean, default=True)
    notify_client = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    stage = db.relationship('Stage', foreign_keys=[stage_id])

class Company(db.Model):
    __tablename__ = 'companies'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    registration_number = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(50))
    address = db.Column(db.Text)
    website = db.Column(db.String(200))
    contact_person = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Application(db.Model):
    __tablename__ = 'applications'

    id = db.Column(db.Integer, primary_key=True)
    application_number = db.Column(db.String(50), unique=True, nullable=False)
    applicant_name = db.Column(db.String(200), nullable=False)
    applicant_email = db.Column(db.String(120), nullable=False)
    applicant_phone = db.Column(db.String(50))
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    certificate_type = db.Column(db.String(200), nullable=False)
    current_stage_id = db.Column(db.Integer, db.ForeignKey('stages.id'), nullable=False)
    status = db.Column(db.String(50), default='Submitted', nullable=False)
    priority = db.Column(db.String(20), default='Normal')
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    company = db.relationship('Company', foreign_keys=[company_id])
    current_stage = db.relationship('Stage', foreign_keys=[current_stage_id])

    def generate_application_number(self):
        """Generate unique application number"""
        if not self.application_number:
            year = datetime.now().year
            # Get the last application number for this year
            last_app = Application.query.filter(
                Application.application_number.like(f'APP{year}%')
            ).order_by(Application.application_number.desc()).first()

            if last_app:
                # Extract the sequence number and increment
                try:
                    last_seq = int(last_app.application_number.split('-')[-1])
                    seq = last_seq + 1
                except (ValueError, IndexError):
                    seq = 1
            else:
                seq = 1

            self.application_number = f'APP{year}-{seq:04d}'

    def generate_client_upload_token(self):
        """Generate secure upload token for this application"""
        # Create a hash based on application ID and secret key
        token_data = f"{self.id}:{self.application_number}:{app.config['SECRET_KEY']}"
        return hashlib.sha256(token_data.encode()).hexdigest()[:32]

    @staticmethod
    def verify_client_upload_token(token, application_number):
        """Verify client upload token"""
        try:
            application = Application.query.filter_by(application_number=application_number).first()
            if application:
                expected_token = application.generate_client_upload_token()
                return application if token == expected_token else None
            return None
        except:
            return None

    @staticmethod
    def generate_access_token():
        """Generate secure access token for external uploads"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def verify_access_token(token):
        """Verify access token and return associated application"""
        # Simple implementation - in production, store tokens in database with expiry
        try:
            # For now, encode application ID in token (not secure for production)
            return Application.query.first()  # Simplified for demo
        except:
            return None

class ApplicationHistory(db.Model):
    __tablename__ = 'application_history'

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    from_stage_id = db.Column(db.Integer, db.ForeignKey('stages.id'))
    to_stage_id = db.Column(db.Integer, db.ForeignKey('stages.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text)
    moved_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    application = db.relationship('Application', foreign_keys=[application_id])
    from_stage = db.relationship('Stage', foreign_keys=[from_stage_id])
    to_stage = db.relationship('Stage', foreign_keys=[to_stage_id])
    moved_by_user = db.relationship('User', foreign_keys=[moved_by_user_id])

class Document(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    document_type = db.Column(db.String(100), default='General Document')
    description = db.Column(db.Text)
    uploaded_by_external = db.Column(db.Boolean, default=False)
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    application = db.relationship('Application', foreign_keys=[application_id])
    uploaded_by_user = db.relationship('User', foreign_keys=[uploaded_by_user_id])

class Certificate(db.Model):
    __tablename__ = 'certificates'

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    certificate_number = db.Column(db.String(100), unique=True, nullable=False)
    certificate_file = db.Column(db.String(255))
    issued_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(50), default='Active', nullable=False)  # Active, InActive, Withdrawn, Suspended, Cancelled
    generated_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    application = db.relationship('Application', foreign_keys=[application_id])
    generated_by = db.relationship('User', foreign_keys=[generated_by_user_id])

    def generate_certificate_number(self):
        """Generate unique certificate number"""
        if not self.certificate_number:
            year = datetime.now().year
            # Get the last certificate number for this year
            last_cert = Certificate.query.filter(
                Certificate.certificate_number.like(f'CERT{year}%')
            ).order_by(Certificate.certificate_number.desc()).first()

            if last_cert:
                try:
                    last_seq = int(last_cert.certificate_number.split('-')[-1])
                    seq = last_seq + 1
                except (ValueError, IndexError):
                    seq = 1
            else:
                seq = 1

            self.certificate_number = f'CERT{year}-{seq:04d}'

class NotificationSignature(db.Model):
    __tablename__ = 'notification_signatures'

    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(50))
    website = db.Column(db.String(200))
    address = db.Column(db.Text)
    signature_text = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CertificateStatusHistory(db.Model):
    __tablename__ = 'certificate_status_history'

    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificates.id'), nullable=False)
    old_status = db.Column(db.String(50), nullable=False)
    new_status = db.Column(db.String(50), nullable=False)
    reason = db.Column(db.Text)
    changed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    certificate = db.relationship('Certificate', foreign_keys=[certificate_id])
    changed_by = db.relationship('User', foreign_keys=[changed_by_user_id])

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(255), nullable=False)
    entity_type = db.Column(db.String(100))
    entity_id = db.Column(db.Integer)
    details = db.Column(db.Text)  # JSON string
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id])

    @staticmethod
    def create_log(user_id, action, entity_type=None, entity_id=None, details=None):
        try:
            audit = AuditLog(
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=json.dumps(details) if details else None,
                ip_address=request.remote_addr if request else None,
                user_agent=request.user_agent.string if request else None
            )
            db.session.add(audit)
            db.session.commit()
        except Exception as e:
            logger.error(f'Failed to create audit log: {e}')

# =============================================================================
# LOGIN MANAGER
# =============================================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =============================================================================
# DECORATORS
# =============================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.has_group('Administrators'):
            flash('Administrator access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# EMAIL SERVICE
# =============================================================================

class EmailService:
    def __init__(self):
        self.smtp_server = app.config['MAIL_SERVER']
        self.smtp_port = app.config['MAIL_PORT']
        self.use_tls = app.config['MAIL_USE_TLS']
        self.username = app.config['MAIL_USERNAME']
        self.password = app.config['MAIL_PASSWORD']
        self.default_sender = app.config['MAIL_DEFAULT_SENDER']

    def get_notification_signature(self):
        """Get notification signature from database"""
        signature = NotificationSignature.query.filter_by(is_active=True).first()
        if signature:
            return f"""
            <br><br>
            <p>Kind Regards,<br>
            {signature.company_name}<br>
            Email: {signature.email}<br>
            Tel: {signature.phone}<br>
            Website: {signature.website}</p>
            """
        return "<br><br><p>Kind Regards,<br>Certificate Management Team</p>"

    def send_email(self, to_emails, subject, body, attachments=None):
        """Send email with complete error handling"""
        try:
            if not self.username or not self.password:
                logger.warning('Email credentials not configured')
                return False

            msg = MIMEMultipart()
            msg['From'] = self.default_sender
            msg['To'] = ', '.join(to_emails) if isinstance(to_emails, list) else to_emails
            msg['Subject'] = subject

            # Add signature to body
            body_with_signature = body + self.get_notification_signature()
            msg.attach(MIMEText(body_with_signature, 'html'))

            # Add attachments
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {os.path.basename(file_path)}'
                            )
                            msg.attach(part)

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f'Email sent successfully to {to_emails}')
            return True

        except Exception as e:
            logger.error(f'Failed to send email: {e}')
            return False

    def get_stage_groups(self, stage_id):
        """Get groups assigned to a stage"""
        assignments = StageGroupAssignment.query.filter_by(stage_id=stage_id).all()
        return [assignment.group for assignment in assignments]

    def send_stage_notification(self, application, action, new_stage, reason=None, notification_type='approved'):
        """Send comprehensive stage notifications based on exact workflow specification"""
        try:
            logger.info(f'Sending notifications for application {application.application_number}, action: {action}, stage: {new_stage.name}')

            # Get notification rules based on your exact specification
            notification_rules = self.get_stage_notification_rules(new_stage.stage_number, action)
            
            # Get stage groups
            stage_groups = self.get_stage_groups(new_stage.id)
            logger.info(f'Found {len(stage_groups)} groups for stage {new_stage.stage_number}: {[g.name for g in stage_groups]}')

            # Determine if this is a rejection/review action
            rejection_actions = [
                'application_not_complete', 'rejected', 'payment_not_verified', 'not_allocated', 'request_info',
                'deviate', 'amendment', 'conditionally_approved', 'not_ratified', 'not_signed'
            ]

            is_rejection = action in rejection_actions
            logger.info(f'Action "{action}" is rejection: {is_rejection}')

            # Send notifications based on your specification
            if notification_rules.get('notify_groups', True) and stage_groups:
                try:
                    # Get additional notification groups from your specification
                    additional_groups = notification_rules.get('additional_groups', [])
                    all_notification_groups = stage_groups + self.get_groups_by_names(additional_groups)
                    
                    if is_rejection:
                        self.notify_groups_review(application, action, new_stage, all_notification_groups, reason)
                    else:
                        self.notify_groups_approved(application, action, new_stage, all_notification_groups, reason)
                    logger.info(f'Successfully notified {len(all_notification_groups)} groups')
                except Exception as e:
                    logger.error(f'Error notifying groups: {e}')

            # Client notifications based on your specification
            if notification_rules.get('notify_client', True):
                try:
                    if is_rejection or notification_type == 'review':
                        self.notify_client_review(application, action, new_stage, reason)
                    else:
                        self.notify_client_approved(application, action, new_stage, reason)
                    logger.info(f'Successfully notified client')
                except Exception as e:
                    logger.error(f'Error notifying client: {e}')

            return True

        except Exception as e:
            logger.error(f'Stage notification error: {e}')
            return False

    def get_stage_notification_rules(self, stage_number, action):
        """Get notification rules based on your exact workflow specification"""
        
        # Define which stages and actions should notify the client based on your specification
        client_notification_rules = {
            # Stage 1: New Application - Always notify client
            1.0: {'all_actions': True},
            
            # Stage 2: Verification of Application Completeness - Always notify client
            2.0: {'all_actions': True},
            
            # Stage 3: Admin Fee Request - Only notify client for "Accepted", NOT for "Rejected" or "Request Info"
            3.0: {'specific_actions': ['accepted']},
            
            # Stage 4.2: Admin fee-Proof of Payment (Client uploads) - Notify client with upload URL
            4.2: {'all_actions': True},
            
            # Stage 11: Client Response - Always notify client
            11.0: {'all_actions': True},
            
            # Stage 11.1: Review: Client Response - Always notify client  
            11.1: {'all_actions': True},
            
            # Stage 13.2: Evaluation fee-Proof of Payment (Client uploads) - Notify client with upload URL
            13.2: {'all_actions': True},
        }
        
        # Check if client should be notified for this stage and action
        should_notify_client = False
        if stage_number in client_notification_rules:
            rule = client_notification_rules[stage_number]
            if rule.get('all_actions', False):
                should_notify_client = True
            elif 'specific_actions' in rule:
                should_notify_client = action in rule['specific_actions']
        
        # Notification rules based on your detailed specification
        notification_rules = {
            # Stage 1: New Application by client - Notify TAO Group and Client
            1.0: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 2: Verification of Application Completeness - TAO Notify TAO Group and Client, Notify Client
            2.0: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 3: Admin Fee Request - Accepted: Notify TAO Group and Client, Rejected/Request Info: Notify TAO Group ONLY
            3.0: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 4: Admin Invoice Generation - Notify Finance Group and TAO Finance Group
            4.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO']},
            
            # Stage 4.1: Confirmation of Invoice - TAO (goes to client)
            4.1: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 4.2: Admin fee-Proof of Payment - Notify TAO Group and Finance Group AND CLIENT
            4.2: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 4.3: Payment Confirmation - Notify TAO Group, TGL: TA
            4.3: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO', 'TGL: TA']},
            
            # Stage 5: Allocation: Criteria Review - Notify TGL: TA Group, Notify TAO Group
            5.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO']},
            
            # Stage 5.1: Review: Application Criteria review - Notify Finance Group
            5.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Finance']},
            
            # Stage 6: Peer Review-Criteria Review - Notify Technical Services Group
            6.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services']},
            
            # Stage 6.1: Peer review Committee - Notify Technical Services Group
            6.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services']},
            
            # Stage 7: Approval - Application Criteria Report - Notify TGL:TA, STA and TAO Group
            7.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['STA', 'TAO']},
            
            # Stage 8: Allocation: Preparation: AWO - Notify STA, TAO Group, Notify STA Group
            8.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['STA', 'TAO']},
            
            # Stage 8.1: Preparation: AWO - Notify Finance Group
            8.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Finance']},
            
            # Stage 8.2: Peer Review-Draft AWO - Notify Technical Services Group
            8.2: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services']},
            
            # Stage 8.3: Peer Committee-Draft AWO - Notify TAO Group
            8.3: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO']},
            
            # Stage 8.4: Review: Approval Submission - Notify TGL:TA, STA and TAO Group, Notify STA Group
            8.4: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['STA', 'TAO']},
            
            # Stage 9: Approval: Assessment work offer - Notify EMTS, TAO, STA and TGL:TA Group, EMTS Group
            9.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO', 'STA', 'TGL: TA']},
            
            # Stage 10: Dispatched Assessment work offer - Notify TAO Group, TGL: TA, STA
            10.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TGL: TA', 'STA']},
            
            # Stage 11: Client Response - Notify TAO Group, TGL: TA, STA, Notify Client & TAO Group
            11.0: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': ['TGL: TA', 'STA']},
            
            # Stage 11.1: Review: Client Response - Notify Client & TAO Group
            11.1: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 12: Evaluation Fee Request - Notify TAO Group
            12.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': []},
            
            # Stage 13: Evaluation Invoice Generation - Notify Finance Group and TAO Finance Group
            13.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO']},
            
            # Stage 13.1: Confirmation of Invoice - TAO (goes to client)
            13.1: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 13.2: Evaluation fee-Proof of Payment - Notify TAO Group and Finance Group AND CLIENT
            13.2: {'notify_groups': True, 'notify_client': should_notify_client, 'additional_groups': []},
            
            # Stage 13.3: Payment Confirmation - Notify TAO Group, TGL: TA, STA
            13.3: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO', 'TGL: TA', 'STA']},
            
            # Stage 14: Project Allocation - Notify TGL: TA, STA, TA
            14.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['STA', 'TA']},
            
            # Stage 14.1: Project Assessment - Notify STA & Project Leader Group and TGL: TA Group
            14.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TGL: TA']},
            
            # Stage 14.11: Draft Project Management Plan - Notify STA Group & Project Leader
            14.11: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['STA']},
            
            # Stage 14.12: Approved Project Management Plan
            14.12: {'notify_groups': True, 'notify_client': False, 'additional_groups': []},
            
            # Stage 14.13: Review Project Submission - Notify PL
            14.13: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['PL']},
            
            # Stage 15: Peer Review-Draft Certificate - Notify Technical Services Group
            15.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services']},
            
            # Stage 15.1: Peer review Committee -Draft Certificate - Notify Technical Services Group
            15.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services']},
            
            # Stage 15.2: Final Review: Assessment Management - Notify TGL: TA Group, STA, Project Leader, Notify TGL: TA Group
            15.2: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['STA', 'PL']},
            
            # Stage 15.3: Review: EMTS - Notify TGL: TA Group
            15.3: {'notify_groups': True, 'notify_client': False, 'additional_groups': []},
            
            # Stage 16: TECO Submission - Notify TECO Group
            16.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services', 'OCEO', 'SOB']},
            
            # Stage 16.1: Review: TECO Approval - Notify TECO Group
            16.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': []},
            
            # Stage 17: TECO Approval - SOB Agreement South Africa, TECO Group
            17.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': []},
            
            # Stage 17.1: Board Ratification - Notify Board Group, Technical Services
            17.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services']},
            
            # Stage 17.2: Review: Board Ratification - Notify Board Group, Technical Services
            17.2: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Technical Services']},
            
            # Stage 18: Publish Certificate - Notify PL Group, STA, and TAO
            18.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['STA', 'TAO']},
            
            # Stage 18.1: Website Upload Request & Gazette - Notify TAO, Notify TAO Group
            18.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': []},
            
            # Stage 18.2: Approval: Publishing Requests - Notify EMTS, TAO and PL, Notify EMTS
            18.2: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['TAO', 'PL']},
            
            # Stage 19: Certificate Signing - Notify Board Chairperson Group, Project Leader, STA, and TAO
            19.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['PL', 'STA', 'TAO']},
            
            # Stage 19.1: Certificate Signing status - Notify Board Chairperson Group
            19.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': []},
            
            # Stage 19.2: Dispatch signed certificate - Notify TAO Group, Project Leader, STA, and TGL:TA
            19.2: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['PL', 'STA', 'TGL: TA']},
            
            # Stage 20: Project Closure - Notify PL Group, Finance, STA, TGL:TA and TAO
            20.0: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Finance', 'STA', 'TGL: TA', 'TAO']},
            
            # Stage 20.1: Project Closeout report - Notify PL Group, Finance, STA, TGL:TA and TAO
            20.1: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['Finance', 'STA', 'TGL: TA', 'TAO']},
            
            # Stage 20.2: Approve Project Closure - Notify PL, STA, TGL:TA and TAO, Notify TGL:TA
            20.2: {'notify_groups': True, 'notify_client': False, 'additional_groups': ['PL', 'STA', 'TAO']},
        }
        
        return notification_rules.get(stage_number, {'notify_groups': True, 'notify_client': False, 'additional_groups': []})

    def get_groups_by_names(self, group_names):
        """Get group objects by their names"""
        if not group_names:
            return []
        
        groups = []
        for name in group_names:
            group = Group.query.filter_by(name=name).first()
            if group:
                groups.append(group)
            else:
                logger.warning(f'Group not found: {name}')
        return groups

    def notify_groups_approved(self, application, action, stage, groups, reason=None):
        """Notify groups when application is approved/moved forward"""
        for group in groups:
            try:
                # Get all active users in the group
                users = User.query.join(
                    UserGroupAssignment, User.id == UserGroupAssignment.user_id
                ).filter(
                    UserGroupAssignment.group_id == group.id,
                    User.is_active == True
                ).all()

                logger.info(f'Found {len(users)} active users in group {group.name}')

                if not users:
                    logger.warning(f'No active users found in group {group.name}')
                    continue

                emails = [user.email for user in users]
                logger.info(f'Sending approval notification to emails: {emails}')

                subject = f'Application {action.title()} - {application.application_number}'

                body = f"""
                <html>
                <body>
                    <h2>Application Status Update</h2>

                    <p>An application has been moved to your stage for processing.</p>

                    <h3>Application Details:</h3>
                    <ul>
                        <li><strong>Application Number:</strong> {application.application_number}</li>
                        <li><strong>Applicant:</strong> {application.applicant_name}</li>
                        <li><strong>Company:</strong> {application.company.name}</li>
                        <li><strong>Certificate Type:</strong> {application.certificate_type}</li>
                        <li><strong>Current Stage:</strong> {stage.name}</li>
                    </ul>

                    {f'<p><strong>Reason/Notes:</strong> {reason}</p>' if reason else ''}

                    <p><strong>Action Required:</strong> Please log in to the system to process this application.</p>
                </body>
                </html>
                """

                email_sent = self.send_email(emails, subject, body)
                if email_sent:
                    logger.info(f'Successfully sent approval notification to group {group.name}')
                else:
                    logger.error(f'Failed to send approval notification to group {group.name}')

            except Exception as e:
                logger.error(f'Error notifying group {group.name}: {e}')

    def notify_groups_review(self, application, action, stage, groups, reason=None):
        """Notify groups when application needs review"""
        for group in groups:
            try:
                # Get all active users in the group
                users = User.query.join(
                    UserGroupAssignment, User.id == UserGroupAssignment.user_id
                ).filter(
                    UserGroupAssignment.group_id == group.id,
                    User.is_active == True
                ).all()

                logger.info(f'Found {len(users)} active users in group {group.name} for review notification')

                if not users:
                    logger.warning(f'No active users found in group {group.name} for review')
                    continue

                emails = [user.email for user in users]
                logger.info(f'Sending review notification to emails: {emails}')

                subject = f'Application Review Required - {application.application_number}'

                body = f"""
                <html>
                <body>
                    <h2>Application Review Required</h2>

                    <p>An application requires review and has been returned to your stage.</p>

                    <h3>Application Details:</h3>
                    <ul>
                        <li><strong>Application Number:</strong> {application.application_number}</li>
                        <li><strong>Applicant:</strong> {application.applicant_name}</li>
                        <li><strong>Company:</strong> {application.company.name}</li>
                        <li><strong>Certificate Type:</strong> {application.certificate_type}</li>
                        <li><strong>Review Stage:</strong> {stage.name}</li>
                        <li><strong>Action:</strong> {action.title()}</li>
                    </ul>

                    {f'<p><strong>Review Reason:</strong> {reason}</p>' if reason else ''}

                    <p><strong>Action Required:</strong> Please log in to the system to address the review comments.</p>
                </body>
                </html>
                """

                email_sent = self.send_email(emails, subject, body)
                if email_sent:
                    logger.info(f'Successfully sent review notification to group {group.name}')
                else:
                    logger.error(f'Failed to send review notification to group {group.name}')

            except Exception as e:
                logger.error(f'Error notifying group {group.name} for review: {e}')

    def notify_client_approved(self, application, action, stage, reason=None):
        """Notify client when application is approved/progressed"""
        try:
            logger.info(f'Sending client approval notification for {application.application_number}')

            subject = f'Application Update - {application.application_number}'

            # Check if the new stage requires client upload
            workflow_service = WorkflowService()
            requires_upload = workflow_service.stage_requires_client_upload(stage.stage_number)
            logger.info(f'Stage {stage.stage_number} requires upload: {requires_upload}')

            upload_section = ""
            if requires_upload:
                upload_token = application.generate_client_upload_token()

                try:
                    # Try to generate URL with Flask context
                    with app.app_context():
                        upload_url = url_for('client_upload_form',
                                           application_number=application.application_number,
                                           token=upload_token,
                                           _external=True)
                except:
                    # Fallback if url_for fails outside request context
                    base_url = "https://certification-management-app-updated.onrender.com"
                    upload_url = f"{base_url}/client/upload/{application.application_number}/{upload_token}"

                logger.info(f'Generated upload URL: {upload_url}')

                # Determine upload message based on stage
                if stage.stage_number == 4.2:
                    upload_message = "upload proof of payment for the admin fee"
                elif stage.stage_number == 13.2:
                    upload_message = "upload proof of payment for the evaluation fee"
                else:
                    upload_message = "upload the required documents"

                upload_section = f"""
                <div style="background: #fff3cd; padding: 20px; border-left: 5px solid #ffc107; margin: 25px 0; border-radius: 5px;">
                    <h3 style="color: #856404; margin-bottom: 15px;">🚨 ACTION REQUIRED: Document Upload</h3>
                    <p style="color: #856404; font-weight: bold; margin-bottom: 15px;">
                        To continue processing your application, you need to {upload_message}.
                    </p>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="{upload_url}"
                           style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none;
                                  border-radius: 8px; font-weight: bold; font-size: 16px; display: inline-block;">
                            📄 UPLOAD DOCUMENTS NOW
                        </a>
                    </div>
                    <p style="color: #856404; font-size: 14px;">
                        This secure link is specific to your application. Please upload your documents promptly to avoid delays.
                    </p>
                </div>
                """

            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #28a745; border-bottom: 2px solid #28a745; padding-bottom: 10px;">
                        Application Status Update
                    </h2>

                    <p style="font-size: 16px;">Dear <strong>{application.applicant_name}</strong>,</p>

                    <p style="font-size: 16px;">
                        We want to inform you that your application has been processed and moved to the next stage.
                    </p>

                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="color: #495057; margin-top: 0;">📋 Application Details</h3>
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px 0; font-weight: bold; width: 40%;">Application Number:</td>
                                <td style="padding: 8px 0;">{application.application_number}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; font-weight: bold;">Certificate Type:</td>
                                <td style="padding: 8px 0;">{application.certificate_type}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; font-weight: bold;">Current Stage:</td>
                                <td style="padding: 8px 0;">{stage.name}</td>
                            </tr>
                        </table>
                    </div>

                    {f'<div style="background: #e8f5e8; padding: 15px; border-left: 4px solid #28a745; margin: 20px 0;"><h4 style="color: #155724; margin-top: 0;">📝 Notes:</h4><p style="color: #155724;">{reason}</p></div>' if reason else ''}

                    {upload_section}

                    <div style="background: #e7f3ff; padding: 15px; border-left: 4px solid #0066cc; margin: 20px 0;">
                        <p style="color: #003d7a; margin-bottom: 0;">
                            You can check your application status at any time using your application number:
                            <strong>{application.application_number}</strong>
                        </p>
                    </div>

                    <p style="margin-top: 30px;">Thank you for your patience and cooperation.</p>
                </div>
            </body>
            </html>
            """

            email_sent = self.send_email([application.applicant_email], subject, body)
            if email_sent:
                logger.info(f'Successfully sent client approval notification to {application.applicant_email}')
            else:
                logger.error(f'Failed to send client approval notification to {application.applicant_email}')

        except Exception as e:
            logger.error(f'Error in notify_client_approved: {e}')

    def notify_client_review(self, application, action, stage, reason=None):
        """Notify client when application needs review/additional info"""
        subject = f'Action Required - {application.application_number}'

        # Check if this stage requires or allows client uploads
        workflow_service = WorkflowService()
        requires_upload = workflow_service.stage_requires_client_upload(stage.stage_number)
        allows_upload = workflow_service.stage_allows_client_upload(stage.stage_number)

        upload_section = ""
        if requires_upload or allows_upload:
            upload_token = application.generate_client_upload_token()

            # Use Flask's url_for with _external=True to generate absolute URLs
            try:
                with app.app_context():
                    upload_url = url_for('client_upload_form',
                                       application_number=application.application_number,
                                       token=upload_token,
                                       _external=True)
            except:
                # Fallback if url_for fails outside request context
                base_url = "https://certification-management-app-updated.onrender.com"
                upload_url = f"{base_url}/client/upload/{application.application_number}/{upload_token}"

            if requires_upload:
                upload_section = f"""
                <div style="background: #fef3cd; padding: 20px; border-left: 5px solid #ffc107; margin: 25px 0; border-radius: 5px;">
                    <h3 style="color: #856404; margin-bottom: 15px;">🚨 URGENT: Document Upload Required</h3>
                    <p style="color: #856404; font-weight: bold; margin-bottom: 15px;">
                        Your application cannot proceed without uploading the required documents.
                    </p>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="{upload_url}"
                           style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none;
                                  border-radius: 8px; font-weight: bold; font-size: 16px; display: inline-block;">
                            📄 UPLOAD DOCUMENTS NOW
                        </a>
                    </div>
                    <p style="color: #856404; font-size: 14px; margin-top: 15px;">
                        This link is secure and specific to your application. Please upload your documents as soon as possible.
                    </p>
                </div>
                """
            else:
                upload_section = f"""
                <div style="background: #e8f5e8; padding: 20px; border-left: 5px solid #28a745; margin: 25px 0; border-radius: 5px;">
                    <h3 style="color: #155724; margin-bottom: 15px;">📄 Upload Additional Documents (Optional)</h3>
                    <p style="color: #155724; margin-bottom: 15px;">
                        If you have additional documents that may help resolve this review, you can upload them using the secure link below:
                    </p>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="{upload_url}"
                           style="background: #28a745; color: white; padding: 12px 25px; text-decoration: none;
                                  border-radius: 6px; font-weight: bold; display: inline-block;">
                            📤 Upload Additional Documents
                        </a>
                    </div>
                </div>
                """

        # Special messages for payment stages
        payment_message = ""
        if stage.stage_number in [4.2, 13.2]:
            payment_message = """
            <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
                <h4 style="color: #856404;">💳 Payment Information</h4>
                <p style="color: #856404;">Please upload clear, legible proof of payment including:</p>
                <ul style="color: #856404;">
                    <li>Bank statement showing the transaction</li>
                    <li>Electronic transfer receipt</li>
                    <li>Payment confirmation from your bank</li>
                </ul>
            </div>
            """

        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #dc3545; border-bottom: 2px solid #dc3545; padding-bottom: 10px;">
                    🔔 Action Required for Your Application
                </h2>

                <p style="font-size: 16px;">Dear <strong>{application.applicant_name}</strong>,</p>

                <p style="font-size: 16px;">
                    Your application requires additional attention or information to proceed to the next stage.
                </p>

                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #495057; margin-top: 0;">📋 Application Details</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold; width: 40%;">Application Number:</td>
                            <td style="padding: 8px 0;">{application.application_number}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold;">Certificate Type:</td>
                            <td style="padding: 8px 0;">{application.certificate_type}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; font-weight: bold;">Current Stage:</td>
                            <td style="padding: 8px 0;">{stage.name}</td>
                        </tr>
                    </table>
                </div>

                {f'<div style="background: #ffe6e6; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;"><h4 style="color: #721c24; margin-top: 0;">📝 Required Action:</h4><p style="color: #721c24; font-weight: bold;">{reason}</p></div>' if reason else ''}

                {payment_message}

                {upload_section}

                <div style="background: #e7f3ff; padding: 15px; border-left: 4px solid #0066cc; margin: 20px 0;">
                    <h4 style="color: #003d7a; margin-top: 0;">📞 Need Help?</h4>
                    <p style="color: #003d7a; margin-bottom: 0;">
                        If you have any questions about your application or need assistance,
                        please contact our support team with your application number.
                    </p>
                </div>

                <p style="margin-top: 30px;">Thank you for your prompt attention to this matter.</p>
            </div>
        </body>
        </html>
        """

        self.send_email([application.applicant_email], subject, body)

    def send_application_confirmation(self, application, uploaded_files):
        """Send application confirmation email to client"""
        subject = f'Application Received - {application.application_number}'

        files_list = '<ul>' + ''.join([f'<li>{file}</li>' for file in uploaded_files]) + '</ul>' if uploaded_files else '<p>No documents uploaded</p>'

        body = f"""
        <html>
        <body>
            <h2>Application Confirmation</h2>

            <p>Dear {application.applicant_name},</p>

            <p>Thank you for submitting your application. We have received your application and it is now being processed.</p>

            <h3>Application Details:</h3>
            <ul>
                <li><strong>Application Number:</strong> {application.application_number}</li>
                <li><strong>Certificate Type:</strong> {application.certificate_type}</li>
                <li><strong>Company:</strong> {application.company.name}</li>
                <li><strong>Submitted:</strong> {application.submitted_at.strftime('%B %d, %Y at %H:%M')}</li>
            </ul>

            <h3>Documents Received:</h3>
            {files_list}

            <p><strong>Next Steps:</strong> Your application will be reviewed by our technical team. You will receive updates via email as your application progresses through our workflow.</p>

            <p>You can check your application status at any time using your application number: <strong>{application.application_number}</strong></p>

            <p>Thank you for choosing our services.</p>
        </body>
        </html>
        """

        return self.send_email([application.applicant_email], subject, body)

    def send_new_application_notification(self, application, group):
        """Send new application notification to review team"""
        try:
            users = User.query.join(
            UserGroupAssignment, User.id == UserGroupAssignment.user_id
        ).filter(
            UserGroupAssignment.group_id == group.id,
            User.is_active == True
        ).all()
            if not users:
                return False
            emails = [user.email for user in users]
            subject = f'New Application Submitted - {application.application_number}'


            body = f"""
            <html>
            <body>
                <h2>New Application Submitted</h2>

                <p>A new application has been submitted and requires review.</p>

                <h3>Application Details:</h3>
                <ul>
                    <li><strong>Application Number:</strong> {application.application_number}</li>
                    <li><strong>Applicant:</strong> {application.applicant_name}</li>
                    <li><strong>Company:</strong> {application.company.name}</li>
                    <li><strong>Email:</strong> {application.applicant_email}</li>
                    <li><strong>Phone:</strong> {application.applicant_phone}</li>
                    <li><strong>Certificate Type:</strong> {application.certificate_type}</li>
                    <li><strong>Submitted:</strong> {application.submitted_at.strftime('%B %d, %Y at %H:%M')}</li>
                </ul>

                <p><strong>Action Required:</strong> Please log in to the system to review this application.</p>
            </body>
            </html>
            """

            return self.send_email(emails, subject, body)

        except Exception as e:
            logger.error(f'Failed to send new application notification: {e}')
            return False

# =============================================================================
# SERVICES
# =============================================================================

class FileService:
    def __init__(self):
        self.upload_folder = app.config['UPLOAD_FOLDER']
        self.allowed_extensions = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif', 'txt'}
        self.max_file_size = app.config['MAX_CONTENT_LENGTH']

    def allowed_file(self, filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.allowed_extensions

    def save_uploaded_file(self, file, application, document_type, description, uploaded_by_external=False, uploaded_by_user_id=None):
        """Save uploaded file with complete validation"""
        try:
            # Validate file
            if not file or file.filename == '':
                return {'success': False, 'message': 'No file selected.'}

            if not self.allowed_file(file.filename):
                return {'success': False, 'message': 'File type not allowed.'}

            # Check file size
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to beginning

            if file_size > self.max_file_size:
                return {'success': False, 'message': 'File size too large.'}

            # Generate secure filename
            original_filename = file.filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            secure_name = secure_filename(original_filename)
            filename = f"{application.application_number}_{timestamp}_{secure_name}"

            # Create directory if not exists
            doc_folder = os.path.join(self.upload_folder, 'documents')
            os.makedirs(doc_folder, exist_ok=True)

            # Save file
            file_path = os.path.join(doc_folder, filename)
            file.save(file_path)

            # Create database record
            document = Document(
                application_id=application.id,
                filename=filename,
                original_filename=original_filename,
                file_path=file_path,
                file_size=file_size,
                file_type=file.content_type,
                document_type=document_type,
                description=description,
                uploaded_by_external=uploaded_by_external,
                uploaded_by_user_id=uploaded_by_user_id
            )

            db.session.add(document)
            db.session.commit()

            logger.info(f'File uploaded successfully: {filename}')

            return {
                'success': True,
                'message': 'File uploaded successfully.',
                'filename': filename,
                'document': document
            }

        except Exception as e:
            logger.error(f'File upload error: {e}')
            return {'success': False, 'message': f'Upload failed: {str(e)}'}

class WorkflowService:
    def __init__(self):
        self.email_service = EmailService()

    def get_available_actions(self, stage):
        """Get available actions for a stage based on your detailed workflow specification"""
        stage_num = stage.stage_number

        # Define actions based on your detailed workflow specification
        stage_actions = {
            # Stage 1: New Application by client
            1.0: [('new_application', 'New Application')],

            # Stage 2: Verification of Application Completeness
            2.0: [('application_complete', 'Application Complete'), ('application_not_complete', 'Application Not Complete')],

            # Stage 3: Admin Fee Request
            3.0: [('accepted', 'Accepted'), ('rejected', 'Rejected'), ('request_info', 'Request Info')],

            # Stage 4: Admin Invoice Generation
            4.0: [('generated', 'Generated'), ('rejected', 'Rejected')],

            # Stage 4.1: Confirmation of Invoice (when confirmed, goes to client)
            4.1: [('confirmed', 'Confirmed')],

            # Stage 4.2: Admin fee-Proof of Payment (Client uploads) - CLIENT UPLOAD STAGE
            4.2: [],  # Empty - only client uploads can progress this stage

            # Stage 4.3: Payment Confirmation
            4.3: [('paid', 'PAID'), ('not_paid', 'NOT PAID')],

            # Stage 5: Allocation: Criteria Review (TGL assigns an STA)
            5.0: [('allocated', 'Allocated'), ('not_allocated', 'Not Allocated'), ('request_info', 'Request Info')],

            # Stage 5.1: Review: Application Criteria review
            5.1: [('drafted', 'Drafted'), ('deviate', 'Deviate to R&D')],

            # Stage 6: Peer Review-Criteria Review
            6.0: [('requested', 'Requested')],

            # Stage 6.1: Peer review Committee -Criteria Report
            6.1: [('reviewed', 'Reviewed')],

            # Stage 7: Approval - Application Criteria Report
            7.0: [('approved', 'Approved'), ('rejected', 'Rejected')],

            # Stage 8: Allocation: Preparation: Assessment Work Offer (AWO)
            8.0: [('allocation', 'Allocation')],

            # Stage 8.1: Preparation: Assessment Work Offer (AWO)
            8.1: [('drafted', 'Drafted')],

            # Stage 8.2: Peer Review-Draft Assessment Work Offer (AWO)
            8.2: [('requested', 'Requested')],

            # Stage 8.3: Peer Committee-Draft Assessment Work Offer
            8.3: [('reviewed', 'Reviewed')],

            # Stage 8.4: Review: Approval Submission
            8.4: [('reviewed', 'Reviewed'), ('rejected', 'Rejected')],

            # Stage 9: Approval: Assessment work offer
            9.0: [('approved', 'Approved'), ('rejected', 'Rejected')],

            # Stage 10: Dispatched Assessment work offer
            10.0: [('dispatched', 'Dispatched')],

            # Stage 11: Client Response
            11.0: [('accepted', 'Accepted'), ('rejected', 'Rejected')],

            # Stage 11.1: Review: Client Response
            11.1: [('reviewed', 'Reviewed')],

            # Stage 12: Evaluation Fee Request
            12.0: [('requested', 'Requested')],

            # Stage 13: Evaluation Invoice Generation
            13.0: [('generated', 'Generated'), ('rejected', 'Rejected')],

            # Stage 13.1: Confirmation of Invoice (when confirmed, goes to client)
            13.1: [('confirmed', 'Confirmed')],

            # Stage 13.2: Evaluation fee-Proof of Payment - CLIENT UPLOAD STAGE
            13.2: [],  # Empty - only client uploads can progress this stage

            # Stage 13.3: Payment Confirmation (uploaded POP)
            13.3: [('paid', 'PAID'), ('not_paid', 'NOT PAID')],

            # Stage 14: Project Allocation
            14.0: [('allocated', 'Allocated')],

            # Stage 14.1: Project Assessment
            14.1: [('confirm', 'Confirm'), ('rejected', 'Rejected')],

            # Stage 14.1.1: Draft Project Management Plan
            14.11: [('draft', 'Draft')],

            # Stage 14.1.2: Approved Project Management Plan (PCM)
            14.12: [('upload', 'Upload')],

            # Stage 14.1.3: Review Project Submission
            14.13: [('approved', 'Approved'), ('rejected', 'Rejected')],

            # Stage 15: Peer Review-Draft Certificate
            15.0: [('requested', 'Requested')],

            # Stage 15.1: Peer review Committee -Draft Certificate
            15.1: [('reviewed', 'Reviewed')],

            # Stage 15.2: Final Review: Assessment Management (Technical Exco)
            15.2: [('reviewed', 'Reviewed'), ('rejected', 'Rejected')],

            # Stage 15.3: Review: EMTS
            15.3: [('reviewed', 'Reviewed'), ('rejected', 'Rejected')],

            # Stage 16: TECO Submission
            16.0: [('submitted', 'Submitted')],

            # Stage 16.1: Review: TECO Approval
            16.1: [('reviewed', 'Reviewed')],

            # Stage 17: TECO Approval
            17.0: [('approved', 'Approved'), ('conditionally_approved', 'Conditionally Approved'), ('rejected', 'Rejected')],

            # Stage 17.1: Board Ratification
            17.1: [('submitted', 'Submitted')],

            # Stage 17.2: Review: Board Ratification
            17.2: [('ratified', 'Ratified'), ('not_ratified', 'Not Ratified')],

            # Stage 18: Publish Certificate (Triggered by 17.1 positive outcome)
            18.0: [('submitted', 'Submitted')],

            # Stage 18.1a: Website Upload Request & Gazette
            18.1: [('submitted', 'Submitted'), ('rejected', 'Rejected')],

            # Stage 18.2a: Approval: Publishing Requests
            18.2: [('approved', 'Approved'), ('rejected', 'Rejected')],

            # Stage 19: Certificate Signing (Triggered by 17.1 positive outcome)
            19.0: [('submitted', 'Submitted')],

            # Stage 19.1b: Certificate Signing status
            19.1: [('signed', 'Signed'), ('not_signed', 'Not Signed')],

            # Stage 19.2b: Dispatch signed certificate
            19.2: [('couriered', 'Couriered'), ('collected', 'Collected'), ('digital_copy', 'Digital Copy')],

            # Stage 20: Project Closure
            20.0: [('submitted', 'Submitted')],

            # Stage 20.1: Project Closeout report
            20.1: [('approved', 'Approved'), ('conditionally_approved', 'Conditionally Approved'), ('rejected', 'Rejected')],

            # Stage 20.2: Approve Project Closure
            20.2: [('approved', 'Approved'), ('rejected', 'Rejected')],

            # Final stage - END
            21.0: []  # No actions - final stage
        }

        return stage_actions.get(stage_num, [])

    def has_sub_stages(self, stage_number):
        """Check if a stage has sub-stages"""
        # Stages that have sub-stages based on CSV
        stages_with_substages = {
            4.0: [4.1, 4.2],
            5.0: [5.1],
            6.0: [6.1],
            8.0: [8.1, 8.2, 8.3, 8.4],
            10.0: [10.1],
            12.0: [12.1, 12.2],
            13.0: [13.1],
            14.0: [14.2, 14.3, 14.4],  # Note: 14.0 doesn't exist but sub-stages do
            15.0: [15.1, 15.2, 15.3],
            16.0: [16.1],
            17.0: [17.1, 17.2],
            18.0: [18.1, 18.2],
            19.0: [19.1, 19.2],
            20.0: [20.1, 20.2]
        }
        return stage_number in stages_with_substages

    def has_multiple_approval_options(self, stage_number):
        """Check if a stage has multiple approval options (Approval2, Approval3)"""
        # Stages with multiple approval options based on CSV
        multiple_approval_stages = {
            2.0, 3.0, 4.0, 5.0, 7.0, 8.3, 8.4, 10.0, 10.1, 12.0, 12.2, 13.1,
            14.3, 15.2, 15.3, 17.0, 17.2, 18.2, 19.1, 20.1, 20.2
        }
        return stage_number in multiple_approval_stages

    def stage_requires_client_upload(self, stage_number):
        """Check if a stage requires client document upload"""
        client_upload_stages = {
            4.2,  # Admin fee-Proof of Payment upload (Client uploads)
            13.2, # Evaluation fee-Proof of Payment upload (Client uploads)
        }
        return stage_number in client_upload_stages

    def stage_allows_client_upload(self, stage_number):
        """Check if a stage allows optional client document upload (for review responses)"""
        # Stages where clients might need to upload additional documents when rejected
        client_optional_upload_stages = {
            2.0, 3.0, 5.0, 6.0, 7.0, 8.3, 8.4, 10.0, 10.1, 15.2, 15.3, 17.1, 17.2, 18.2, 19.1, 20.2
        }
        return stage_number in client_optional_upload_stages

    def get_first_sub_stage(self, main_stage_number):
        """Get the first sub-stage for a main stage"""
        substage_mapping = {
            4.0: 4.1,
            5.0: 5.1,
            6.0: 6.1,
            8.0: 8.1,
            10.0: 10.1,
            12.0: 12.1,
            13.0: 13.1,
            14.0: 14.2,  # Special case
            15.0: 15.1,
            16.0: 16.1,
            17.0: 17.1,
            18.0: 18.1,
            19.0: 19.1,
            20.0: 20.1
        }
        return substage_mapping.get(main_stage_number)

    def get_next_stage_number(self, current_stage_number):
        """Get the next sequential stage number"""
        # Define the complete stage sequence
        stage_sequence = [
            1.0, 2.0, 3.0, 4.0, 4.1, 4.2, 5.0, 5.1, 6.0, 6.1, 7.0,
            8.0, 8.1, 8.2, 8.3, 8.4, 9.0, 10.0, 10.1, 11.0,
            12.0, 12.1, 12.2, 13.0, 13.1, 14.2, 14.3, 14.4,
            15.0, 15.1, 15.2, 15.3, 16.0, 16.1, 17.0, 17.1, 17.2,
            18.0, 18.1, 18.2, 19.0, 19.1, 19.2, 20.0, 20.1, 20.2, 23.0
        ]

        try:
            current_index = stage_sequence.index(current_stage_number)
            if current_index < len(stage_sequence) - 1:
                return stage_sequence[current_index + 1]
        except ValueError:
            pass

        return None

    def get_previous_stage_number(self, current_stage_number):
        """Get the previous stage number"""
        stage_sequence = [
            1.0, 2.0, 3.0, 4.0, 4.1, 4.2, 5.0, 5.1, 6.0, 6.1, 7.0,
            8.0, 8.1, 8.2, 8.3, 8.4, 9.0, 10.0, 10.1, 11.0,
            12.0, 12.1, 12.2, 13.0, 13.1, 14.2, 14.3, 14.4,
            15.0, 15.1, 15.2, 15.3, 16.0, 16.1, 17.0, 17.1, 17.2,
            18.0, 18.1, 18.2, 19.0, 19.1, 19.2, 20.0, 20.1, 20.2, 23.0
        ]

        try:
            current_index = stage_sequence.index(current_stage_number)
            if current_index > 0:
                return stage_sequence[current_index - 1]
        except ValueError:
            pass

        return None

    def get_next_stage(self, current_stage, action):
        """Implement proper workflow logic based on your detailed workflow specification"""
        current_stage_num = current_stage.stage_number

        # Stage transition rules based on your detailed workflow specification

        # Stage 1: New Application by client - Go to 2
        if current_stage_num == 1.0:
            return Stage.query.filter_by(stage_number=2.0).first()

        # Stage 2: Verification of Application Completeness
        elif current_stage_num == 2.0:
            if action == 'application_complete':
                return Stage.query.filter_by(stage_number=3.0).first()  # Go to 3
            elif action == 'application_not_complete':
                return current_stage  # Stay on 2

        # Stage 3: Admin Fee Request
        elif current_stage_num == 3.0:
            if action == 'accepted':
                return Stage.query.filter_by(stage_number=4.0).first()  # Go to 4
            elif action in ['rejected', 'request_info']:
                return current_stage  # Stay on 3

        # Stage 4: Admin Invoice Generation
        elif current_stage_num == 4.0:
            if action == 'generated':
                return Stage.query.filter_by(stage_number=4.1).first()  # Go to 4.1
            elif action == 'rejected':
                return Stage.query.filter_by(stage_number=3.0).first()  # Go to 3

        # Stage 4.1: Confirmation of Invoice (when confirmed, goes to client)
        elif current_stage_num == 4.1:
            if action == 'confirmed':
                return Stage.query.filter_by(stage_number=4.2).first()  # Go to 4.2

        # Stage 4.2: Admin fee-Proof of Payment (Client uploads) - CLIENT UPLOAD STAGE
        elif current_stage_num == 4.2:
            if action == 'client_upload_received':
                return Stage.query.filter_by(stage_number=4.3).first()  # Go to 4.3
            else:
                return current_stage  # Stay here until client uploads

        # Stage 4.3: Payment Confirmation
        elif current_stage_num == 4.3:
            if action == 'paid':
                return Stage.query.filter_by(stage_number=5.0).first()  # Go to 5
            elif action == 'not_paid':
                return Stage.query.filter_by(stage_number=4.2).first()  # Go to 4.2

        # Stage 5: Allocation: Criteria Review (TGL assigns an STA)
        elif current_stage_num == 5.0:
            if action == 'allocated':
                return Stage.query.filter_by(stage_number=5.1).first()  # Go to 5.1
            elif action == 'not_allocated':
                return current_stage  # Stay on 5.1 (as per spec)
            elif action == 'request_info':
                return Stage.query.filter_by(stage_number=3.0).first()  # Stay on 3

        # Stage 5.1: Review: Application Criteria review
        elif current_stage_num == 5.1:
            if action == 'drafted':
                return Stage.query.filter_by(stage_number=6.0).first()  # Go to 6
            elif action == 'deviate':
                # Deviate to R&D - for now, stay on current stage
                return current_stage

        # Stage 6: Peer Review-Criteria Review
        elif current_stage_num == 6.0:
            if action == 'requested':
                return Stage.query.filter_by(stage_number=6.1).first()  # Go to 6.1

        # Stage 6.1: Peer review Committee -Criteria Report
        elif current_stage_num == 6.1:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=7.0).first()  # Go to 7

        # Stage 7: Approval - Application Criteria Report
        elif current_stage_num == 7.0:
            if action == 'approved':
                return Stage.query.filter_by(stage_number=8.0).first()  # Go to 8
            elif action == 'rejected':
                return current_stage  # Stay on 7

        # Stage 8: Allocation: Preparation: Assessment Work Offer (AWO)
        elif current_stage_num == 8.0:
            if action == 'allocation':
                return Stage.query.filter_by(stage_number=8.1).first()  # Go to 8.1

        # Stage 8.1: Preparation: Assessment Work Offer (AWO)
        elif current_stage_num == 8.1:
            if action == 'drafted':
                return Stage.query.filter_by(stage_number=8.2).first()  # Go to 8.2

        # Stage 8.2: Peer Review-Draft Assessment Work Offer (AWO)
        elif current_stage_num == 8.2:
            if action == 'requested':
                return Stage.query.filter_by(stage_number=8.3).first()  # Go to 8.3

        # Stage 8.3: Peer Committee-Draft Assessment Work Offer
        elif current_stage_num == 8.3:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=8.4).first()  # Go to 8.4

        # Stage 8.4: Review: Approval Submission
        elif current_stage_num == 8.4:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=9.0).first()  # Go to 9
            elif action == 'rejected':
                return Stage.query.filter_by(stage_number=8.3).first()  # Stay on 8.3

        # Stage 9: Approval: Assessment work offer
        elif current_stage_num == 9.0:
            if action == 'approved':
                return Stage.query.filter_by(stage_number=10.0).first()  # Go to 10
            elif action == 'rejected':
                return Stage.query.filter_by(stage_number=8.4).first()  # Stay on 8.4

        # Stage 10: Dispatched Assessment work offer
        elif current_stage_num == 10.0:
            if action == 'dispatched':
                return Stage.query.filter_by(stage_number=11.0).first()  # Go to 11

        # Stage 11: Client Response
        elif current_stage_num == 11.0:
            if action == 'accepted':
                return Stage.query.filter_by(stage_number=11.1).first()  # Go to 11.1
            elif action == 'rejected':
                return Stage.query.filter_by(stage_number=10.0).first()  # Stay on 10

        # Stage 11.1: Review: Client Response
        elif current_stage_num == 11.1:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=12.0).first()  # Go to 12

        # Stage 12: Evaluation Fee Request
        elif current_stage_num == 12.0:
            if action == 'requested':
                return Stage.query.filter_by(stage_number=13.0).first()  # Go to 13

        # Stage 13: Evaluation Invoice Generation
        elif current_stage_num == 13.0:
            if action == 'generated':
                return Stage.query.filter_by(stage_number=13.1).first()  # Go to 13.1
            elif action == 'rejected':
                return current_stage  # Stay on 13

        # Stage 13.1: Confirmation of Invoice (when confirmed, goes to client)
        elif current_stage_num == 13.1:
            if action == 'confirmed':
                return Stage.query.filter_by(stage_number=13.2).first()  # Go to 13.2

        # Stage 13.2: Evaluation fee-Proof of Payment - CLIENT UPLOAD STAGE
        elif current_stage_num == 13.2:
            if action == 'client_upload_received':
                return Stage.query.filter_by(stage_number=13.3).first()  # Go to 13.3
            else:
                return current_stage  # Stay here until client uploads

        # Stage 13.3: Payment Confirmation (uploaded POP)
        elif current_stage_num == 13.3:
            if action == 'paid':
                return Stage.query.filter_by(stage_number=14.0).first()  # Go to 14
            elif action == 'not_paid':
                return Stage.query.filter_by(stage_number=13.2).first()  # Stay on 13.2

        # Stage 14: Project Allocation
        elif current_stage_num == 14.0:
            if action == 'allocated':
                # Allocation triggers both 14.1 and 14.1.1 - go to 14.1 first
                return Stage.query.filter_by(stage_number=14.1).first()  # Go to 14.1 and 14.1.1

        # Stage 14.1: Project Assessment
        elif current_stage_num == 14.1:
            if action == 'confirm':
                return Stage.query.filter_by(stage_number=14.11).first()  # Go to 14.1.1 (covers 14.1.1-14.1.1.2)
            elif action == 'rejected':
                return Stage.query.filter_by(stage_number=14.0).first()  # Stay on 14

        # Stage 14.1.1: Draft Project Management Plan
        elif current_stage_num == 14.11:
            if action == 'draft':
                return Stage.query.filter_by(stage_number=14.12).first()  # Go to 14.1.2

        # Stage 14.1.2: Approved Project Management Plan (PCM)
        elif current_stage_num == 14.12:
            if action == 'upload':
                return Stage.query.filter_by(stage_number=15.0).first()  # Go to 15

        # Stage 14.1.3: Review Project Submission
        elif current_stage_num == 14.13:
            if action == 'approved':
                return Stage.query.filter_by(stage_number=15.0).first()  # Go to 15
            elif action == 'rejected':
                return current_stage  # Stay on 14.1.3

        # Stage 15: Peer Review-Draft Certificate
        elif current_stage_num == 15.0:
            if action == 'requested':
                return Stage.query.filter_by(stage_number=15.1).first()  # Go to 15.1

        # Stage 15.1: Peer review Committee -Draft Certificate
        elif current_stage_num == 15.1:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=15.2).first()  # Go to 15.2

        # Stage 15.2: Final Review: Assessment Management (Technical Exco)
        elif current_stage_num == 15.2:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=15.3).first()  # Go to 15.3
            elif action == 'rejected':
                return current_stage  # Stay on 15.2

        # Stage 15.3: Review: EMTS
        elif current_stage_num == 15.3:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=16.0).first()  # Go to 16
            elif action == 'rejected':
                return current_stage  # Stay on 15.3

        # Stage 16: TECO Submission
        elif current_stage_num == 16.0:
            if action == 'submitted':
                return Stage.query.filter_by(stage_number=16.1).first()  # Go to 16.1

        # Stage 16.1: Review: TECO Approval
        elif current_stage_num == 16.1:
            if action == 'reviewed':
                return Stage.query.filter_by(stage_number=17.0).first()  # Go to 17

        # Stage 17: TECO Approval
        elif current_stage_num == 17.0:
            if action == 'approved':
                return Stage.query.filter_by(stage_number=17.1).first()  # Go to 17.1
            elif action == 'conditionally_approved':
                return current_stage  # Stay on 17.1
            elif action == 'rejected':
                return current_stage  # Stay on 17

        # Stage 17.1: Board Ratification
        elif current_stage_num == 17.1:
            if action == 'submitted':
                return Stage.query.filter_by(stage_number=17.2).first()  # Go to 17.2

        # Stage 17.2: Review: Board Ratification
        elif current_stage_num == 17.2:
            if action == 'ratified':
                # Ratified triggers both 18 and 19 - go to 18 first
                return Stage.query.filter_by(stage_number=18.0).first()  # Go to 18
            elif action == 'not_ratified':
                return current_stage  # Stay on 17.2

        # Stage 18: Publish Certificate (Triggered by 17.1 positive outcome)
        elif current_stage_num == 18.0:
            if action == 'submitted':
                return Stage.query.filter_by(stage_number=18.1).first()  # Go to 18.1a

        # Stage 18.1a: Website Upload Request & Gazette
        elif current_stage_num == 18.1:
            if action == 'submitted':
                return Stage.query.filter_by(stage_number=18.2).first()  # Go to 18.2a
            elif action == 'rejected':
                return current_stage  # Stay on 18.1a

        # Stage 18.2a: Approval: Publishing Requests
        elif current_stage_num == 18.2:
            if action == 'approved':
                return Stage.query.filter_by(stage_number=19.1).first()  # Go to 19.1b
            elif action == 'rejected':
                return current_stage  # Stay on 18.2a

        # Stage 19: Certificate Signing (Triggered by 17.1 positive outcome)
        elif current_stage_num == 19.0:
            if action == 'submitted':
                return Stage.query.filter_by(stage_number=19.2).first()  # Go to 19.2b

        # Stage 19.1b: Certificate Signing status
        elif current_stage_num == 19.1:
            if action == 'signed':
                return Stage.query.filter_by(stage_number=19.2).first()  # Go to 19.2b
            elif action == 'not_signed':
                return current_stage  # Stay on 19.1b

        # Stage 19.2b: Dispatch signed certificate
        elif current_stage_num == 19.2:
            if action in ['couriered', 'collected', 'digital_copy']:
                return Stage.query.filter_by(stage_number=20.0).first()  # Go to 20

        # Stage 20: Project Closure
        elif current_stage_num == 20.0:
            if action == 'submitted':
                return Stage.query.filter_by(stage_number=20.1).first()  # Go to 20.1

        # Stage 20.1: Project Closeout report
        elif current_stage_num == 20.1:
            if action in ['approved', 'conditionally_approved']:
                return Stage.query.filter_by(stage_number=20.2).first()  # Go to 20.2
            elif action == 'rejected':
                return Stage.query.filter_by(stage_number=20.0).first()  # Stay on 20

        # Stage 20.2: Approve Project Closure
        elif current_stage_num == 20.2:
            if action == 'approved':
                # This is the final stage - application is completed
                # Certificate generation will be triggered by the completion status
                return current_stage  # Stay on 20.2 but mark as completed
            elif action == 'rejected':
                return current_stage  # Stay on 20.2

        # Final stage - END
        elif current_stage_num == 21.0:
            return current_stage  # Already at final stage

        # Fallback: stay at current stage
        return current_stage

    def move_application(self, application, action, reason=None, user_id=None):
        """Move application to next stage based on action"""
        try:
            logger.info(f'Moving application {application.application_number} with action: {action}')

            current_stage = application.current_stage
            next_stage = self.get_next_stage(current_stage, action)

            # Special handling for final stage completion
            if current_stage.stage_number == 20.2 and action == 'approved':
                # Move to final completion stage
                final_stage = Stage.query.filter_by(stage_number=23.0).first()
                if final_stage:
                    # Update application to final stage
                    application.current_stage_id = final_stage.id
                    application.status = 'Completed'
                    application.last_updated = datetime.utcnow()

                    # Create history record for completion
                    history = ApplicationHistory(
                        application_id=application.id,
                        from_stage_id=current_stage.id,
                        to_stage_id=final_stage.id,
                        action=action,
                        reason=reason or 'Application completed - ready for certificate generation',
                        moved_by_user_id=user_id
                    )

                    db.session.add(history)
                    db.session.commit()
                    logger.info('Application moved to final stage - ready for certificate generation')

                    # Send completion notifications
                    self.email_service.send_stage_notification(
                        application=application,
                        action='completed',
                        new_stage=final_stage,
                        reason='Application has been completed and is ready for certificate generation.',
                        notification_type='approved'
                    )

                    return {
                        'success': True,
                        'message': 'Application completed successfully - ready for certificate generation',
                        'new_stage': final_stage,
                        'completed': True
                    }
                else:
                    logger.error('Final stage 23.0 not found')
                    return {
                        'success': False,
                        'message': 'Error: Final stage not found'
                    }


            if not next_stage:
                logger.error(f'Unable to determine next stage for action: {action} from stage: {current_stage.stage_number}')
                return {
                    'success': False,
                    'message': 'Unable to determine next stage'
                }

            logger.info(f'Moving from stage {current_stage.stage_number} ({current_stage.name}) to stage {next_stage.stage_number} ({next_stage.name})')

            # Update application
            old_stage = application.current_stage
            application.current_stage_id = next_stage.id
            application.last_updated = datetime.utcnow()

            # Update status based on stage
            if next_stage.stage_number >= 23.0:
                application.status = 'Completed'
            elif next_stage.is_review_stage:
                application.status = 'Under Review'
            elif self.stage_requires_client_upload(next_stage.stage_number):
                application.status = 'Awaiting Client Upload'
            else:
                application.status = 'In Progress'

            logger.info(f'Updated application status to: {application.status}')

            # Create history record
            history = ApplicationHistory(
                application_id=application.id,
                from_stage_id=old_stage.id,
                to_stage_id=next_stage.id,
                action=action,
                reason=reason,
                moved_by_user_id=user_id
            )

            db.session.add(history)
            db.session.commit()
            logger.info('Database updated successfully')

            # Send notifications
            notification_type = 'review' if next_stage.is_review_stage else 'approved'
            logger.info(f'Sending notifications with type: {notification_type}')

            notification_sent = self.email_service.send_stage_notification(
                application=application,
                action=action,
                new_stage=next_stage,
                reason=reason,
                notification_type=notification_type
            )

            if notification_sent:
                logger.info('Notifications sent successfully')
            else:
                logger.warning('Notifications failed to send')

            return {
                'success': True,
                'message': f'Application moved from {old_stage.name} to {next_stage.name}',
                'new_stage': next_stage
            }

        except Exception as e:
            db.session.rollback()
            logger.error(f'Workflow error: {e}', exc_info=True)
            return {
                'success': False,
                'message': f'Workflow error: {str(e)}'
            }

    def handle_client_upload(self, application):
        """Handle automatic progression when client uploads documents"""
        try:
            current_stage = application.current_stage

            # Only auto-progress from client upload stages
            if current_stage.stage_number in [4.2, 13.2]:  # Updated stage numbers
                next_stage = self.get_next_stage(current_stage, 'client_upload_received')

                if next_stage and next_stage.id != current_stage.id:
                    # Update application
                    old_stage = application.current_stage
                    application.current_stage_id = next_stage.id
                    application.last_updated = datetime.utcnow()
                    application.status = 'In Progress'

                    # Create history record
                    history = ApplicationHistory(
                        application_id=application.id,
                        from_stage_id=old_stage.id,
                        to_stage_id=next_stage.id,
                        action='client_upload_received',
                        reason='Client uploaded required documents',
                        moved_by_user_id=None  # System action
                    )

                    db.session.add(history)
                    db.session.commit()

                    # Notify assigned groups that documents are ready for verification
                    self.email_service.send_stage_notification(
                        application=application,
                        action='client_upload_received',
                        new_stage=next_stage,
                        reason='Client has uploaded required documents. Please verify payment.',
                        notification_type='approved'
                    )

                    return True

            return False

        except Exception as e:
            db.session.rollback()
            logger.error(f'Client upload progression error: {e}')
            return False

# CertificateService class removed - certificates will be uploaded manually via the certificates page

# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, is_active=True).first()

        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user)

            AuditLog.create_log(
                user_id=user.id,
                action='User logged in',
                details={'username': username}
            )

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    AuditLog.create_log(
        user_id=current_user.id,
        action='User logged out'
    )
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# =============================================================================
# ROUTES - MAIN APPLICATION
# =============================================================================

@app.route('/')
@login_required
def index():
    """Dashboard with application statistics"""
    try:
        # Get statistics
        total_applications = Application.query.count()
        pending_applications = Application.query.filter(
            Application.status.in_(['Submitted', 'In Progress'])
        ).count()

        # Recent applications
        recent_applications = Application.query.order_by(
            Application.submitted_at.desc()
        ).limit(5).all()

        # Applications by stage
        stage_stats = db.session.query(
            Stage.name,
            db.func.count(Application.id).label('count')
        ).join(Application).group_by(Stage.name).all()

        return render_template('main/index.html',
                             total_applications=total_applications,
                             pending_applications=pending_applications,
                             recent_applications=recent_applications,
                             stage_stats=stage_stats)

    except Exception as e:
        logger.error(f'Dashboard error: {e}')
        flash('Error loading dashboard data.', 'error')
        return render_template('main/index.html')

@app.route('/applications')
@login_required
def applications():
    """List all applications with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20

        # Base query
        query = Application.query

        # Apply filters
        status_filter = request.args.get('status')
        if status_filter:
            query = query.filter(Application.status == status_filter)

        stage_filter = request.args.get('stage_id')
        if stage_filter:
            query = query.filter(Application.current_stage_id == stage_filter)

        search = request.args.get('search')
        if search:
            query = query.filter(
                db.or_(
                    Application.application_number.ilike(f'%{search}%'),
                    Application.applicant_name.ilike(f'%{search}%'),
                    Application.applicant_email.ilike(f'%{search}%')
                )
            )

        # Paginate results
        applications = query.order_by(Application.submitted_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        # Get all stages for filter dropdown
        stages = Stage.query.filter_by(is_active=True).order_by(Stage.stage_number).all()

        return render_template('main/applications.html',
                             applications=applications,
                             stages=stages)

    except Exception as e:
        logger.error(f'Applications list error: {e}')
        flash('Error loading applications.', 'error')
        return render_template('main/applications.html')

@app.route('/application/<int:id>')
@login_required
def application_detail(id):
    """Application detail with processing interface"""
    try:
        application = Application.query.get_or_404(id)

        # Get application documents
        documents = Document.query.filter_by(application_id=application.id).all()

        # Get application history
        history = ApplicationHistory.query.filter_by(
            application_id=application.id
        ).order_by(ApplicationHistory.created_at.desc()).all()

        # Get workflow actions
        workflow_service = WorkflowService()
        available_actions = workflow_service.get_available_actions(application.current_stage)

        # Get certificates
        certificates = Certificate.query.filter_by(application_id=application.id).all()

        return render_template('main/application_detail.html',
                             application=application,
                             documents=documents,
                             history=history,
                             available_actions=available_actions,
                             certificates=certificates)

    except Exception as e:
        logger.error(f'Application detail error: {e}')
        flash('Error loading application details.', 'error')
        return redirect(url_for('applications'))

@app.route('/application/<int:id>/process', methods=['POST'])
@login_required
def process_application(id):
    """Process application workflow action"""
    try:
        application = Application.query.get_or_404(id)

        action = request.form.get('action')
        reason = request.form.get('reason', '').strip()

        if not action:
            flash('Please select an action.', 'error')
            return redirect(url_for('application_detail', id=id))

        # Process workflow
        workflow_service = WorkflowService()
        result = workflow_service.move_application(
            application=application,
            action=action,
            reason=reason if reason else None,
            user_id=current_user.id
        )

        if result['success']:
            flash(result['message'], 'success')

            # Log the action
            AuditLog.create_log(
                user_id=current_user.id,
                action=f'Application processed: {action}',
                entity_type='Application',
                entity_id=application.id,
                details={
                    'action': action,
                    'reason': reason,
                    'old_stage': application.current_stage.name,
                    'new_stage': result['new_stage'].name
                }
            )
        else:
            flash(result['message'], 'error')

        return redirect(url_for('application_detail', id=id))

    except Exception as e:
        logger.error(f'Process application error: {e}')
        flash('Error processing application.', 'error')
        return redirect(url_for('application_detail', id=id))

@app.route('/application/<int:id>/upload', methods=['POST'])
@login_required
def upload_document(id):
    """Upload document for application"""
    try:
        application = Application.query.get_or_404(id)

        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('application_detail', id=id))

        file = request.files['file']
        document_type = request.form.get('document_type', 'General Document')
        description = request.form.get('description', '')

        file_service = FileService()
        result = file_service.save_uploaded_file(
            file=file,
            application=application,
            document_type=document_type,
            description=description,
            uploaded_by_external=False,
            uploaded_by_user_id=current_user.id
        )

        if result['success']:
            flash(result['message'], 'success')

            # Log the upload
            AuditLog.create_log(
                user_id=current_user.id,
                action='Document uploaded',
                entity_type='Document',
                entity_id=result['document'].id,
                details={
                    'filename': result['filename'],
                    'application_number': application.application_number,
                    'document_type': document_type
                }
            )
        else:
            flash(result['message'], 'error')

        return redirect(url_for('application_detail', id=id))

    except Exception as e:
        logger.error(f'Document upload error: {e}')
        flash('Error uploading document.', 'error')
        return redirect(url_for('application_detail', id=id))

@app.route('/document/<int:id>/download')
@login_required
def download_document(id):
    """Download document"""
    try:
        document = Document.query.get_or_404(id)

        if not os.path.exists(document.file_path):
            flash('File not found.', 'error')
            return redirect(request.referrer or url_for('applications'))

        # Log the download
        AuditLog.create_log(
            user_id=current_user.id,
            action='Document downloaded',
            entity_type='Document',
            entity_id=document.id,
            details={
                'filename': document.original_filename,
                'application_number': document.application.application_number
            }
        )

        return send_file(
            document.file_path,
            as_attachment=True,
            download_name=document.original_filename
        )

    except Exception as e:
        logger.error(f'Document download error: {e}')
        flash('Error downloading document.', 'error')
        return redirect(request.referrer or url_for('applications'))

@app.route('/application/<int:id>/create_certificate', methods=['POST'])
@login_required
def create_certificate_record(id):
    """Create certificate record for completed application"""
    try:
        application = Application.query.get_or_404(id)

        # Check if application is completed
        if application.status != 'Completed':
            flash('Certificate can only be created for completed applications.', 'error')
            return redirect(url_for('application_detail', id=id))

        # Check if certificate already exists
        existing_cert = Certificate.query.filter_by(application_id=application.id).first()
        if existing_cert:
            flash('Certificate already exists for this application.', 'warning')
            return redirect(url_for('application_detail', id=id))

        # Create certificate record
        certificate = Certificate(
            application_id=application.id,
            issued_date=date.today(),
            expiry_date=date.today() + timedelta(days=365 * app.config['CERTIFICATE_VALIDITY_YEARS']),
            generated_by_user_id=current_user.id,
            status='InActive'  # Set to InActive until PDF is uploaded
        )
        certificate.generate_certificate_number()

        db.session.add(certificate)
        db.session.commit()

        # Log certificate creation
        AuditLog.create_log(
            user_id=current_user.id,
            action='Certificate record created',
            entity_type='Certificate',
            entity_id=certificate.id,
            details={
                'certificate_number': certificate.certificate_number,
                'application_number': application.application_number
            }
        )

        flash(f'Certificate record created: {certificate.certificate_number}. Please upload the PDF file.', 'success')
        return redirect(url_for('certificate_detail', id=certificate.id))

    except Exception as e:
        logger.error(f'Certificate creation error: {e}')
        flash('Error creating certificate record.', 'error')
        return redirect(url_for('application_detail', id=id))

# =============================================================================
# ROUTES - EXTERNAL APPLICATION SUBMISSION
# =============================================================================

@app.route('/apply')
def apply():
    """External application form"""
    return render_template('external/apply.html')

@app.route('/submit_application', methods=['POST'])
def submit_application():
    """Handle external application submission"""
    try:
        # Get form data
        data = request.form.to_dict()
        files = request.files

        # Validate required fields
        required_fields = ['first_name', 'last_name', 'company_name', 'applicant_email', 'applicant_phone']
        for field in required_fields:
            if not data.get(field):
                flash(f'Please fill in the {field.replace("_", " ").title()} field.', 'error')
                return render_template('external/apply.html')

        # Create or get company
        company = Company.query.filter_by(name=data['company_name']).first()
        if not company:
            company = Company(
                name=data['company_name'],
                registration_number=data.get('comp_reg_number', ''),
                email=data.get('company_email', ''),
                phone=data.get('company_phone', ''),
                address=data.get('physical_address', ''),
                website=data.get('company_website', ''),
                contact_person=f"{data['first_name']} {data['last_name']}"
            )
            db.session.add(company)
            db.session.flush()

        # Get first stage
        first_stage = Stage.query.filter_by(stage_number=1.0).first()
        if not first_stage:
            flash('System error: No initial stage found.', 'error')
            return render_template('external/apply.html')

        # Create application
        application = Application(
            applicant_name=f"{data['first_name']} {data['last_name']}",
            applicant_email=data['applicant_email'],
            applicant_phone=data['applicant_phone'],
            company_id=company.id,
            certificate_type=data.get('certification_type', 'Professional Certification'),
            current_stage_id=first_stage.id,
            status='Submitted'
        )
        application.generate_application_number()

        db.session.add(application)
        db.session.flush()

        # Handle file uploads
        uploaded_files = []
        if 'supporting_documents' in files:
            file_list = files.getlist('supporting_documents')
            for file in file_list:
                if file and file.filename != '':
                    file_service = FileService()
                    result = file_service.save_uploaded_file(
                        file=file,
                        application=application,
                        document_type='Initial Application Document',
                        description='Document submitted with initial application',
                        uploaded_by_external=True
                    )
                    if result['success']:
                        uploaded_files.append(result['filename'])
                    else:
                        logger.warning(f"File upload failed: {result['message']}")

        # Create audit log for application submission
        AuditLog.create_log(
            user_id=None,  # External submission
            action='External application submitted',
            entity_type='Application',
            entity_id=application.id,
            details={
                'application_number': application.application_number,
                'applicant_name': application.applicant_name,
                'company_name': company.name,
                'documents_uploaded': len(uploaded_files)
            }
        )

        db.session.commit()

        # Send confirmation email
        try:
            email_service = EmailService()
            email_service.send_application_confirmation(application, uploaded_files)
        except Exception as e:
            logger.error(f"Failed to send confirmation email: {e}")

        # Send notification to review team
        try:
            # Get the TAO group (first stage group)
            stage_groups = StageGroupAssignment.query.filter_by(stage_id=first_stage.id).all()
            for stage_group in stage_groups:
                email_service.send_new_application_notification(application, stage_group.group)
        except Exception as e:
            logger.error(f"Failed to send team notification: {e}")

        return render_template('external/success.html',
                             application_number=application.application_number,
                             applicant_name=application.applicant_name)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Application submission error: {e}")
        flash(f'Application submission failed: {str(e)}', 'error')
        return render_template('external/apply.html')

@app.route('/check_status')
def status_check_form():
    """Status check form"""
    return render_template('external/status_check.html')

@app.route('/application_status/<application_number>')
def view_application_status(application_number):
    """View application status with application number in URL"""
    try:
        application = Application.query.filter_by(application_number=application_number).first()

        if not application:
            flash('Application not found. Please check your application number.', 'error')
            return render_template('external/status_check.html')

        # Get application history
        history = ApplicationHistory.query.filter_by(
            application_id=application.id
        ).order_by(ApplicationHistory.created_at.desc()).limit(10).all()

        # Get application documents
        documents = Document.query.filter_by(application_id=application.id).all()

        return render_template('external/status.html',
                             application=application,
                             history=history,
                             documents=documents)

    except Exception as e:
        logger.error(f"Status check error: {e}")
        flash('Error checking application status.', 'error')
        return render_template('external/status_check.html')

@app.route('/application_status', methods=['POST'])
def check_application_status():
    """Public application status check"""
    try:
        application_number = request.form.get('application_number', '').strip()

        if not application_number:
            flash('Please enter an application number.', 'error')
            return render_template('external/status_check.html')

        application = Application.query.filter_by(application_number=application_number).first()

        if not application:
            flash('Application not found. Please check your application number.', 'error')
            return render_template('external/status_check.html')

        # Redirect to the status page with application number in URL
        return redirect(url_for('view_application_status', application_number=application.application_number))

    except Exception as e:
        logger.error(f"Status check error: {e}")
        flash('Error checking application status.', 'error')
        return render_template('external/status_check.html')

@app.route('/application_status/<application_number>/upload', methods=['POST'])
def upload_missing_document(application_number):
    """Handle document upload from status page"""
    try:
        application = Application.query.filter_by(application_number=application_number).first()

        if not application:
            flash('Application not found.', 'error')
            return redirect(url_for('status_check_form'))

        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('status_check_form'))

        file = request.files['file']
        document_type = request.form.get('document_type', 'Missing Document')
        description = request.form.get('description', 'Document uploaded by applicant from status page')

        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('status_check_form'))

        file_service = FileService()
        result = file_service.save_uploaded_file(
            file=file,
            application=application,
            document_type=document_type,
            description=description,
            uploaded_by_external=True
        )

        if result['success']:
            # Log the upload
            AuditLog.create_log(
                user_id=None,  # External upload
                action='Missing document uploaded from status page',
                entity_type='Document',
                entity_id=result['document'].id,
                details={
                    'filename': result['filename'],
                    'application_number': application.application_number,
                    'document_type': document_type,
                    'description': description
                }
            )

            # Notify assigned groups about new documents
            try:
                email_service = EmailService()
                stage_groups = email_service.get_stage_groups(application.current_stage_id)

                for group in stage_groups:
                    users = User.query.join(UserGroupAssignment).filter(
                        UserGroupAssignment.group_id == group.id,
                        User.is_active == True
                    ).all()

                    if users:
                        emails = [user.email for user in users]
                        subject = f'Missing Document Uploaded - {application.application_number}'

                        body = f"""
                        <html>
                        <body>
                            <h2>Missing Document Uploaded</h2>

                            <p>The applicant has uploaded a missing document for their application.</p>

                            <h3>Application Details:</h3>
                            <ul>
                                <li><strong>Application Number:</strong> {application.application_number}</li>
                                <li><strong>Applicant:</strong> {application.applicant_name}</li>
                                <li><strong>Company:</strong> {application.company.name}</li>
                                <li><strong>Current Stage:</strong> {application.current_stage.name}</li>
                                <li><strong>Document Type:</strong> {document_type}</li>
                                <li><strong>Description:</strong> {description}</li>
                                <li><strong>File:</strong> {result['filename']}</li>
                            </ul>

                            <p><strong>Action Required:</strong> Please log in to the system to review the uploaded document.</p>
                        </body>
                        </html>
                        """

                        email_service.send_email(emails, subject, body)

            except Exception as e:
                logger.error(f"Failed to send upload notification: {e}")

            flash('Document uploaded successfully! Our team will review it shortly.', 'success')
        else:
            flash(result['message'], 'error')

        # Redirect back to the application status page
        return redirect(url_for('view_application_status', application_number=application.application_number))

    except Exception as e:
        logger.error(f'Document upload error: {e}')
        flash('Error uploading document.', 'error')
        return redirect(url_for('status_check_form'))

# =============================================================================
# ROUTES - CLIENT UPLOADS
# =============================================================================

@app.route('/client/upload/<application_number>/<token>')
def client_upload_form(application_number, token):
    """Client upload form for specific application stages"""
    try:
        application = Application.verify_client_upload_token(token, application_number)
        if not application:
            flash('Invalid or expired upload link. Please contact us for assistance.', 'error')
            return render_template('external/error.html')

        # Check what type of upload is required
        workflow_service = WorkflowService()
        current_stage = application.current_stage
        requires_upload = workflow_service.stage_requires_client_upload(current_stage.stage_number)
        allows_upload = workflow_service.stage_allows_client_upload(current_stage.stage_number)

        if not (requires_upload or allows_upload):
            flash('Document upload is not available for this application stage.', 'error')
            return render_template('external/error.html')

        # Determine upload type based on stage
        upload_type = "general"
        upload_title = "Upload Documents"
        upload_description = "Upload additional documents for your application"

        if current_stage.stage_number == 4.1:
            upload_type = "payment_proof"
            upload_title = "Upload Admin Fee Payment Proof"
            upload_description = "Please upload proof of payment for the admin fee"
        elif current_stage.stage_number == 12.1:
            upload_type = "payment_proof"
            upload_title = "Upload Evaluation Fee Payment Proof"
            upload_description = "Please upload proof of payment for the evaluation fee"

        return render_template('external/client_upload.html',
                             application=application,
                             token=token,
                             upload_type=upload_type,
                             upload_title=upload_title,
                             upload_description=upload_description,
                             requires_upload=requires_upload)

    except Exception as e:
        logger.error(f'Client upload form error: {e}')
        return render_template('external/error.html')

@app.route('/client/upload/<application_number>/<token>/submit', methods=['POST'])
def client_upload_submit(application_number, token):
    """Handle client document upload submission"""
    try:
        application = Application.verify_client_upload_token(token, application_number)
        if not application:
            flash('Invalid or expired upload link.', 'error')
            return render_template('external/error.html')

        if 'files' not in request.files:
            flash('Please select at least one file.', 'error')
            return redirect(url_for('client_upload_form',
                                  application_number=application_number,
                                  token=token))

        files = request.files.getlist('files')
        document_type = request.form.get('document_type', 'Client Document')
        description = request.form.get('description', 'Document uploaded by client')

        uploaded_files = []
        file_service = FileService()

        for file in files:
            if file and file.filename != '':
                result = file_service.save_uploaded_file(
                    file=file,
                    application=application,
                    document_type=document_type,
                    description=description,
                    uploaded_by_external=True
                )
                if result['success']:
                    uploaded_files.append(result['filename'])
                else:
                    flash(result['message'], 'warning')

        if uploaded_files:
            # Log the client upload
            AuditLog.create_log(
                user_id=None,  # Client upload
                action='Client document upload',
                entity_type='Application',
                entity_id=application.id,
                details={
                    'application_number': application.application_number,
                    'files_uploaded': uploaded_files,
                    'document_type': document_type,
                    'stage': application.current_stage.name
                }
            )

            # Auto-progress application if this is a client upload stage
            workflow_service = WorkflowService()
            auto_progressed = workflow_service.handle_client_upload(application)

            if not auto_progressed:
                # If not auto-progressed, notify assigned groups about new documents
                try:
                    email_service = EmailService()
                    stage_groups = email_service.get_stage_groups(application.current_stage_id)

                    for group in stage_groups:
                        users = User.query.join(UserGroupAssignment).filter(
                            UserGroupAssignment.group_id == group.id,
                            User.is_active == True
                        ).all()

                        if users:
                            emails = [user.email for user in users]
                            subject = f'Client Documents Uploaded - {application.application_number}'

                            body = f"""
                            <html>
                            <body>
                                <h2>Client Documents Uploaded</h2>

                                <p>The client has uploaded documents for their application.</p>

                                <h3>Application Details:</h3>
                                <ul>
                                    <li><strong>Application Number:</strong> {application.application_number}</li>
                                    <li><strong>Applicant:</strong> {application.applicant_name}</li>
                                    <li><strong>Company:</strong> {application.company.name}</li>
                                    <li><strong>Current Stage:</strong> {application.current_stage.name}</li>
                                    <li><strong>Files Uploaded:</strong> {len(uploaded_files)}</li>
                                </ul>

                                <p><strong>Document Type:</strong> {document_type}</p>
                                <p><strong>Description:</strong> {description}</p>

                                <p><strong>Action Required:</strong> Please log in to the system to review the uploaded documents.</p>
                            </body>
                            </html>
                            """

                            email_service.send_email(emails, subject, body)

                except Exception as e:
                    logger.error(f"Failed to send upload notification: {e}")

            return render_template('external/client_upload_success.html',
                                 application_number=application.application_number,
                                 files_count=len(uploaded_files),
                                 upload_type=request.form.get('upload_type', 'general'))
        else:
            flash('No files were uploaded successfully.', 'error')
            return redirect(url_for('client_upload_form',
                                  application_number=application_number,
                                  token=token))

    except Exception as e:
        logger.error(f'Client upload error: {e}')
        flash('Error uploading documents.', 'error')
        return render_template('external/error.html')

# =============================================================================
# ROUTES - EXTERNAL UPLOAD
# =============================================================================

@app.route('/external/apply')
def external_apply():
    """Public application form"""
    return render_template('external/apply.html')

@app.route('/external/upload/<token>')
def external_upload(token):
    """External document upload with secure token"""
    try:
        application = Application.verify_access_token(token)
        if not application:
            flash('Invalid or expired link. Please contact us for assistance.', 'error')
            return render_template('external/error.html')

        return render_template('external/upload.html',
                             application=application,
                             token=token)

    except Exception as e:
        logger.error(f'External upload access error: {e}')
        return render_template('external/error.html')

@app.route('/external/upload/<token>/submit', methods=['POST'])
def external_upload_submit(token):
    """Handle external document upload submission"""
    try:
        application = Application.verify_access_token(token)
        if not application:
            flash('Invalid or expired link.', 'error')
            return render_template('external/error.html')

        if 'files' not in request.files:
            flash('Please select at least one file.', 'error')
            return render_template('external/upload.html',
                                 application=application,
                                 token=token)

        files = request.files.getlist('files')
        document_type = request.form.get('document_type', 'Client Submitted Document')
        description = request.form.get('description', 'Document uploaded by client')

        uploaded_files = []
        file_service = FileService()

        for file in files:
            if file and file.filename != '':
                result = file_service.save_uploaded_file(
                    file=file,
                    application=application,
                    document_type=document_type,
                    description=description,
                    uploaded_by_external=True
                )
                if result['success']:
                    uploaded_files.append(result['filename'])
                else:
                    flash(result['message'], 'warning')

        if uploaded_files:
            # Log the external upload
            AuditLog.create_log(
                user_id=None,  # External upload
                action='External document upload',
                entity_type='Application',
                entity_id=application.id,
                details={
                    'application_number': application.application_number,
                    'files_uploaded': uploaded_files,
                    'document_type': document_type
                }
            )

            # Notify assigned groups about new documents
            try:
                email_service = EmailService()
                stage_groups = email_service.get_stage_groups(application.current_stage_id)

                for group in stage_groups:
                    users = User.query.join(UserGroupAssignment).filter(
                        UserGroupAssignment.group_id == group.id,
                        User.is_active == True
                    ).all()

                    if users:
                        emails = [user.email for user in users]
                        subject = f'New Documents Uploaded - {application.application_number}'

                        body = f"""
                        <html>
                        <body>
                            <h2>New Documents Uploaded</h2>

                            <p>The client has uploaded additional documents for an application.</p>

                            <h3>Application Details:</h3>
                            <ul>
                                <li><strong>Application Number:</strong> {application.application_number}</li>
                                <li><strong>Applicant:</strong> {application.applicant_name}</li>
                                <li><strong>Company:</strong> {application.company.name}</li>
                                <li><strong>Current Stage:</strong> {application.current_stage.name}</li>
                                <li><strong>Files Uploaded:</strong> {len(uploaded_files)}</li>
                            </ul>

                            <p><strong>Document Type:</strong> {document_type}</p>
                            <p><strong>Description:</strong> {description}</p>

                            <p><strong>Action Required:</strong> Please log in to the system to review the uploaded documents.</p>
                        </body>
                        </html>
                        """

                        email_service.send_email(emails, subject, body)

            except Exception as e:
                logger.error(f"Failed to send upload notification: {e}")

            return render_template('external/upload_success.html',
                                 application_number=application.application_number,
                                 files_count=len(uploaded_files))
        else:
            flash('No files were uploaded successfully.', 'error')
            return render_template('external/upload.html',
                                 application=application,
                                 token=token)

    except Exception as e:
        logger.error(f'External upload error: {e}')
        flash('Error uploading documents.', 'error')
        return render_template('external/error.html')

# =============================================================================
# ROUTES - CERTIFICATE MANAGEMENT
# =============================================================================

@app.route('/certificates')
@login_required
def certificates():
    """Certificate management page with search and filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20

        # Base query - only show certificates for completed applications
        query = Certificate.query.join(Application).filter(
            Application.status == 'Completed'
        )

        # Apply filters
        status_filter = request.args.get('status')
        if status_filter and status_filter != 'All':
            query = query.filter(Certificate.status == status_filter)

        search = request.args.get('search')
        if search:
            query = query.filter(
                db.or_(
                    Certificate.certificate_number.ilike(f'%{search}%'),
                    Application.application_number.ilike(f'%{search}%'),
                    Application.applicant_name.ilike(f'%{search}%'),
                    Application.company.has(Company.name.ilike(f'%{search}%'))
                )
            )

        # Paginate results
        certificates = query.order_by(Certificate.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        # Get status counts for filter tabs
        status_counts = {
            'All': Certificate.query.join(Application).filter(Application.status == 'Completed').count(),
            'Active': Certificate.query.join(Application).filter(Application.status == 'Completed', Certificate.status == 'Active').count(),
            'InActive': Certificate.query.join(Application).filter(Application.status == 'Completed', Certificate.status == 'InActive').count(),
            'Withdrawn': Certificate.query.join(Application).filter(Application.status == 'Completed', Certificate.status == 'Withdrawn').count(),
            'Suspended': Certificate.query.join(Application).filter(Application.status == 'Completed', Certificate.status == 'Suspended').count(),
            'Cancelled': Certificate.query.join(Application).filter(Application.status == 'Completed', Certificate.status == 'Cancelled').count(),
        }

        return render_template('main/certificates.html',
                             certificates=certificates,
                             status_counts=status_counts)

    except Exception as e:
        db.session.rollback()  # Rollback the failed transaction
        logger.error(f'Certificates page error: {e}')
        flash('Error loading certificates.', 'error')
        return render_template('main/certificates.html', certificates=None, status_counts={})

@app.route('/certificate/<int:id>')
@login_required
def certificate_detail(id):
    """Certificate detail page with upload and status management"""
    try:
        certificate = Certificate.query.get_or_404(id)

        # Get certificate status history
        status_history = CertificateStatusHistory.query.filter_by(
            certificate_id=certificate.id
        ).order_by(CertificateStatusHistory.changed_at.desc()).all()

        return render_template('main/certificate_detail.html',
                             certificate=certificate,
                             status_history=status_history)

    except Exception as e:
        logger.error(f'Certificate detail error: {e}')
        flash('Error loading certificate details.', 'error')
        return redirect(url_for('certificates'))

@app.route('/certificate/<int:id>/upload', methods=['POST'])
@login_required
def upload_certificate_file(id):
    """Upload certificate PDF file"""
    try:
        certificate = Certificate.query.get_or_404(id)

        if 'certificate_file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('certificate_detail', id=id))

        file = request.files['certificate_file']

        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('certificate_detail', id=id))

        # Validate file type (PDF only)
        if not file.filename.lower().endswith('.pdf'):
            flash('Only PDF files are allowed.', 'error')
            return redirect(url_for('certificate_detail', id=id))

        # Generate secure filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{certificate.certificate_number}_{timestamp}.pdf"

        # Create directory if not exists
        cert_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'certificates')
        os.makedirs(cert_folder, exist_ok=True)

        # Save file
        file_path = os.path.join(cert_folder, filename)
        file.save(file_path)

        # Update certificate record
        old_status = certificate.status
        certificate.certificate_file = filename
        certificate.status = 'Active'  # Set to Active when uploaded
        certificate.last_updated = datetime.utcnow()

        # Create status history if status changed
        if old_status != 'Active':
            status_history = CertificateStatusHistory(
                certificate_id=certificate.id,
                old_status=old_status,
                new_status='Active',
                reason='Certificate file uploaded',
                changed_by_user_id=current_user.id
            )
            db.session.add(status_history)

        db.session.commit()

        # Log the action
        AuditLog.create_log(
            user_id=current_user.id,
            action='Certificate file uploaded',
            entity_type='Certificate',
            entity_id=certificate.id,
            details={
                'certificate_number': certificate.certificate_number,
                'filename': filename,
                'application_number': certificate.application.application_number
            }
        )

        flash('Certificate file uploaded successfully!', 'success')
        return redirect(url_for('certificate_detail', id=id))

    except Exception as e:
        logger.error(f'Certificate upload error: {e}')
        flash('Error uploading certificate file.', 'error')
        return redirect(url_for('certificate_detail', id=id))

@app.route('/certificate/<int:id>/status', methods=['POST'])
@login_required
def update_certificate_status(id):
    """Update certificate status with reason"""
    try:
        certificate = Certificate.query.get_or_404(id)

        new_status = request.form.get('status')
        reason = request.form.get('reason', '').strip()

        if not new_status:
            flash('Please select a status.', 'error')
            return redirect(url_for('certificate_detail', id=id))

        if not reason:
            flash('Please provide a reason for the status change.', 'error')
            return redirect(url_for('certificate_detail', id=id))

        # Valid statuses
        valid_statuses = ['Active', 'InActive', 'Withdrawn', 'Suspended', 'Cancelled']
        if new_status not in valid_statuses:
            flash('Invalid status selected.', 'error')
            return redirect(url_for('certificate_detail', id=id))

        old_status = certificate.status

        if old_status == new_status:
            flash('Certificate is already in this status.', 'warning')
            return redirect(url_for('certificate_detail', id=id))

        # Update certificate status
        certificate.status = new_status
        certificate.last_updated = datetime.utcnow()

        # Create status history
        status_history = CertificateStatusHistory(
            certificate_id=certificate.id,
            old_status=old_status,
            new_status=new_status,
            reason=reason,
            changed_by_user_id=current_user.id
        )

        db.session.add(status_history)
        db.session.commit()

        # Log the action
        AuditLog.create_log(
            user_id=current_user.id,
            action=f'Certificate status changed from {old_status} to {new_status}',
            entity_type='Certificate',
            entity_id=certificate.id,
            details={
                'certificate_number': certificate.certificate_number,
                'old_status': old_status,
                'new_status': new_status,
                'reason': reason
            }
        )

        # Send notification email to applicant about status change
        try:
            email_service = EmailService()
            subject = f'Certificate Status Update - {certificate.certificate_number}'

            body = f"""
            <html>
            <body>
                <h2>Certificate Status Update</h2>

                <p>Dear {certificate.application.applicant_name},</p>

                <p>Your certificate status has been updated.</p>

                <h3>Certificate Details:</h3>
                <ul>
                    <li><strong>Certificate Number:</strong> {certificate.certificate_number}</li>
                    <li><strong>Application Number:</strong> {certificate.application.application_number}</li>
                    <li><strong>Previous Status:</strong> {old_status}</li>
                    <li><strong>New Status:</strong> {new_status}</li>
                    <li><strong>Reason:</strong> {reason}</li>
                </ul>

                <p>If you have any questions regarding this status change, please contact us.</p>
            </body>
            </html>
            """

            email_service.send_email([certificate.application.applicant_email], subject, body)
        except Exception as e:
            logger.error(f"Failed to send status change notification: {e}")

        flash(f'Certificate status updated from {old_status} to {new_status}.', 'success')
        return redirect(url_for('certificate_detail', id=id))

    except Exception as e:
        db.session.rollback()
        logger.error(f'Certificate status update error: {e}')
        flash('Error updating certificate status.', 'error')
        return redirect(url_for('certificate_detail', id=id))

@app.route('/certificate/<int:id>/download')
@login_required
def download_certificate(id):
    """Download certificate file"""
    try:
        certificate = Certificate.query.get_or_404(id)

        if not certificate.certificate_file:
            flash('No certificate file available.', 'error')
            return redirect(request.referrer or url_for('certificates'))

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'certificates', certificate.certificate_file)

        if not os.path.exists(file_path):
            flash('Certificate file not found.', 'error')
            return redirect(request.referrer or url_for('certificates'))

        # Log the download
        AuditLog.create_log(
            user_id=current_user.id,
            action='Certificate downloaded',
            entity_type='Certificate',
            entity_id=certificate.id,
            details={
                'certificate_number': certificate.certificate_number,
                'filename': certificate.certificate_file
            }
        )

        return send_file(
            file_path,
            as_attachment=True,
            download_name=f"{certificate.certificate_number}.pdf"
        )

    except Exception as e:
        logger.error(f'Certificate download error: {e}')
        flash('Error downloading certificate.', 'error')
        return redirect(request.referrer or url_for('certificates'))

# =============================================================================
# ROUTES - ADMIN PANEL
# =============================================================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Administrator dashboard"""
    try:
        # Get statistics
        total_users = User.query.count()
        total_groups = Group.query.count()
        total_stages = Stage.query.count()

        # Recent audit logs
        recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()

        return render_template('admin/dashboard.html',
                             total_users=total_users,
                             total_groups=total_groups,
                             total_stages=total_stages,
                             recent_logs=recent_logs)

    except Exception as e:
        logger.error(f'Admin dashboard error: {e}')
        flash('Error loading admin dashboard.', 'error')
        return render_template('admin/dashboard.html')

@app.route('/admin/users')
@admin_required
def admin_users():
    """List all users with management options"""
    try:
        users = User.query.filter_by(is_internal=True).order_by(User.created_at.desc()).all()

        # Get group assignments for each user
        user_groups = {}
        for user in users:
            assignments = UserGroupAssignment.query.filter_by(user_id=user.id).all()
            user_groups[user.id] = [assignment.group.name for assignment in assignments]

        return render_template('admin/users.html',
                             users=users,
                             user_groups=user_groups)

    except Exception as e:
        logger.error(f'Admin users error: {e}')
        flash('Error loading users.', 'error')
        return render_template('admin/users.html', users=[], user_groups={})

@app.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    """Admin creates new internal user"""
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form['username']
            email = request.form['email']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            password = request.form['password']

            # Check if user already exists
            existing_user = User.query.filter(
                db.or_(User.username == username, User.email == email)
            ).first()

            if existing_user:
                flash('User with this username or email already exists.', 'error')
                return render_template('admin/create_user.html')

            # Create user
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_internal=True,
                is_active=True
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            # Log the action
            AuditLog.create_log(
                user_id=current_user.id,
                action='User created',
                entity_type='User',
                entity_id=user.id,
                details={
                    'username': username,
                    'email': email,
                    'full_name': f"{first_name} {last_name}"
                }
            )

            flash(f'User {username} created successfully!', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            logger.error(f'Create user error: {e}')
            flash(f'Error creating user: {str(e)}', 'error')

    return render_template('admin/create_user.html')

@app.route('/admin/users/<int:user_id>/groups', methods=['GET', 'POST'])
@admin_required
def manage_user_groups(user_id):
    """Assign/remove user from groups"""
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        try:
            # Get selected groups from form
            selected_group_ids = request.form.getlist('groups')

            # Remove all existing assignments
            UserGroupAssignment.query.filter_by(user_id=user_id).delete()

            # Add new assignments
            for group_id in selected_group_ids:
                assignment = UserGroupAssignment(
                    user_id=user_id,
                    group_id=int(group_id),
                    assigned_by_user_id=current_user.id
                )
                db.session.add(assignment)

            db.session.commit()

            # Log the action
            group_names = [Group.query.get(int(gid)).name for gid in selected_group_ids]
            AuditLog.create_log(
                user_id=current_user.id,
                action='User groups updated',
                entity_type='User',
                entity_id=user_id,
                details={
                    'user': user.username,
                    'groups_assigned': group_names
                }
            )

            flash(f'Groups updated for {user.full_name}', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            logger.error(f'Update user groups error: {e}')
            flash(f'Error updating groups: {str(e)}', 'error')

    # GET request - show form
    all_groups = Group.query.filter_by(is_active=True).all()
    current_assignments = UserGroupAssignment.query.filter_by(user_id=user_id).all()
    current_group_ids = [assignment.group_id for assignment in current_assignments]

    return render_template('admin/user_groups.html',
                         user=user,
                         all_groups=all_groups,
                         current_group_ids=current_group_ids)

@app.route('/admin/users/<int:user_id>/deactivate')
@admin_required
def deactivate_user(user_id):
    """Deactivate a user account"""
    try:
        user = User.query.get_or_404(user_id)

        if user.id == current_user.id:
            flash('You cannot deactivate your own account.', 'error')
            return redirect(url_for('admin_users'))

        user.is_active = False
        db.session.commit()

        # Log the action
        AuditLog.create_log(
            user_id=current_user.id,
            action='User deactivated',
            entity_type='User',
            entity_id=user_id,
            details={
                'username': user.username,
                'email': user.email
            }
        )

        flash(f'User {user.username} has been deactivated.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f'Deactivate user error: {e}')
        flash('Error deactivating user.', 'error')

    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/activate')
@admin_required
def activate_user(user_id):
    """Activate a user account"""
    try:
        user = User.query.get_or_404(user_id)
        user.is_active = True
        db.session.commit()

        # Log the action
        AuditLog.create_log(
            user_id=current_user.id,
            action='User activated',
            entity_type='User',
            entity_id=user_id,
            details={
                'username': user.username,
                'email': user.email
            }
        )

        flash(f'User {user.username} has been activated.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f'Activate user error: {e}')
        flash('Error activating user.', 'error')

    return redirect(url_for('admin_users'))

@app.route('/admin/stages')
@admin_required
def admin_stages():
    """Stage management"""
    try:
        stages = Stage.query.order_by(Stage.stage_number).all()

        return render_template('admin/stages.html', stages=stages)

    except Exception as e:
        logger.error(f'Admin stages error: {e}')
        flash('Error loading stages.', 'error')
        return render_template('admin/stages.html')

@app.route('/admin/setup', methods=['GET', 'POST'])
@admin_required
def admin_setup():
    """System setup and initialization"""
    if request.method == 'POST':
        try:
            setup_type = request.form.get('setup_type')

            if setup_type == 'initial_data':
                create_initial_data()
                flash('Initial data created successfully!', 'success')
            elif setup_type == 'sample_applications':
                create_sample_applications()
                flash('Sample applications created successfully!', 'success')
            elif setup_type == 'reset_database':
                reset_database()
                flash('Database reset successfully!', 'success')

        except Exception as e:
            logger.error(f'Setup error: {e}')
            flash(f'Setup error: {str(e)}', 'error')

    return render_template('admin/setup.html')


def create_stage_group_assignments():
    """Assign groups to stages based on exact workflow specification"""

    # Stage assignments based on your detailed workflow specification
    stage_assignments = {
        1.0: ['TAO'],  # New Application by client - TAO processes
        2.0: ['TAO'],  # Verification of Application Completeness - TAO processes
        3.0: ['TAO'],  # Admin Fee Request - TAO processes
        4.0: ['Finance'],  # Admin Invoice Generation - Finance processes
        4.1: ['TAO'],  # Confirmation of Invoice - TAO confirms
        4.2: ['TAO', 'Finance'],  # Admin fee-Proof of Payment - Notify TAO Group and Finance Group
        4.3: ['Finance'],  # Payment Confirmation - Finance Group processes
        5.0: ['TGL: TA'],  # Allocation: Criteria Review - TGL: TA processes
        5.1: ['STA'],  # Review: Application Criteria review - STA processes
        6.0: ['TAO'],  # Peer Review-Criteria Review - TAO processes
        6.1: ['STA'],  # Peer review Committee -Criteria Report - STA processes
        7.0: ['TGL: TA'],  # Approval - Application Criteria Report - TGL: TA processes
        8.0: ['TGL: TA'],  # Allocation: Preparation: Assessment Work Offer - TGL:TA processes
        8.1: ['STA'],  # Preparation: Assessment Work Offer - STA processes
        8.2: ['TAO'],  # Peer Review-Draft Assessment Work Offer - TAO processes
        8.3: ['STA'],  # Peer Committee-Draft Assessment Work Offer - STA processes
        8.4: ['TGL: TA'],  # Review: Approval Submission - TGL:TA processes
        9.0: ['EMTS'],  # Approval: Assessment work offer - EMTS processes
        10.0: ['TAO'],  # Dispatched Assessment work offer - TAO processes
        11.0: ['TAO'],  # Client Response - TAO processes (with client)
        11.1: ['TAO'],  # Review: Client Response - TAO processes (with client)
        12.0: ['TAO'],  # Evaluation Fee Request - TAO processes
        13.0: ['Finance'],  # Evaluation Invoice Generation - Finance processes
        13.1: ['TAO'],  # Confirmation of Invoice - TAO processes
        13.2: ['TAO', 'Finance'],  # Evaluation fee-Proof of Payment - Notify TAO Group and Finance Group
        13.3: ['Finance'],  # Payment Confirmation - Finance Group processes
        14.0: ['TGL: TA'],  # Project Allocation - TGL: TA processes
        14.1: ['STA', 'PL'],  # Project Assessment - STA & Project Leader process
        14.11: ['PL'],  # Draft Project Management Plan - Project Leader processes
        14.12: ['PL'],  # Approved Project Management Plan - Project Leader processes
        14.13: ['TGL: TA', 'STA'],  # Review Project Submission - TGL:TA & STA process
        15.0: ['TAO'],  # Peer Review-Draft Certificate - TAO processes
        15.1: ['PL'],  # Peer review Committee -Draft Certificate - Project Leader processes
        15.2: ['TGL: TA', 'STA'],  # Final Review: Assessment Management - TGL: TA & STA process
        15.3: ['TGL: TA'],  # Review: EMTS - TGL: TA processes
        16.0: ['EMTS', 'TAO'],  # TECO Submission - EMTS & TAO process
        16.1: ['SOB'],  # Review: TECO Approval - SOB processes
        17.0: ['SOB'],  # TECO Approval - SOB processes
        17.1: ['SOB'],  # Board Ratification - SOB processes
        17.2: ['SOB'],  # Review: Board Ratification - SOB processes
        18.0: ['PL'],  # Publish Certificate - PL processes
        18.1: ['TAO'],  # Website Upload Request & Gazette - TAO processes
        18.2: ['EMTS'],  # Approval: Publishing Requests - EMTS processes
        19.0: ['SOB'],  # Certificate Signing - SOB processes
        19.1: ['SOB'],  # Certificate Signing status - SOB processes
        19.2: ['TAO'],  # Dispatch signed certificate - TAO processes
        20.0: ['PL'],  # Project Closure - Project Leader processes
        20.1: ['PL'],  # Project Closeout report - Project Leader processes
        20.2: ['TGL: TA'],  # Approve Project Closure - TGL:TA processes
        23.0: [],  # Completed - No group needed
    }



    try:
        for stage_number, group_names in stage_assignments.items():
            stage = Stage.query.filter_by(stage_number=stage_number).first()
            if stage:
                for group_name in group_names:
                    group = Group.query.filter_by(name=group_name).first()
                    if group:
                        # Check if assignment already exists
                        existing = StageGroupAssignment.query.filter_by(
                            stage_id=stage.id,
                            group_id=group.id
                        ).first()

                        if not existing:
                            assignment = StageGroupAssignment(
                                stage_id=stage.id,
                                group_id=group.id
                            )
                            db.session.add(assignment)
                            logger.info(f'Assigned {group_name} to stage {stage_number}: {stage.name}')

        db.session.commit()
        logger.info('Stage group assignments created successfully')

    except Exception as e:
        db.session.rollback()
        logger.error(f'Error creating stage assignments: {e}')
        raise
def create_initial_data():
    """Create initial system data with updated groups"""
    try:
        # Create admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@certmanagement.com',
                first_name='System',
                last_name='Administrator',
                is_internal=True,
                is_active=True
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)

        groups_data = [
            ('Administrators', 'System administrators with full access'),
            ('TAO', 'Technical Assessment Officers'),
            ('Finance', 'Finance Department'),
            ('TGL: TA', 'Technical Group Leader: Technical Assessment'),
            ('STA', 'Senior Technical Assessor'),
            ('EMTS', 'Engineering Management and Technical Services'),
            ('TECO', 'Technical Committee'),
            ('Board', 'Board of Directors'),
            ('Board Chairperson', 'Board Chairperson'),
            ('PL', 'Project Leader'),
            ('Client & TAO', 'Client and Technical Assessment Officers'),
            ('TAO & Finance', 'Technical Assessment Officers and Finance'),
            ('STA & Project Leader', 'Senior Technical Assessor and Project Leader'),
            ('SOB', 'Senior Operations Board'),
            ('OCEO', 'Office of Chief Executive Officer'),
            ('Technical Services', 'Technical Services Department'),
            ('Drawing Office', 'Drawing Office Team'),
            ('TA', 'Technical Assessor'),
            # Additional groups needed for your workflow specification
            ('TAO Group', 'Technical Assessment Office Group'),
            ('Finance Group', 'Finance Department Group'),
            ('TGL: TA Group', 'Technical Group Leader: Technical Assessment Group'),
            ('STA Group', 'Senior Technical Assessor Group'),
            ('Technical Services Group', 'Technical Services Department Group'),
            ('EMTS Group', 'Engineering Management and Technical Services Group'),
            ('TECO Group', 'Technical Committee Group'),
            ('Board Group', 'Board of Directors Group'),
            ('Board Chairperson Group', 'Board Chairperson Group'),
            ('Project Leader Group', 'Project Leader Group'),
        ]

        for group_name, description in groups_data:
            group = Group.query.filter_by(name=group_name).first()
            if not group:
                group = Group(name=group_name, description=description)
                db.session.add(group)

        db.session.flush()

        # Assign admin to administrators group
        admin_group = Group.query.filter_by(name='Administrators').first()
        assignment = UserGroupAssignment.query.filter_by(
            user_id=admin_user.id, group_id=admin_group.id
        ).first()
        if not assignment:
            assignment = UserGroupAssignment(
                user_id=admin_user.id,
                group_id=admin_group.id,
                assigned_by_user_id=admin_user.id
            )
            db.session.add(assignment)

        # Create users
        users_data = [
            ('TAO', 'Thabang', 'Motlanthe', 'Tmotlanthe@agrement.co.za'),
            ('TAO', 'Kamogelo', 'Makutu', 'Kmakutu@agrement.co.za'),
            ('TGL: TA', 'Lennox', 'Makwedini', 'LMakwedini@agrement.co.za'),
            ('Technical Services', 'Dominique', 'Geszler', 'Dgeszler@agrement.co.za'),
            ('STA', 'Samuel', 'Skosana', 'Sskosana@agrement.co.za'),
            ('STA', 'Sibusisiwe', 'Ndamashe', 'Sndamashe@agrement.co.za'),
            ('TA', 'Anga', 'Tintelo', 'ATintelo@agrement.co.za'),
            ('TA', 'Zanele', 'Nkosi', 'ZNkosi@agrement.co.za'),
            ('TA', 'Emily', 'Moloto', 'EMoloto@agrement.co.za'),
            ('TA', 'Sakiwo', 'Silingo', 'SSilingo@agrement.co.za'),
            ('TA', 'Orefilethato', 'Ramantsi', 'ORamantsi@agrement.co.za'),
            ('TA', 'Thulani', 'Zama', 'TZama@agrement.co.za'),
            ('Drawing Office', 'Lebabo', 'Majoro', 'LMajoro@agrement.co.za'),
            ('EMTS', 'Lindelani', 'Mulaudzi', 'LMulaudzi@agrement.co.za'),
            ('SOB', 'Ramona', 'Singh', 'RSingh@agrement.co.za'),
            ('Finance', 'Khathu', 'Madzivha', 'kmadzivha@agrement.co.za')
        ]

        for designation, first_name, last_name, email in users_data:
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(
                    username=email.split('@')[0],
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    is_internal=True,
                    is_active=True
                )
                user.set_password('default123')  # Default password
                db.session.add(user)
                db.session.flush()

            group = Group.query.filter_by(name=designation).first()
            if group:
                assignment = UserGroupAssignment.query.filter_by(
                    user_id=user.id, group_id=group.id
                ).first()
                if not assignment:
                    assignment = UserGroupAssignment(
                        user_id=user.id,
                        group_id=group.id,
                        assigned_by_user_id=admin_user.id
                    )
                    db.session.add(assignment)

        # Workflow stages
        stages_data = [
            (1.0, 'New Application', False, 'Initial application submission received'),
            (2.0, 'Verification of Application Completeness', False, 'Initial completeness review'),
            (3.0, 'Admin Fee Request', False, 'Processing application fees'),
            (4.0, 'Invoice Generation', False, 'Invoice creation process'),
            (4.1, 'Admin fee-Proof of Payment', False, 'Payment proof upload'),
            (4.2, 'Payment Confirmation', False, 'Payment verification'),
            (5.0, 'Allocation: Criteria Review', False, 'Criteria allocation review'),
            (5.1, 'Review: Application Criteria review', False, 'Application criteria evaluation'),
            (6.0, 'Peer Review-Criteria Review', False, 'Peer review of criteria'),
            (6.1, 'Peer review Committee -Criteria Report', False, 'Committee criteria report review'),
            (7.0, 'Approval - Application Criteria Report', False, 'Criteria report approval'),
            (8.0, 'Preparation: Assessment Work Offer (AWO)', False, 'AWO preparation'),
            (8.1, 'Peer Review-Draft Assessment Work Offer', False, 'Peer review of draft AWO'),
            (8.2, 'Peer Committee-Draft Assessment Work Offer', False, 'Committee review of draft AWO'),
            (8.3, 'Review: Approval Submission', False, 'Approval submission review'),
            (8.4, 'Approval: Assessment work offer', False, 'AWO approval'),
            (9.0, 'Dispatched Assessment work offer', False, 'AWO dispatch'),
            (10.0, 'Client Response', False, 'Client response to AWO'),
            (10.1, 'Review: Client Response', False, 'Client response review'),
            (11.0, 'Evaluation Fee Request', False, 'Evaluation fee request'),
            (12.0, 'Invoice Generation', False, 'Evaluation invoice generation'),
            (12.1, 'Evaluation fee-Proof of Payment', False, 'Evaluation payment proof'),
            (12.2, 'Payment Confirmation', False, 'Evaluation payment confirmation'),
            (13.0, 'Project Allocation', False, 'Project resource allocation'),
            (13.1, 'Project Assessment', False, 'Project assessment execution'),
            (14.2, 'Draft Project Management Plan', False, 'Draft project plan creation'),
            (14.3, 'Draft Project Management Plan', False, 'Project plan review'),
            (14.4, 'Approved Project Management Plan (PCM)', False, 'Final project plan approval'),
            (15.0, 'Peer Review-Draft Certificate', False, 'Certificate peer review'),
            (15.1, 'Peer review Committee -Draft Certificate', False, 'Committee certificate review'),
            (15.2, 'Final Review: Assessment Management', False, 'Assessment management review'),
            (15.3, 'Review: EMTS', False, 'EMTS review'),
            (16.0, 'TECO Submission', False, 'TECO submission'),
            (16.1, 'Review: TECO Approval', False, 'TECO approval review'),
            (17.0, 'TECO Approval', False, 'TECO final approval'),
            (17.1, 'Board Ratification', False, 'Board ratification submission'),
            (17.2, 'Review: Board Ratification', False, 'Board ratification review'),
            (18.0, 'Publish Certificate. Triggered by 17.1 positive outcome (Ratified)', False, 'Certificate publication'),
            (18.1, 'Website Upload Request & Gazette', False, 'Website and gazette upload'),
            (18.2, 'Approval: Publishing Requests', False, 'Publishing approval'),
            (19.0, 'Certificate Signing. Triggered by 17.1 positive outcome (Ratified)', False, 'Certificate signing'),
            (19.1, 'Certificate Signing status', False, 'Signing status update'),
            (19.2, 'Dispatch signed certificate', False, 'Certificate dispatch'),
            (20.0, 'Project Closure', False, 'Project closure initiation'),
            (20.1, 'Project Closeout report', False, 'Project closeout report'),
            (20.2, 'Approve Project Closure', False, 'Final project closure approval'),
            (23.0, 'Completed', False, 'Application completed'),
        ]

        for stage_number, name, is_review, description in stages_data:
            stage = Stage.query.filter_by(stage_number=stage_number).first()
            if not stage:
                stage = Stage(
                    stage_number=stage_number,
                    name=name,
                    is_review_stage=is_review,
                    description=description
                )
                db.session.add(stage)

        db.session.commit()

        # Stage group assignment
        create_stage_group_assignments()

        # Notification signature
        signature = NotificationSignature.query.filter_by(is_active=True).first()
        if not signature:
            signature = NotificationSignature(
                company_name='Certificate Management System',
                email='techassess@lis-demos.co.za',
                phone='+27 (0) 11 000 0000',
                website='https://www.certmanagement.com',
                address='123 Business Street, Johannesburg, South Africa',
                signature_text='Professional certification services',
                is_active=True
            )
            db.session.add(signature)

        db.session.commit()

        # Update existing certificates
        certificates_without_status = Certificate.query.filter_by(status=None).all()
        for cert in certificates_without_status:
            cert.status = 'Active'

        db.session.commit()
        logger.info('Initial data created successfully')

    except Exception as e:
        db.session.rollback()
        logger.error(f'Error creating initial data: {e}')
        raise




def create_sample_applications():
    """Create sample applications for testing"""
    try:
        # Create sample company
        company = Company.query.filter_by(name='Sample Corporation Ltd').first()
        if not company:
            company = Company(
                name='Sample Corporation Ltd',
                registration_number='REG123456',
                email='info@samplecorp.com',
                phone='+1-555-0123',
                address='456 Corporate Ave, Business District',
                website='https://www.samplecorp.com',
                contact_person='John Smith'
            )
            db.session.add(company)
            db.session.flush()

        # Get first stage
        first_stage = Stage.query.filter_by(stage_number=1.0).first()

        if first_stage:
            # Create sample applications
            sample_apps = [
                {
                    'applicant_name': 'John Smith',
                    'applicant_email': 'john.smith@samplecorp.com',
                    'applicant_phone': '+1-555-0123',
                    'certificate_type': 'Cold Mix Asphalt'
                },
                {
                    'applicant_name': 'Jane Doe',
                    'applicant_email': 'jane.doe@example.com',
                    'applicant_phone': '+1-555-0456',
                    'certificate_type': 'Waterproofing'
                },
                {
                    'applicant_name': 'Bob Johnson',
                    'applicant_email': 'bob.johnson@testcorp.com',
                    'applicant_phone': '+1-555-0789',
                    'certificate_type': 'Traffic Monitoring Systems'
                }
            ]

            for app_data in sample_apps:
                # Check if application already exists
                existing = Application.query.filter_by(
                    applicant_email=app_data['applicant_email']
                ).first()

                if not existing:
                    application = Application(
                        applicant_name=app_data['applicant_name'],
                        applicant_email=app_data['applicant_email'],
                        applicant_phone=app_data['applicant_phone'],
                        company_id=company.id,
                        certificate_type=app_data['certificate_type'],
                        current_stage_id=first_stage.id,
                        status='Submitted'
                    )
                    application.generate_application_number()
                    db.session.add(application)

        db.session.commit()
        logger.info('Sample applications created successfully')

    except Exception as e:
        db.session.rollback()
        logger.error(f'Error creating sample applications: {e}')
        raise

def reset_database():
    """Reset database - USE WITH CAUTION"""
    try:
        # Drop all tables
        db.drop_all()

        # Create all tables
        db.create_all()

        # Create initial data
        create_initial_data()

        logger.info('Database reset successfully')

    except Exception as e:
        logger.error(f'Error resetting database: {e}')
        raise

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

if __name__ == '__main__':
    with app.app_context():
        try:
            create_initial_data()
            logger.info('Application startup completed successfully')
        except Exception as e:
            logger.error(f'Startup error: {e}')

    # Use the PORT Render provides, fallback to 5000 for local testing
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, use_reloader=False)
