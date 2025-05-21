from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, abort
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, text
import os
import pandas as pd
from werkzeug.utils import secure_filename
import datetime
import logging
import re
import json
import bcrypt
from typing import Tuple, Optional, Set, Dict, List
from pandas import ExcelWriter
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

# SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'csv', 'xlsx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Model Classes
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def __init__(self, username, full_name, password, role):
        self.username = username
        self.full_name = full_name
        self.password = password
        self.role = role

class Client(db.Model):
    __tablename__ = 'clients'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    details = db.Column(db.Text)
    files = db.relationship('File', backref='client', lazy=True)
    leads_files = db.relationship('LeadsFile', backref='client', lazy=True)
    used_leads = db.relationship('UsedLead', backref='client', lazy=True)

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    output_filename = db.Column(db.String(255))
    upload_date = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    suppression_number = db.Column(db.Integer)
    unique_count = db.Column(db.Integer, default=0)
    duplicate_count = db.Column(db.Integer, default=0)
    total_checked = db.Column(db.Integer, default=0)
    unique_before_merge = db.Column(db.Integer, default=0)
    unique_after_merge = db.Column(db.Integer, default=0)
    duplicates_removed = db.Column(db.Integer, default=0)

class UsedLead(db.Model):
    __tablename__ = 'used_leads'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    added_date = db.Column(db.String(50))
    __table_args__ = (db.UniqueConstraint('client_id', 'phone', name='uix_client_phone'),)

class LeadsFile(db.Model):
    __tablename__ = 'leads_files'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    data_filename = db.Column(db.String(255), nullable=False)
    output_filename = db.Column(db.String(255))
    upload_date = db.Column(db.String(50))
    total_phones = db.Column(db.Integer, default=0)
    unique_leads = db.Column(db.Integer, default=0)
    suppression_number = db.Column(db.Integer)
    lead_number = db.Column(db.Integer)
    revenue_filter = db.Column(db.String(50))
    number_type_filter = db.Column(db.String(50))
    email_filter = db.Column(db.Boolean)
    lead_quantity = db.Column(db.Integer)
    custom_filters = db.Column(db.Text)

class DataFile(db.Model):
    __tablename__ = 'data_files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.String(50))

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        # Create index for used_leads
        try:
            db.engine.execute('CREATE INDEX IF NOT EXISTS idx_used_leads_phone ON used_leads (client_id, phone)')
        except Exception as e:
            logger.warning(f"Index creation skipped: {str(e)}")
        # Insert default admin user if none exists
        if not User.query.filter_by(role='admin').first():
            default_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            admin = User(
                username='admin',
                full_name='Administrator',
                password=default_password,
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()

init_db()

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Error handler for file size limit
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'status': 'error', 'message': 'File too large. Maximum size allowed is 100MB.'}), 413

# Input validation
def validate_password(password: str) -> bool:
    return len(password) >= 8 and re.search(r'[A-Za-z0-9@#$%^&+=]', password)

def sanitize_input(value: str) -> str:
    return re.sub(r'[^\w\s]', '', value.strip())

# Helper functions
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def number_to_ordinal(n: int) -> str:
    ordinals = {1: 'first', 2: 'second', 3: 'third', 4: 'fourth', 5: 'fifth',
                6: 'sixth', 7: 'seventh', 8: 'eighth', 9: 'ninth', 10: 'tenth'}
    return ordinals.get(n, f"{n}th")

def batch_insert_unique_phones(client_id: int, unique_phones: List[str]):
    batch_size = 10000
    current_time = datetime.datetime.now().isoformat()
    for i in range(0, len(unique_phones), batch_size):
        batch = unique_phones[i:i + batch_size]
        for phone in batch:
            try:
                lead = UsedLead(client_id=client_id, phone=phone, added_date=current_time)
                db.session.add(lead)
            except IntegrityError:
                db.session.rollback()
                continue
        db.session.commit()
        logger.info(f"Inserted batch of {len(batch)} phones for client {client_id}")

def suppress_leads(input_dfs: List[pd.DataFrame], used_numbers: Set[str], suppression_number: int) -> Tuple[Optional[pd.DataFrame], str, List[Dict[str, int]], Dict[str, int]]:
    try:
        file_metrics = []
        all_phones = []
        total_checked = 0
        unique_before_merge = 0

        for idx, df in enumerate(input_dfs):
            logger.info(f"Processing file {idx + 1} with {len(df)} rows")
            phone_col = None
            for col in df.columns:
                if col.lower() in ['phone', 'mobile']:
                    phone_col = col
                    break
            if phone_col is None:
                logger.warning(f"File {idx + 1}: Skipped - No 'Phone' or 'Mobile' column")
                file_metrics.append({'unique_count': 0, 'duplicate_count': 0})
                all_phones.append(pd.DataFrame())
                continue

            df = df[[phone_col]].copy()

            def clean_phone(phone: str) -> str:
                if pd.isna(phone):
                    return ''
                return re.sub(r'\D', '', str(phone)).strip()

            def is_valid_phone(phone: str) -> bool:
                return bool(phone and 7 <= len(phone) <= 15)

            df['cleaned_phone'] = df[phone_col].apply(clean_phone)
            df['is_valid'] = df['cleaned_phone'].apply(is_valid_phone)

            invalid_phones = df[~df['is_valid']][phone_col].tolist()
            if invalid_phones:
                logger.warning(f"File {idx + 1}: Invalid phone numbers: {invalid_phones[:10]}")

            valid_df = df[df['is_valid']].copy()
            if valid_df.empty:
                logger.warning(f"File {idx + 1}: Skipped - No valid phone numbers")
                file_metrics.append({'unique_count': 0, 'duplicate_count': 0})
                all_phones.append(pd.DataFrame())
                continue

            total_checked += len(valid_df)
            valid_df = valid_df[[phone_col, 'cleaned_phone']].rename(columns={phone_col: 'phone'})
            valid_df = valid_df.drop_duplicates(subset='cleaned_phone')
            logger.info(f"File {idx + 1}: {len(valid_df)} valid unique phones after intra-file deduplication")
            unique_before_merge += len(valid_df)

            valid_df['status'] = valid_df['cleaned_phone'].apply(
                lambda x: 'duplicate' if x in used_numbers else 'unique'
            )
            unique_count = len(valid_df[valid_df['status'] == 'unique'])
            duplicate_count = len(valid_df[valid_df['status'] == 'duplicate'])
            file_metrics.append({'unique_count': unique_count, 'duplicate_count': duplicate_count})
            logger.info(f"File {idx + 1}: {unique_count} uniques, {duplicate_count} duplicates")

            all_phones.append(valid_df)

        if not any(not df.empty for df in all_phones):
            logger.error("No valid phone numbers found in any input file")
            return None, 'failed', file_metrics, {'total_checked': total_checked}

        logger.info(f"Merging {len(all_phones)} files for suppression {suppression_number}")
        combined_df = pd.concat(all_phones, ignore_index=True)
        logger.info(f"Total phones before cross-file deduplication: {len(combined_df)}")

        if combined_df.empty:
            logger.error("No valid phone numbers after combining")
            return None, 'failed', file_metrics, {'total_checked': total_checked}

        combined_df = combined_df.drop_duplicates(subset='cleaned_phone')
        logger.info(f"Total phones after cross-file deduplication: {len(combined_df)}")

        combined_df['status'] = combined_df['cleaned_phone'].apply(
            lambda x: 'duplicate' if x in used_numbers else 'unique'
        )
        unique_after_merge = len(combined_df[combined_df['status'] == 'unique'])
        duplicates_removed = unique_before_merge - len(combined_df)
        logger.info(f"Suppression {suppression_number}: {unique_after_merge} uniques, "
                    f"{len(combined_df) - unique_after_merge} duplicates in output, "
                    f"{duplicates_removed} duplicates removed after merge")

        output_df = combined_df[['phone', 'status']].copy()
        summary_metrics = {
            'total_checked': total_checked,
            'unique_before_merge': unique_before_merge,
            'unique_after_merge': unique_after_merge,
            'duplicates_removed': duplicates_removed
        }
        return output_df, 'completed', file_metrics, summary_metrics
    except Exception as e:
        logger.error(f"Error in suppression {suppression_number}: {str(e)}")
        return None, 'failed', file_metrics, {'total_checked': total_checked}

def get_suppression_number(client_id: int) -> int:
    max_number = db.session.query(func.max(File.suppression_number)).filter_by(client_id=client_id).scalar()
    return (max_number or 0) + 1

def get_lead_number(client_id: int) -> int:
    max_number = db.session.query(func.max(LeadsFile.lead_number)).filter_by(client_id=client_id).scalar()
    return (max_number or 0) + 1

def get_previous_suppression_numbers(client_id: int) -> Set[str]:
    used_numbers = set()
    files = File.query.filter_by(client_id=client_id, status='completed').all()
    for file in files:
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], file.output_filename)
        if os.path.exists(output_path):
            try:
                if file.output_filename.endswith('.csv'):
                    df = pd.read_csv(output_path, usecols=['phone', 'status'])
                else:
                    df = pd.read_excel(output_path, engine='openpyxl', usecols=['phone', 'status'])
                if 'phone' in df.columns:
                    unique_phones = df[df['status'] == 'unique']['phone'].apply(
                        lambda x: re.sub(r'\D', '', str(x)).strip()
                    ).tolist()
                    used_numbers.update(unique_phones)
                    logger.info(f"Loaded {len(unique_phones)} unique phones from {file.output_filename}")
            except Exception as e:
                logger.error(f"Error reading previous suppression file {file.output_filename}: {str(e)}")
    logger.info(f"Total prior unique phones for client {client_id}: {len(used_numbers)}")
    return used_numbers

def get_latest_suppression(client_id: int) -> Optional[Tuple[str, int]]:
    latest_file = File.query.filter_by(client_id=client_id, status='completed').order_by(File.suppression_number.desc()).first()
    if latest_file:
        return latest_file.output_filename, latest_file.suppression_number
    return None

def get_data_file() -> Optional[Tuple[str, str]]:
    latest_data_file = DataFile.query.order_by(DataFile.upload_date.desc()).first()
    if latest_data_file:
        return latest_data_file.filename, latest_data_file.upload_date
    return None

#everything is perfect now. 

def generate_leads(
    data_file_path: str,
    client_id: int,
    client_name: str,
    revenue_filter: Optional[str] = None,
    number_type_filter: Optional[str] = None,
    email_filter: bool = False,
    lead_quantity: Optional[int] = None,
    custom_filters: Optional[List[Dict]] = None
) -> Tuple[Optional[str], str, Dict[str, any]]:
    try:
        # Check if any filters are applied
        no_filters = not any([revenue_filter, number_type_filter, email_filter, custom_filters, lead_quantity])
        
        # Determine columns to load based on filters
        if no_filters:
            usecols = None
            output_columns = None
        else:
            usecols = ['Phone', 'Mobile']
            output_columns = [col for col in usecols]
            if revenue_filter:
                usecols.append('Revenue')
                output_columns.append('Revenue')
            if number_type_filter:
                usecols.append('NumberType')
                output_columns.append('NumberType')
            if email_filter:
                usecols.append('Email')
                output_columns.append('Email')
            if custom_filters:
                for custom_filter in custom_filters:
                    column = custom_filter.get('column')
                    if column and column not in usecols:
                        usecols.append(column)
                        output_columns.append(column)

        # Load the data file
        if data_file_path.endswith('.xlsx'):
            df = pd.read_excel(data_file_path, engine='openpyxl', usecols=usecols)
        else:
            chunks = pd.read_csv(data_file_path, chunksize=10000, usecols=usecols)
            df = pd.concat(chunks, ignore_index=True)
        logger.info(f"Loaded data file: {data_file_path} with {len(df)} rows and columns: {df.columns.tolist()}")

        # Identify phone and filter-related columns
        phone_col = None
        revenue_col = None
        number_type_col = None
        email_col = None
        for col in df.columns:
            if col.lower() in ['phone', 'mobile']:
                phone_col = col
            elif 'revenue' in col.lower():
                revenue_col = col
            elif 'numbertype' in col.lower():
                number_type_col = col
            elif 'email' in col.lower():
                email_col = col
        if phone_col is None:
            logger.error("No 'Phone' or 'Mobile' column found in data file")
            return None, 'failed', {'total_phones': 0, 'unique_leads': 0}

        # Clean and validate phone numbers
        def clean_phone(phone: str) -> str:
            if pd.isna(phone):
                return ''
            return re.sub(r'\D', '', str(phone)).strip()

        def is_valid_phone(phone: str) -> bool:
            return bool(phone and 7 <= len(phone) <= 15)

        df['cleaned_phone'] = df[phone_col].apply(clean_phone)
        df['is_valid'] = df['cleaned_phone'].apply(is_valid_phone)

        valid_df = df[df['is_valid']].copy()
        total_phones = len(valid_df)
        if valid_df.empty:
            logger.error("No valid phone numbers in data file")
            return None, 'failed', {'total_phones': 0, 'unique_leads': 0}

        # Load latest suppression file
        latest_suppression = get_latest_suppression(client_id)
        if not latest_suppression:
            logger.error(f"No completed suppressions found for client {client_id}")
            return None, 'failed', {'total_phones': total_phones, 'unique_leads': 0}

        suppression_filename, suppression_number = latest_suppression
        suppression_path = os.path.join(app.config['UPLOAD_FOLDER'], suppression_filename)
        if not os.path.exists(suppression_path):
            logger.error(f"Suppression file {suppression_filename} not found")
            return None, 'failed', {'total_phones': total_phones, 'unique_leads': 0}

        if suppression_filename.endswith('.csv'):
            suppression_df = pd.read_csv(suppression_path, usecols=['phone', 'status'])
        else:
            suppression_df = pd.read_excel(suppression_path, engine='openpyxl', usecols=['phone', 'status'])
        suppression_phones = set(
            suppression_df[suppression_df['status'] == 'unique']['phone'].apply(
                lambda x: re.sub(r'\D', '', str(x)).strip()
            ).tolist()
        )
        logger.info(f"Loaded {len(suppression_phones)} unique phones from suppression {suppression_filename}")

        # Apply suppression
        valid_df['is_lead'] = valid_df['cleaned_phone'].apply(lambda x: x not in suppression_phones)
        leads_df = valid_df[valid_df['is_lead']].copy()

        # Apply filters if any
        if revenue_filter and revenue_col:
            if revenue_filter == 'full':
                leads_df = leads_df[leads_df[revenue_col].notna() & (leads_df[revenue_col] != 0)]
                logger.info(f"Applied 'full' revenue filter: {len(leads_df)} leads remaining")
            elif revenue_filter == '100k+':
                leads_df = leads_df[leads_df[revenue_col] >= 100000]
                logger.info(f"Applied '100k+' revenue filter: {len(leads_df)} leads remaining")

        if number_type_filter == 'mobile' and number_type_col:
            leads_df = leads_df[leads_df[number_type_col].str.lower() == 'mobile']
            logger.info(f"Applied 'mobile' number type filter: {len(leads_df)} leads remaining")

        if email_filter and email_col:
            def is_valid_email(email: str) -> bool:
                if pd.isna(email):
                    return False
                return bool(re.match(r'[^@]+@[^@]+\.[^@]+', str(email)))
            leads_df = leads_df[leads_df[email_col].apply(is_valid_email)]
            logger.info(f"Applied valid email filter: {len(leads_df)} leads remaining")

        if custom_filters:
            for custom_filter in custom_filters:
                column = custom_filter.get('column')
                condition = custom_filter.get('condition')
                value = custom_filter.get('value')
                if column not in leads_df.columns:
                    logger.warning(f"Custom filter column {column} not found")
                    continue
                try:
                    if condition == '==':
                        leads_df = leads_df[leads_df[column] == value]
                    elif condition == '>':
                        leads_df = leads_df[leads_df[column] > float(value)]
                    elif condition == '<':
                        leads_df = leads_df[leads_df[column] < float(value)]
                    elif condition == 'contains':
                        leads_df = leads_df[leads_df[column].str.contains(value, case=False, na=False)]
                    logger.info(f"Applied custom filter {column} {condition} {value}: {len(leads_df)} leads remaining")
                except Exception as e:
                    logger.error(f"Error applying custom filter {column} {condition} {value}: {str(e)}")
                    continue

        unique_leads = len(leads_df)
        if unique_leads == 0:
            logger.info("No unique leads found after filtering")
            return None, 'completed', {
                'total_phones': total_phones,
                'unique_leads': 0,
                'suppression_number': suppression_number
            }

        # Apply lead quantity limit
        if lead_quantity and lead_quantity < unique_leads:
            sort_col = revenue_col if revenue_filter and revenue_col else phone_col
            leads_df = leads_df.sort_values(by=sort_col, ascending=False)
            leads_df = leads_df.head(lead_quantity)
            unique_leads = len(leads_df)
            logger.info(f"Selected top {lead_quantity} leads: {unique_leads} leads remaining")

        # Select output columns
        if not no_filters and output_columns:
            if phone_col not in output_columns:
                output_columns.append(phone_col)
            output_columns = [col for col in output_columns if col in leads_df.columns]
            leads_df = leads_df[output_columns]
            logger.info(f"Output columns with filters: {output_columns}")
        else:
            logger.info(f"Output includes all columns: {leads_df.columns.tolist()}")

        # Generate output file
        lead_number = get_lead_number(client_id)
        output_filename = f"lead{lead_number}_{client_name}.xlsx"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        # Remove temporary columns
        columns_to_drop = ['cleaned_phone', 'is_valid', 'is_lead']
        leads_df = leads_df.drop(columns=[col for col in columns_to_drop if col in leads_df.columns], errors='ignore')

        # Save output
        max_excel_rows = 1048576
        if len(leads_df) > max_excel_rows:
            output_filename = f"lead{lead_number}_{client_name}.csv"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            leads_df.to_csv(output_path, index=False)
            logger.info(f"Saved leads output as CSV: {output_filename} with {unique_leads} rows")
        else:
            with ExcelWriter(output_path, engine='openpyxl') as writer:
                leads_df.to_excel(writer, index=False)
            logger.info(f"Saved leads output as Excel: {output_filename} with {unique_leads} rows")

        return output_filename, 'completed', {
            'total_phones': total_phones,
            'unique_leads': unique_leads,
            'suppression_number': suppression_number,
            'lead_number': lead_number,
            'revenue_filter': revenue_filter,
            'number_type_filter': number_type_filter,
            'email_filter': email_filter,
            'lead_quantity': lead_quantity,
            'custom_filters': json.dumps(custom_filters) if custom_filters else None
        }
    except Exception as e:
        logger.error(f"Error generating leads: {str(e)}")
        return None, 'failed', {'total_phones': 0, 'unique_leads': 0}

def process_suppression(file_paths: List[str], client_id: int, suppression_number: int) -> Tuple[Optional[str], str, List[Dict[str, int]], Dict[str, int]]:
    try:
        input_dfs = []
        for idx, file_path in enumerate(file_paths):
            try:
                if file_path.endswith('.csv'):
                    chunk_size = 10000
                    chunks = pd.read_csv(file_path, chunksize=chunk_size, usecols=lambda x: x.lower() in ['phone', 'mobile'])
                    df_chunks = []
                    for chunk in chunks:
                        df_chunks.append(chunk)
                    if df_chunks:
                        df = pd.concat(df_chunks, ignore_index=True)
                    else:
                        df = pd.DataFrame()
                else:
                    df = pd.read_excel(file_path, engine='openpyxl', usecols=lambda x: x.lower() in ['phone', 'mobile'])
                    if df.empty:
                        df = pd.DataFrame()
                input_dfs.append(df)
                logger.info(f"Loaded file {idx + 1}: {file_path} with {len(df)} rows")
            except Exception as e:
                logger.warning(f"Skipping file {file_path}: {str(e)}")
                input_dfs.append(pd.DataFrame())
                continue

        if not any(not df.empty for df in input_dfs):
            logger.error("No valid files to process")
            return None, 'failed', [{'unique_count': 0, 'duplicate_count': 0}] * len(file_paths), {'total_checked': 0}

        used_numbers = get_previous_suppression_numbers(client_id)
        output_df, status, file_metrics, summary_metrics = suppress_leads(input_dfs, used_numbers, suppression_number)
        if output_df is None or output_df.empty:
            logger.error(f"Suppression {suppression_number} failed: No valid output generated")
            return None, 'failed', file_metrics, summary_metrics

        logger.info(f"Output DataFrame has {len(output_df)} rows and columns: {output_df.columns.tolist()}")
        if not all(col in output_df.columns for col in ['phone', 'status']):
            logger.error(f"Suppression {suppression_number} failed: Output DataFrame missing required columns")
            return None, 'failed', file_metrics, summary_metrics

        max_excel_rows = 1048576
        output_filename = f"{number_to_ordinal(suppression_number)}_suppression"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        
        if len(output_df) > max_excel_rows:
            output_filename += '.csv'
            output_path += '.csv'
            output_df.to_csv(output_path, index=False)
            logger.info(f"Saved output as CSV: {output_filename} with {len(output_df)} rows")
        else:
            output_filename += '.xlsx'
            output_path += '.xlsx'
            chunk_size = max_excel_rows - 1
            with ExcelWriter(output_path, engine='openpyxl') as writer:
                for i in range(0, len(output_df), chunk_size):
                    chunk = output_df[i:i + chunk_size]
                    sheet_name = f'Suppression_{i // chunk_size + 1}'
                    chunk.to_excel(writer, index=False, sheet_name=sheet_name)
                    logger.info(f"Wrote sheet {sheet_name} with {len(chunk)} rows to {output_filename}")

        if not os.path.exists(output_path):
            logger.error(f"Suppression {suppression_number} failed: Output file {output_filename} was not created")
            return None, 'failed', file_metrics, summary_metrics

        logger.info(f"Saved output: {output_filename} with {len(output_df)} rows")

        unique_phones = output_df[output_df['status'] == 'unique']['phone'].apply(
            lambda x: re.sub(r'\D', '', str(x)).strip()
        ).tolist()
        if unique_phones:
            batch_insert_unique_phones(client_id, unique_phones)

        return output_filename, status, file_metrics, summary_metrics
    except Exception as e:
        logger.error(f"Error processing suppression {suppression_number}: {str(e)}")
        return None, 'failed', [{'unique_count': 0, 'duplicate_count': 0}] * len(file_paths), {'total_checked': 0}

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_portal'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        logger.info(f"Login attempt for username: {username}")
        user = User.query.filter_by(username=username).first()
        if user:
            stored_password = user.password if isinstance(user.password, bytes) else user.password.encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                login_user(user)
                logger.info(f"Login successful for username: {username}, role: {user.role}")
                flash('Login successful!', 'success')
                if user.role == 'admin':
                    return redirect(url_for('admin_portal'))
                return redirect(url_for('dashboard'))
            else:
                logger.warning(f"Invalid password for username: {username}")
                flash('Invalid username or password', 'error')
        else:
            logger.warning(f"Username not found: {username}")
            flash('Invalid username or password', 'error')
        return redirect(url_for('login'))
    return render_template('login.html', csrf_token=generate_csrf())

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User {current_user.username} logged out")
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not all([current_password, new_password, confirm_password]):
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400

    if new_password != confirm_password:
        return jsonify({'status': 'error', 'message': 'New passwords do not match'}), 400

    if not validate_password(new_password):
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long and contain letters, numbers, or special characters'}), 400

    user = User.query.get(current_user.id)
    stored_password = user.password if isinstance(user.password, bytes) else user.password.encode('utf-8')
    if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password):
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    user.password = hashed_password
    db.session.commit()

    logger.info(f"Password changed successfully for user: {current_user.username}")
    return jsonify({'status': 'success', 'message': 'Password changed successfully'})

@app.route('/dashboard')
@login_required
def dashboard():
    clients = Client.query.all()
    if current_user.role == 'admin':
        files = File.query.join(Client).all()
        leads_files = LeadsFile.query.join(Client).all()
    else:
        files = File.query.join(Client).all()
        leads_files = LeadsFile.query.join(Client).all()
    data_file = DataFile.query.order_by(DataFile.upload_date.desc()).first()

    # Convert File objects to dictionaries
    files_data = [
        {
            'id': f.id,
            'client_id': f.client_id,
            'client_name': f.client.name,  # Add client name
            'filename': f.filename,
            'output_filename': f.output_filename,
            'upload_date': f.upload_date,
            'status': f.status,
            'suppression_number': f.suppression_number,
            'unique_count': f.unique_count,
            'duplicate_count': f.duplicate_count,
            'total_phones_checked': f.total_checked,
            'unique_phones_before': f.unique_before_merge,
            'unique_phones_after': f.unique_after_merge,
            'duplicates_removed': f.duplicates_removed
        } for f in files
    ]

    # Convert LeadsFile objects to dictionaries
    leads_files_data = [
        {
            'id': lf.id,
            'client_id': lf.client_id,
            'client_name': lf.client.name,  # Add client name
            'data_filename': lf.data_filename,
            'output_filename': lf.output_filename,
            'upload_date': lf.upload_date,
            'total_phones': lf.total_phones,
            'unique_leads': lf.unique_leads,
            'suppression_number': lf.suppression_number,
            'lead_number': lf.lead_number,
            'revenue_filter': lf.revenue_filter,
            'number_type_filter': lf.number_type_filter,
            'email_filter': lf.email_filter,
            'lead_quantity': lf.lead_quantity,
            'custom_filters': lf.custom_filters
        } for lf in leads_files
    ]

    return render_template(
        'dashboard.html',
        clients=clients,
        files=files_data,
        leads_files=leads_files_data,
        data_file=data_file,
        csrf_token=generate_csrf()
    )

@app.route('/admin')
@admin_required
def admin_portal():
    users = User.query.all()
    clients = Client.query.all()
    return render_template('admin.html', users=users, clients=clients, csrf_token=generate_csrf())

@app.route('/add_user', methods=['POST'])
@admin_required
def add_user():
    try:
        logger.info(f"Received add_user request with form data: {request.form}")
        username = sanitize_input(request.form.get('username', ''))
        full_name = sanitize_input(request.form.get('full_name', ''))
        password = request.form.get('password', '')
        role = request.form.get('role', 'user')

        if not username or not full_name or not password:
            logger.warning("Missing required fields")
            return jsonify({'status': 'error', 'message': 'All fields are required'}), 400

        if role not in ['user', 'admin']:
            logger.warning(f"Invalid role: {role}")
            return jsonify({'status': 'error', 'message': 'Invalid role'}), 400

        if not validate_password(password):
            logger.warning("Password validation failed")
            return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long and contain letters, numbers, or special characters'}), 400

        if User.query.filter_by(username=username).first():
            logger.warning(f"Username already exists: {username}")
            return jsonify({'status': 'error', 'message': 'Username already exists'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(
            username=username,
            full_name=full_name,
            password=hashed_password,
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        logger.info(f"User {username} added successfully")
        return jsonify({'status': 'success', 'message': 'User added successfully'})
    except Exception as e:
        logger.error(f"Error in add_user: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Server error occurred'}), 500

@app.route('/add_client', methods=['POST'])
@login_required
def add_client():
    try:
        logger.info(f"Received add_client request with form data: {request.form}")
        name = sanitize_input(request.form.get('name', ''))
        details = request.form.get('details', '')

        if not name:
            logger.warning("Missing required field: name")
            return jsonify({'status': 'error', 'message': 'Client name is required'}), 400

        if Client.query.filter_by(name=name).first():
            logger.warning(f"Client name already exists: {name}")
            return jsonify({'status': 'error', 'message': 'Client name already exists'}), 400

        new_client = Client(name=name, details=details)
        db.session.add(new_client)
        db.session.commit()

        logger.info(f"Client {name} added successfully by user {current_user.username}")
        return jsonify({'status': 'success', 'message': 'Client added successfully'})
    except Exception as e:
        logger.error(f"Error in add_client: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Server error occurred'}), 500

@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    data = request.form
    username = sanitize_input(data.get('username', ''))
    full_name = sanitize_input(data.get('full_name', ''))
    role = data.get('role', '')
    password = data.get('password', '')

    if not all([username, full_name, role]):
        return jsonify({'status': 'error', 'message': 'Username, full name, and role are required'}), 400

    if role not in ['admin', 'user']:
        return jsonify({'status': 'error', 'message': 'Invalid role'}), 400

    if password and not validate_password(password):
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long and contain letters, numbers, or special characters'}), 400

    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        user.username = username
        user.full_name = full_name
        user.role = role
        if password:
            user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        db.session.commit()
        logger.info(f"User ID {user_id} updated successfully")
        return jsonify({'status': 'success', 'message': 'User updated successfully'})
    except IntegrityError:
        logger.warning(f"Username already exists during edit: {username}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Server error occurred'}), 500

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    if user_id == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot delete yourself'}), 400
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        db.session.delete(user)
        db.session.commit()
        logger.info(f"User ID {user_id} deleted successfully")
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Error deleting user'}), 500

@app.route('/delete_client/<int:client_id>', methods=['POST'])
@admin_required
def delete_client(client_id):
    try:
        client = Client.query.get(client_id)
        if not client:
            logger.warning(f"Client ID {client_id} not found for deletion by user {current_user.username}")
            return jsonify({'status': 'error', 'message': 'Client not found'}), 404

        # Check for associated files or leads
        associated_files = File.query.filter_by(client_id=client_id).first()
        associated_leads_files = LeadsFile.query.filter_by(client_id=client_id).first()
        associated_used_leads = UsedLead.query.filter_by(client_id=client_id).first()
        if associated_files or associated_leads_files or associated_used_leads:
            logger.warning(f"Cannot delete client ID {client_id}: Associated files or leads exist")
            return jsonify({'status': 'error', 'message': 'Cannot delete client with associated files or leads'}), 400

        db.session.delete(client)
        db.session.commit()
        logger.info(f"Client ID {client_id} deleted successfully by user {current_user.username}")
        return jsonify({'status': 'success', 'message': 'Client deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting client {client_id} by user {current_user.username}: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Error deleting client'}), 500
    
    
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    client_id = request.form.get('client_id')
    if not client_id:
        return jsonify({'status': 'error', 'message': 'Client ID is required'}), 400

    client = Client.query.get(client_id)
    if not client:
        return jsonify({'status': 'error', 'message': 'Client not found'}), 404

    files = request.files.getlist('files')
    if not files:
        return jsonify({'status': 'error', 'message': 'No files selected'}), 400

    suppression_number = get_suppression_number(int(client_id))
    file_paths = []
    filenames = []

    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            file_paths.append(file_path)
            filenames.append(filename)
            logger.info(f"Uploaded file: {filename}")
        else:
            logger.warning(f"Skipping file {file.filename}: Invalid file type")
            continue

    if not file_paths:
        return jsonify({'status': 'error', 'message': 'No valid files uploaded'}), 400

    output_filename, status, file_metrics, summary_metrics = process_suppression(file_paths, int(client_id), suppression_number)

    if status == 'completed' and output_filename:
        for filename in filenames:
            new_file = File(
                client_id=client_id,
                filename=filename,
                output_filename=output_filename,
                upload_date=datetime.datetime.now().isoformat(),
                status=status,
                suppression_number=suppression_number,
                unique_count=file_metrics[0]['unique_count'] if file_metrics else 0,
                duplicate_count=file_metrics[0]['duplicate_count'] if file_metrics else 0,
                total_checked=summary_metrics.get('total_checked', 0),
                unique_before_merge=summary_metrics.get('unique_before_merge', 0),
                unique_after_merge=summary_metrics.get('unique_after_merge', 0),
                duplicates_removed=summary_metrics.get('duplicates_removed', 0)
            )
            db.session.add(new_file)
        db.session.commit()
        logger.info(f"Stored {len(filenames)} files in database for suppression {suppression_number} for client {client_id}")

        return jsonify({
            'status': 'success',
            'message': 'Processing completed',
            'output_filename': output_filename,
            'metrics': file_metrics,
            'summary_metrics': summary_metrics
        })
    else:
        return jsonify({
            'status': 'error',
            'message': f'Processing failed: {summary_metrics.get("error", "Unable to save output file")}',
            'metrics': file_metrics,
            'summary_metrics': summary_metrics
        }), 500

@app.route('/upload_data', methods=['POST'])
@login_required
def upload_data():
    try:
        if 'file' not in request.files:
            logger.error('Upload failed: No file part in request')
            return jsonify({'status': 'error', 'message': 'No file part in the request'}), 400
        file = request.files['file']
        if file.filename == '':
            logger.error('Upload failed: No file selected')
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400
        if not allowed_file(file.filename):
            logger.error(f'Upload failed: Invalid file type {file.filename}')
            return jsonify({'status': 'error', 'message': 'Invalid file type. Allowed types: csv, xlsx'}), 400
        if file.seek(0, os.SEEK_END) == 0:
            file.seek(0)
            logger.error('Upload failed: File is empty')
            return jsonify({'status': 'error', 'message': 'File is empty'}), 400
        file.seek(0)
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        logger.info(f'Attempting to save file {filename} to {file_path}')
        file.save(file_path)
        logger.info(f'File {filename} saved successfully')
        # Clear existing data files
        DataFile.query.delete()
        # Save to database
        upload_date = datetime.datetime.now().isoformat()
        new_data_file = DataFile(filename=filename, upload_date=upload_date)
        db.session.add(new_data_file)
        db.session.commit()
        logger.info(f'Stored data file {filename} in database')
        return jsonify({'status': 'success', 'message': 'Data file uploaded successfully'})
    except RequestEntityTooLarge:
        logger.error('Upload failed: File too large')
        return jsonify({'status': 'error', 'message': 'File too large. Maximum size is 100MB'}), 413
    except Exception as e:
        logger.error(f'Error uploading data file: {str(e)}\n{traceback.format_exc()}')
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error uploading data file: {str(e)}'}), 500
    

@app.route('/generate_leads', methods=['POST'])
@login_required
def generate_leads_route():
    client_id = request.form.get('client_id')
    if not client_id:
        return jsonify({'status': 'error', 'message': 'Client ID is required'}), 400

    client = Client.query.get(client_id)
    if not client:
        return jsonify({'status': 'error', 'message': 'Client not found'}), 404
    client_name = client.name

    data_file = get_data_file()
    if not data_file:
        return jsonify({'status': 'error', 'message': 'No data file uploaded'})

    data_filename, _ = data_file
    data_file_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)
    if not os.path.exists(data_file_path):
        return jsonify({'status': 'error', 'message': 'Data file not found'})

    revenue_filter = request.form.get('revenue_filter')
    number_type_filter = request.form.get('number_type_filter')
    email_filter = request.form.get('email_filter') == 'true'
    lead_quantity = request.form.get('lead_quantity', type=int)
    custom_filters = request.form.get('custom_filters')
    custom_filters = json.loads(custom_filters) if custom_filters else None

    output_filename, status, metrics = generate_leads(
        data_file_path, int(client_id), client_name, revenue_filter, number_type_filter, email_filter, lead_quantity, custom_filters
    )

    if status == 'completed':
        new_leads_file = LeadsFile(
            client_id=client_id,
            data_filename=data_filename,
            output_filename=output_filename,
            upload_date=datetime.datetime.now().isoformat(),
            total_phones=metrics['total_phones'],
            unique_leads=metrics['unique_leads'],
            suppression_number=metrics['suppression_number'],
            lead_number=metrics['lead_number'],
            revenue_filter=revenue_filter,
            number_type_filter=number_type_filter,
            email_filter=email_filter,
            lead_quantity=lead_quantity,
            custom_filters=metrics['custom_filters']
        )
        db.session.add(new_leads_file)
        db.session.commit()
        logger.info(f"Leads generated successfully for client: {client_name}, output: {output_filename}")
        return jsonify({
            'status': 'success',
            'message': 'Lead generation completed',
            'output_filename': output_filename,
            'metrics': metrics
        })
    else:
        logger.error(f"Lead generation failed for client: {client_name}")
        return jsonify({'status': 'error', 'message': 'Lead generation failed', 'metrics': metrics})

@app.route('/download/<filename>')
@login_required
def download(filename):
    file = File.query.filter_by(output_filename=filename).first()
    leads_file = LeadsFile.query.filter_by(output_filename=filename).first() if not file else None
    data_file = DataFile.query.filter_by(filename=filename).first() if not file and not leads_file else None
    if file or leads_file or data_file:
        client_id = file.client_id if file else leads_file.client_id if leads_file else None
        if current_user.role == 'admin' or client_id is None:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                logger.info(f"User {current_user.username} downloaded file: {filename}")
                return send_file(file_path, as_attachment=True)
    logger.warning(f"File download failed for user {current_user.username}: {filename} not found or access denied")
    return jsonify({'status': 'error', 'message': 'File not found or access denied'}), 404

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    try:
        file = File.query.get(file_id)
        if not file:
            logger.warning(f"File ID {file_id} not found for deletion by user {current_user.username}")
            return jsonify({'status': 'error', 'message': 'File not found'}), 404
        if current_user.role != 'admin':
            logger.warning(f"Access denied for user {current_user.username} to delete file ID {file_id}")
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        db.session.delete(file)
        db.session.commit()
        logger.info(f"Deleted file with id {file_id}: {file.filename} by user {current_user.username}")
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Removed file from storage: {file.filename}")
        return jsonify({'status': 'success', 'message': 'File deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting file {file_id} by user {current_user.username}: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Error deleting file'}), 500

if __name__ == '__main__':
    app.run(debug=True)