from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, abort
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
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

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, full_name, role):
        self.id = id
        self.username = username
        self.full_name = full_name
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, username, full_name, role FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if user:
            return User(user[0], user[1], user[2], user[3])
        return None

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        if current_user.role != 'admin':
            abort(403)  # Forbidden for non-admin users
        return f(*args, **kwargs)
    return decorated_function

# Error handler for file size limit
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'status': 'error', 'message': 'File too large. Maximum size allowed is 100MB.'}), 413

# Database setup
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Users table (for authentication)
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
        )''')
        # Clients table (for client entities)
        c.execute('''CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            details TEXT
        )''')
        # Files table (suppressions, linked to clients)
        c.execute('''CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            filename TEXT NOT NULL,
            output_filename TEXT,
            upload_date TEXT,
            status TEXT DEFAULT 'pending',
            suppression_number INTEGER,
            unique_count INTEGER DEFAULT 0,
            duplicate_count INTEGER DEFAULT 0,
            total_checked INTEGER DEFAULT 0,
            unique_before_merge INTEGER DEFAULT 0,
            unique_after_merge INTEGER DEFAULT 0,
            duplicates_removed INTEGER DEFAULT 0,
            FOREIGN KEY (client_id) REFERENCES clients (id)
        )''')
        # Used leads table (linked to clients)
        c.execute('''CREATE TABLE IF NOT EXISTS used_leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            phone TEXT NOT NULL,
            added_date TEXT,
            UNIQUE(client_id, phone),
            FOREIGN KEY (client_id) REFERENCES clients (id)
        )''')
        # Leads files table (linked to clients)
        c.execute('''CREATE TABLE IF NOT EXISTS leads_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            data_filename TEXT NOT NULL,
            output_filename TEXT,
            upload_date TEXT,
            total_phones INTEGER DEFAULT 0,
            unique_leads INTEGER DEFAULT 0,
            suppression_number INTEGER,
            lead_number INTEGER,
            revenue_filter TEXT,
            number_type_filter TEXT,
            email_filter BOOLEAN,
            lead_quantity INTEGER,
            custom_filters TEXT,
            FOREIGN KEY (client_id) REFERENCES clients (id)
        )''')
        # Data files table (unchanged)
        c.execute('''CREATE TABLE IF NOT EXISTS data_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            upload_date TEXT
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_used_leads_phone ON used_leads (client_id, phone)')
        # Insert a default admin user if none exists
        c.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        if c.fetchone()[0] == 0:
            default_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            c.execute('INSERT INTO users (username, full_name, password, role) VALUES (?, ?, ?, ?)',
                      ('admin', 'Administrator', default_password.decode('utf-8'), 'admin'))
        conn.commit()

init_db()

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
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        current_time = datetime.datetime.now().isoformat()
        for i in range(0, len(unique_phones), batch_size):
            batch = unique_phones[i:i + batch_size]
            c.executemany(
                'INSERT OR IGNORE INTO used_leads (client_id, phone, added_date) VALUES (?, ?, ?)',
                [(client_id, phone, current_time) for phone in batch]
            )
            conn.commit()
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
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT MAX(suppression_number) FROM files WHERE client_id = ?', (client_id,))
        max_number = c.fetchone()[0]
        return (max_number or 0) + 1

def get_lead_number(client_id: int) -> int:
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT MAX(lead_number) FROM leads_files WHERE client_id = ?', (client_id,))
        max_number = c.fetchone()[0]
        return (max_number or 0) + 1

def get_previous_suppression_numbers(client_id: int) -> Set[str]:
    used_numbers = set()
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT output_filename FROM files WHERE client_id = ? AND status = "completed"', (client_id,))
        previous_files = c.fetchall()
        for file in previous_files:
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
            if os.path.exists(output_path):
                try:
                    if file[0].endswith('.csv'):
                        df = pd.read_csv(output_path, usecols=['phone', 'status'])
                    else:
                        df = pd.read_excel(output_path, engine='openpyxl', usecols=['phone', 'status'])
                    if 'phone' in df.columns:
                        unique_phones = df[df['status'] == 'unique']['phone'].apply(
                            lambda x: re.sub(r'\D', '', str(x)).strip()
                        ).tolist()
                        used_numbers.update(unique_phones)
                        logger.info(f"Loaded {len(unique_phones)} unique phones from {file[0]}")
                except Exception as e:
                    logger.error(f"Error reading previous suppression file {file[0]}: {str(e)}")
    logger.info(f"Total prior unique phones for client {client_id}: {len(used_numbers)}")
    return used_numbers

def get_latest_suppression(client_id: int) -> Optional[Tuple[str, int]]:
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT output_filename, suppression_number FROM files WHERE client_id = ? AND status = "completed" ORDER BY suppression_number DESC LIMIT 1', (client_id,))
        result = c.fetchone()
        if result:
            return result[0], result[1]
        return None

def get_data_file() -> Optional[Tuple[str, str]]:
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT filename, upload_date FROM data_files ORDER BY upload_date DESC LIMIT 1')
        result = c.fetchone()
        if result:
            return result[0], result[1]
        return None

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
            usecols = None  # Load all columns when no filters are applied
            output_columns = None  # Retain all columns in output
        else:
            usecols = ['Phone', 'Mobile']
            output_columns = [col for col in usecols]  # Start with phone column
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
            # Ensure phone_col is included in output
            if phone_col not in output_columns:
                output_columns.append(phone_col)
            # Filter columns, keeping only those that exist in leads_df
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

        # Save output (use CSV for large datasets)
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

        # Validate output_df
        logger.info(f"Output DataFrame has {len(output_df)} rows and columns: {output_df.columns.tolist()}")
        if not all(col in output_df.columns for col in ['phone', 'status']):
            logger.error(f"Suppression {suppression_number} failed: Output DataFrame missing required columns")
            return None, 'failed', file_metrics, summary_metrics

        # Determine output format based on row count
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

        # Verify output file exists
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
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, full_name, password, role FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user:
                stored_password = user[3] if isinstance(user[3], bytes) else user[3].encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                    user_obj = User(user[0], user[1], user[2], user[4])
                    login_user(user_obj)
                    logger.info(f"Login successful for username: {username}, role: {user[4]}")
                    flash('Login successful!', 'success')
                    if user[4] == 'admin':
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

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE id = ?', (current_user.id,))
        user = c.fetchone()
        stored_password = user[0] if isinstance(user[0], bytes) else user[0].encode('utf-8')
        if not user or not bcrypt.checkpw(current_password.encode('utf-8'), stored_password):
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
        conn.commit()

    logger.info(f"Password changed successfully for user: {current_user.username}")
    return jsonify({'status': 'success', 'message': 'Password changed successfully'})

@app.route('/dashboard')
@login_required
def dashboard():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Fetch all clients
        c.execute('SELECT id, name, details FROM clients')
        clients = c.fetchall()
        if current_user.role == 'admin':
            # Admins see all files and leads
            c.execute('SELECT f.id, f.filename, f.output_filename, f.upload_date, f.status, f.suppression_number, c.name, c.details, f.client_id, f.unique_count, f.duplicate_count, '
                      'f.total_checked, f.unique_before_merge, f.unique_after_merge, f.duplicates_removed '
                      'FROM files f JOIN clients c ON f.client_id = c.id')
            files = c.fetchall()
            c.execute('SELECT l.id, l.data_filename, l.output_filename, l.upload_date, l.total_phones, l.unique_leads, l.suppression_number, c.name, c.details, l.client_id, l.lead_number, '
                      'l.revenue_filter, l.number_type_filter, l.email_filter, l.lead_quantity, l.custom_filters '
                      'FROM leads_files l JOIN clients c ON l.client_id = c.id')
            leads_files = c.fetchall()
        else:
            # Regular users see files/leads for clients they are authorized to access
            # For simplicity, assume users can access all clients (modify if you have a user-client mapping)
            c.execute('SELECT f.id, f.filename, f.output_filename, f.upload_date, f.status, f.suppression_number, c.name, c.details, f.client_id, f.unique_count, f.duplicate_count, '
                      'f.total_checked, f.unique_before_merge, f.unique_after_merge, f.duplicates_removed '
                      'FROM files f JOIN clients c ON f.client_id = c.id')
            files = c.fetchall()
            c.execute('SELECT l.id, l.data_filename, l.output_filename, l.upload_date, l.total_phones, l.unique_leads, l.suppression_number, c.name, c.details, l.client_id, l.lead_number, '
                      'l.revenue_filter, l.number_type_filter, l.email_filter, l.lead_quantity, l.custom_filters '
                      'FROM leads_files l JOIN clients c ON l.client_id = c.id')
            leads_files = c.fetchall()
        c.execute('SELECT filename, upload_date FROM data_files ORDER BY upload_date DESC LIMIT 1')
        data_file = c.fetchone()
    return render_template('dashboard.html', clients=clients, files=files, leads_files=leads_files, data_file=data_file, csrf_token=generate_csrf())

@app.route('/admin')
@admin_required
def admin_portal():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, username, full_name, role FROM users')
        users = c.fetchall()
    return render_template('admin.html', users=users, csrf_token=generate_csrf())

@app.route('/add_user', methods=['POST'])
@admin_required
def add_user():
    try:
        logger.info(f"Received add_user request with form data: {request.form}, CSRF token: {request.form.get('csrf_token')}")
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

        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT username FROM users WHERE username = ?', (username,))
            if c.fetchone():
                logger.warning(f"Username already exists: {username}")
                return jsonify({'status': 'error', 'message': 'Username already exists'}), 400

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            c.execute('INSERT INTO users (username, full_name, password, role) VALUES (?, ?, ?, ?)',
                      (username, full_name, hashed_password, role))
            conn.commit()

        logger.info(f"User {username} added successfully")
        return jsonify({'status': 'success', 'message': 'User added successfully'})
    except Exception as e:
        logger.error(f"Error in add_user: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Server error occurred'}), 500

@app.route('/add_client', methods=['POST'])
@login_required
def add_client():
    try:
        logger.info(f"Received add_client request with form data: {request.form}, CSRF token: {request.form.get('csrf_token')}")
        name = sanitize_input(request.form.get('name', ''))
        details = request.form.get('details', '')

        if not name:
            logger.warning("Missing required field: name")
            return jsonify({'status': 'error', 'message': 'Client name is required'}), 400

        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT name FROM clients WHERE name = ?', (name,))
            if c.fetchone():
                logger.warning(f"Client name already exists: {name}")
                return jsonify({'status': 'error', 'message': 'Client name already exists'}), 400

            c.execute('INSERT INTO clients (name, details) VALUES (?, ?)', (name, details))
            conn.commit()

        logger.info(f"Client {name} added successfully by user {current_user.username}")
        return jsonify({'status': 'success', 'message': 'Client added successfully'})
    except Exception as e:
        logger.error(f"Error in add_client: {str(e)}")
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
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            if password:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                c.execute('UPDATE users SET username = ?, full_name = ?, password = ?, role = ? WHERE id = ?',
                          (username, full_name, hashed_password, role, user_id))
            else:
                c.execute('UPDATE users SET username = ?, full_name = ?, role = ? WHERE id = ?',
                          (username, full_name, role, user_id))
            conn.commit()
        logger.info(f"User ID {user_id} updated successfully")
        return jsonify({'status': 'success', 'message': 'User updated successfully'})
    except sqlite3.IntegrityError:
        logger.warning(f"Username already exists during edit: {username}")
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 400

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    if user_id == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot delete yourself'}), 400
    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('DELETE FROM users WHERE id = ?', (user_id,))
            if c.rowcount == 0:
                return jsonify({'status': 'error', 'message': 'User not found'}), 404
            conn.commit()
        logger.info(f"User ID {user_id} deleted successfully")
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Error deleting user'}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    client_id = request.form.get('client_id')
    if not client_id:
        return jsonify({'status': 'error', 'message': 'Client ID is required'}), 400

    # Verify client exists
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
        if not c.fetchone():
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
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            for filename in filenames:
                c.execute('INSERT INTO files (client_id, filename, upload_date, status, suppression_number, output_filename, '
                          'unique_count, duplicate_count, total_checked, unique_before_merge, unique_after_merge, duplicates_removed) '
                          'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                          (client_id, filename, datetime.datetime.now().isoformat(), status, suppression_number, output_filename,
                           file_metrics[0]['unique_count'] if file_metrics else 0,
                           file_metrics[0]['duplicate_count'] if file_metrics else 0,
                           summary_metrics.get('total_checked', 0),
                           summary_metrics.get('unique_before_merge', 0),
                           summary_metrics.get('unique_after_merge', 0),
                           summary_metrics.get('duplicates_removed', 0)))
            conn.commit()
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
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return jsonify({'status': 'error', 'message': 'No valid file uploaded'})

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    logger.info(f"Uploaded data file: {filename}")

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('DELETE FROM data_files')
        c.execute('INSERT INTO data_files (filename, upload_date) VALUES (?, ?)',
                  (filename, datetime.datetime.now().isoformat()))
        conn.commit()
        logger.info(f"Stored data file: {filename}")

    return jsonify({'status': 'success', 'message': 'Data file uploaded successfully'})

@app.route('/generate_leads', methods=['POST'])
@login_required
def generate_leads_route():
    client_id = request.form.get('client_id')
    if not client_id:
        return jsonify({'status': 'error', 'message': 'Client ID is required'}), 400

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT name FROM clients WHERE id = ?', (client_id,))
        client = c.fetchone()
        if not client:
            return jsonify({'status': 'error', 'message': 'Client not found'}), 404
        client_name = client[0]

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
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO leads_files (client_id, data_filename, output_filename, upload_date, total_phones, unique_leads, '
                      'suppression_number, lead_number, revenue_filter, number_type_filter, email_filter, lead_quantity, custom_filters) '
                      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                      (client_id, data_filename, output_filename, datetime.datetime.now().isoformat(),
                       metrics['total_phones'], metrics['unique_leads'], metrics['suppression_number'],
                       metrics['lead_number'], revenue_filter, number_type_filter, email_filter, lead_quantity,
                       metrics['custom_filters']))
            conn.commit()
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
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT output_filename, client_id FROM files WHERE output_filename = ? UNION '
                  'SELECT output_filename, client_id FROM leads_files WHERE output_filename = ? UNION '
                  'SELECT filename, NULL FROM data_files WHERE filename = ?', (filename, filename, filename))
        file = c.fetchone()
        if file and (current_user.role == 'admin' or file[1] is None):
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
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT filename, client_id FROM files WHERE id = ?', (file_id,))
            file = c.fetchone()
            if not file:
                logger.warning(f"File ID {file_id} not found for deletion by user {current_user.username}")
                return jsonify({'status': 'error', 'message': 'File not found'}), 404
            if current_user.role != 'admin':
                logger.warning(f"Access denied for user {current_user.username} to delete file ID {file_id}")
                return jsonify({'status': 'error', 'message': 'Access denied'}), 403
            c.execute('DELETE FROM files WHERE id = ?', (file_id,))
            conn.commit()
            logger.info(f"Deleted file with id {file_id}: {file[0]} by user {current_user.username}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Removed file from storage: {file[0]}")
        return jsonify({'status': 'success', 'message': 'File deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting file {file_id} by user {current_user.username}: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Error deleting file'}), 500

if __name__ == '__main__':
    app.run(debug=True)