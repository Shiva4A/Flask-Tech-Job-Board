import os
from flask import Flask, render_template_string, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Flask App Initialization and Configuration ---

app = Flask(__name__)
# Use a simple SQLite database file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_board.db'
app.config['SECRET_KEY'] = 'a_very_secret_and_long_key_for_session_management'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "You must log in to proceed."
login_manager.login_message_category = "warning"

# --- Database Models ---

class User(UserMixin, db.Model):
    """Database model for all users (Job Seekers, Employers, Admin)."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    # 'admin' for system administrator, 'employer', 'seeker'
    role = db.Column(db.String(20), nullable=False, default='seeker')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_employer(self):
        return self.role == 'employer'

class Job(db.Model):
    """Database model for job postings."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    employer = db.relationship('User', backref=db.backref('jobs', lazy=True))

class Application(db.Model):
    """Database model for job applications."""
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    seeker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Status can be: 'Pending', 'Reviewed', 'Interviewing', 'Rejected', 'Hired'
    status = db.Column(db.String(50), nullable=False, default='Pending')
    job = db.relationship('Job', backref=db.backref('applications', lazy=True))
    seeker = db.relationship('User', backref=db.backref('applications', lazy=True))

# --- Login Manager Configuration ---

@login_manager.user_loader
def load_user(user_id):
    """Required callback for Flask-Login to load a user from the session."""
    return User.query.get(int(user_id))

# --- Decorators for Role-Based Access Control (RBAC) ---

def employer_required(f):
    """Decorator to restrict access to employer/admin users."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['employer', 'admin']:
            flash('Access denied. Employer or Admin access is required for management actions.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Database Initialization Function ---

def init_db():
    """Initializes the database and ensures an admin user exists, adding sample jobs."""
    with app.app_context():
        db.create_all()
        
        # Check for and create testing users if they don't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', email='admin@jobboard.com', role='admin')
            admin_user.set_password('adminpass')
            db.session.add(admin_user)
        
        employer_user = User.query.filter_by(username='employer_one').first()
        if not employer_user:
            employer_user = User(username='employer_one', email='employer1@corp.com', role='employer')
            employer_user.set_password('employerpass')
            db.session.add(employer_user)
        
        if not User.query.filter_by(username='seeker_one').first():
            seeker_user = User(username='seeker_one', email='seeker1@mail.com', role='seeker')
            seeker_user.set_password('seekerpass')
            db.session.add(seeker_user)
        
        db.session.commit()
        
        # --- Add Sample Jobs (Python and Java jobs added here) ---
        if employer_user and not Job.query.first():
            # Jobs posted by the 'employer_one' account
            sample_jobs = [
                Job(
                    title='Senior Python Developer',
                    company='TechInnovate',
                    location='Remote',
                    description="""Develop and maintain high-performance, scalable backend services using Python and Flask/Django.
                        You will be responsible for designing and implementing APIs, integrating with databases (PostgreSQL), and writing extensive unit tests.
                        **Requirements:** 5+ years of Python experience, deep knowledge of RESTful services, and cloud deployment (AWS/Azure).""",
                    employer_id=employer_user.id
                ),
                Job(
                    title='Java Backend Engineer',
                    company='Global Banking Corp',
                    location='Hyderabad, IN',
                    description="""Work on critical low-latency trading systems using Java 17 and the Spring ecosystem. 
                        This role requires strong fundamental knowledge of multithreading, data structures, and object-oriented design.
                        **Roles:** Develop new features, optimize performance, and participate in code reviews.""",
                    employer_id=employer_user.id
                ),
                Job(
                    title='Junior Data Scientist (Python Focus)',
                    company='DataDriven Insights',
                    location='New York, NY',
                    description="""Support the data science team by cleaning, analyzing, and modeling large datasets using Python libraries (Pandas, NumPy, Scikit-learn).
                        Opportunity to build and deploy machine learning models in production.
                        **Requirements:** Bachelor's degree in a quantitative field, and experience with SQL is essential.""",
                    employer_id=employer_user.id
                )
            ]
            db.session.add_all(sample_jobs)
            db.session.commit()
            print("Sample jobs added successfully.")

        print("Database initialized and default testing users created.")

# --- Utility Functions for Data Retrieval (Unchanged) ---

def get_job_data(job_id):
    """Retrieves a job object or returns None."""
    return Job.query.get(job_id)

def get_jobs_list(search_query=None):
    """Retrieves a list of all jobs, optionally filtered by search query."""
    q = Job.query.order_by(Job.id.desc())
    if search_query:
        q = q.filter(
            (Job.title.contains(search_query)) |
            (Job.company.contains(search_query)) |
            (Job.location.contains(search_query))
        )
    return q.all()

def get_applications_for_job(job_id):
    """Retrieves all applications for a specific job, including seeker details."""
    return Application.query.filter_by(job_id=job_id).all()

# --- Route Handlers (Unchanged) ---

@app.route('/')
def index():
    """Home page: Displays all job listings (Public)."""
    search_query = request.args.get('search', '')
    jobs = get_jobs_list(search_query)

    application_statuses = {}
    if current_user.is_authenticated and current_user.role == 'seeker':
        seeker_applications = Application.query.filter_by(seeker_id=current_user.id).all()
        application_statuses = {app.job_id: app.status for app in seeker_applications}

    return render_template_string(template, jobs=jobs, application_statuses=application_statuses, search_query=search_query)

@app.route('/job/<int:job_id>')
def job_details(job_id):
    """Displays detailed information about a single job (Public)."""
    job = get_job_data(job_id)
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('index'))

    application = None
    if current_user.is_authenticated and current_user.role == 'seeker':
        application = Application.query.filter_by(job_id=job_id, seeker_id=current_user.id).first()

    return render_template_string(template, job=job, application=application)

@app.route('/apply/<int:job_id>', methods=['POST'])
def apply_for_job(job_id):
    """Handles the job application submission."""
    if not current_user.is_authenticated:
        flash('You must log in or register as a Job Seeker to submit an application.', 'warning')
        return redirect(url_for('login', next=url_for('job_details', job_id=job_id)))

    if current_user.role != 'seeker':
        flash('Only Job Seekers can apply for jobs.', 'danger')
        return redirect(url_for('job_details', job_id=job_id))

    job = get_job_data(job_id)
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('index'))

    existing_application = Application.query.filter_by(job_id=job_id, seeker_id=current_user.id).first()
    if existing_application:
        flash(f'You have already applied for this job. Status: {existing_application.status}', 'warning')
        return redirect(url_for('job_details', job_id=job_id))

    new_application = Application(job_id=job_id, seeker_id=current_user.id, status='Pending')
    db.session.add(new_application)
    db.session.commit()

    flash('Application submitted successfully! Check the job details page for status updates.', 'success')
    return redirect(url_for('job_details', job_id=job_id))

# --- Employer/Admin Routes ---

@app.route('/dashboard')
@employer_required
def employer_dashboard():
    """Dashboard for Employers (and Admin) to manage their jobs and applications."""
    if current_user.is_admin():
        jobs = Job.query.order_by(Job.id.desc()).all()
    else:
        jobs = Job.query.filter_by(employer_id=current_user.id).order_by(Job.id.desc()).all()

    job_stats = {}
    for job in jobs:
        total_applications = Application.query.filter_by(job_id=job.id).count()
        pending_applications = Application.query.filter_by(job_id=job.id, status='Pending').count()
        job_stats[job.id] = {'total': total_applications, 'pending': pending_applications}

    return render_template_string(template, jobs=jobs, job_stats=job_stats)

@app.route('/post_job', methods=['GET', 'POST'])
@employer_required
def post_job():
    """Route to post a new job."""
    if request.method == 'POST':
        title = request.form.get('title')
        company = request.form.get('company')
        location = request.form.get('location')
        description = request.form.get('description')

        if not all([title, company, location, description]):
            flash('All fields are required.', 'danger')
        else:
            employer_id = current_user.id

            new_job = Job(
                title=title,
                company=company,
                location=location,
                description=description,
                employer_id=employer_id
            )
            db.session.add(new_job)
            db.session.commit()
            flash(f'Job "{title}" posted successfully!', 'success')
            return redirect(url_for('employer_dashboard'))

    return render_template_string(template)

@app.route('/view_applicants/<int:job_id>')
@employer_required
def view_applicants(job_id):
    """View all applicants for a specific job."""
    job = get_job_data(job_id)
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('employer_dashboard'))

    # Security check: Employers can only view applicants for their own jobs
    if current_user.role == 'employer' and job.employer_id != current_user.id:
        flash('You are not authorized to view applicants for this job.', 'danger')
        return redirect(url_for('employer_dashboard'))

    applications = get_applications_for_job(job_id)
    status_options = ['Pending', 'Reviewed', 'Interviewing', 'Rejected', 'Hired']

    return render_template_string(template, job=job, applications=applications, status_options=status_options)

@app.route('/update_status/<int:application_id>', methods=['POST'])
@employer_required
def update_application_status(application_id):
    """Endpoint to update the status of a job application."""
    new_status = request.form.get('status')
    if not new_status:
        flash('Invalid status provided.', 'danger')
        return redirect(request.referrer or url_for('employer_dashboard'))

    application = Application.query.get(application_id)
    if not application:
        flash('Application not found.', 'danger')
        return redirect(request.referrer or url_for('employer_dashboard'))

    job = application.job
    # Security check: Only the job's employer (or admin) can update the status
    if current_user.role == 'employer' and job.employer_id != current_user.id:
        flash('You are not authorized to update this application.', 'danger')
        return redirect(request.referrer or url_for('employer_dashboard'))

    application.status = new_status
    db.session.commit()
    flash(f'Application status updated to "{new_status}" for {application.seeker.username}.', 'success')
    return redirect(url_for('view_applicants', job_id=application.job_id))

@app.route('/delete_job/<int:job_id>', methods=['POST'])
@employer_required
def delete_job(job_id):
    """Deletes a job and all associated applications."""
    job = get_job_data(job_id)
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('employer_dashboard'))

    # Security check: Only the job's employer (or admin) can delete the job
    if current_user.role == 'employer' and job.employer_id != current_user.id:
        flash('You are not authorized to delete this job.', 'danger')
        return redirect(url_for('employer_dashboard'))

    Application.query.filter_by(job_id=job.id).delete()
    db.session.delete(job)
    db.session.commit()
    flash(f'Job "{job.title}" and all applications deleted successfully.', 'info')
    return redirect(url_for('employer_dashboard'))

# --- Authentication Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'Logged in successfully as {user.username} ({user.role}).', 'success')
            next_page = request.args.get('next')
            if user.role in ['admin', 'employer']:
                 return redirect(next_page or url_for('employer_dashboard'))
            return redirect(next_page or url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template_string(template)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'seeker') # Default to seeker

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        elif role not in ['seeker', 'employer']:
            flash('Invalid role selected.', 'danger')
        else:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Account created successfully for {username} as a {role}!', 'success')
            return redirect(url_for('login'))

    return render_template_string(template)

@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- HTML Template (Embedded using render_template_string) ---

template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Job Board App</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                    },
                    colors: {
                        'primary-indigo': '#4f46e5',
                        'secondary-green': '#10b981',
                    }
                }
            }
        }
    </script>
    <style>
        /* Custom styles for the dropdown to ensure it overlays */
        .dropdown {
            position: relative;
            display: inline-block;
        }

        /* Style for the custom flash message container */
        .flash-container {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 1000;
        }
        .flash-message {
            margin-bottom: 0.5rem;
            padding: 1rem;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
            max-width: 300px;
            min-width: 200px;
            transition: opacity 0.3s ease-in-out, transform 0.3s ease-in-out;
            transform: translateY(0);
        }
        .flash-message.success { background-color: #d1fae5; color: #065f46; border: 1px solid #34d399; }
        .flash-message.warning { background-color: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }
        .flash-message.danger { background-color: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
        .flash-message.info { background-color: #e0f2f1; color: #0f766e; border: 1px solid #478e8b; }
    </style>
</head>
<body class="bg-gray-50 font-sans min-h-screen flex flex-col">

    <div class="flash-container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash-message {{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <nav class="bg-white shadow-md sticky top-0 z-50">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <a href="{{ url_for('index') }}" class="text-2xl font-bold text-indigo-600 tracking-tight">
                JobSeekerCentral<span class="text-green-400">.io</span>
            </a>
            <div class="flex items-center space-x-4">
                <a href="{{ url_for('index') }}" class="text-gray-600 hover:text-indigo-600 font-medium transition duration-150">Jobs</a>

                {% if current_user.is_authenticated %}
                    {% if current_user.is_employer() or current_user.is_admin() %}
                        <a href="{{ url_for('employer_dashboard') }}" class="text-gray-600 hover:text-indigo-600 font-medium transition duration-150">
                            Dashboard
                        </a>
                        <a href="{{ url_for('post_job') }}" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition duration-150 shadow-md">
                            Post Job
                        </a>
                    {% endif %}
                    <a href="{{ url_for('logout') }}" class="text-gray-600 hover:text-red-600 font-medium transition duration-150">Logout ({{ current_user.username }})</a>
                {% else %}
                    <a href="{{ url_for('login') }}" class="text-gray-600 hover:text-indigo-600 font-medium transition duration-150">Login</a>
                    <a href="{{ url_for('register') }}" class="bg-secondary-green text-white px-4 py-2 rounded-lg hover:bg-green-600 transition duration-150 shadow-md">
                        Register
                    </a>
                {% endif %}
            </div>
        </div>
    </nav>

    <main class="flex-grow container mx-auto px-4 sm:px-6 lg:px-8 py-12">

        {% if request.path == url_for('login') %}
            <div class="max-w-md mx-auto bg-white p-8 rounded-xl shadow-2xl">
                <h2 class="text-3xl font-extrabold text-gray-900 text-center mb-6">Sign in to your account</h2>
                
                <p class="text-sm text-center text-gray-500 mb-6 p-3 bg-gray-100 rounded-lg border border-gray-200">
                    <span class="font-bold text-gray-700">Testing Tip:</span> Default accounts are created on startup:
                    <ul class="text-left mt-2 space-y-0.5 ml-4 list-disc list-inside">
                        <li><span class="font-semibold text-indigo-600">Admin:</span> **admin** / **adminpass**</li>
                        <li><span class="font-semibold text-indigo-600">Employer:</span> **employer_one** / **employerpass**</li>
                        <li><span class="font-semibold text-indigo-600">Seeker:</span> **seeker_one** / **seekerpass**</li>
                    </ul>
                </p>

                <form action="{{ url_for('login') }}" method="POST" class="space-y-6">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                        <input type="text" name="username" id="username" required
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                    </div>
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                        <input type="password" name="password" id="password" required
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                    </div>
                    <button type="submit"
                            class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-primary-indigo hover:bg-indigo-700 transition duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-indigo">
                        Sign in
                    </button>
                </form>
                <p class="mt-4 text-center text-sm text-gray-600">
                    Don't have an account?
                    <a href="{{ url_for('register') }}" class="font-medium text-primary-indigo hover:text-indigo-500">
                        Register here
                    </a>
                </p>
            </div>

        {% elif request.path == url_for('register') %}
            <div class="max-w-lg mx-auto bg-white p-8 rounded-xl shadow-2xl">
                <h2 class="text-3xl font-extrabold text-gray-900 text-center mb-6">Create a New Account</h2>
                <form action="{{ url_for('register') }}" method="POST" class="space-y-6">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                        <input type="text" name="username" id="username" required
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                    </div>
                    <div>
                        <label for="email" class="block text-sm font-medium text-gray-700">Email Address</label>
                        <input type="email" name="email" id="email" required
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                    </div>
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                        <input type="password" name="password" id="password" required
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                    </div>
                    <div>
                        <label for="role" class="block text-sm font-medium text-gray-700">Account Type</label>
                        <select name="role" id="role" required
                                class="mt-1 block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo sm:text-sm rounded-lg shadow-sm">
                            <option value="seeker">Job Seeker</option>
                            <option value="employer">Employer</option>
                        </select>
                    </div>
                    <button type="submit"
                            class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-secondary-green hover:bg-green-600 transition duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-secondary-green">
                        Register Account
                    </button>
                </form>
            </div>

        {% elif request.path == url_for('post_job') %}
            <div class="max-w-2xl mx-auto bg-white p-8 rounded-xl shadow-2xl">
                <h2 class="text-3xl font-extrabold text-gray-900 text-center mb-6">Post a New Job</h2>
                <form action="{{ url_for('post_job') }}" method="POST" class="space-y-6">
                    <div>
                        <label for="title" class="block text-sm font-medium text-gray-700">Job Title</label>
                        <input type="text" name="title" id="title" required
                               class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label for="company" class="block text-sm font-medium text-gray-700">Company Name</label>
                            <input type="text" name="company" id="company" required
                                   class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                        </div>
                        <div>
                            <label for="location" class="block text-sm font-medium text-gray-700">Location</label>
                            <input type="text" name="location" id="location" required
                                   class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo">
                        </div>
                    </div>
                    <div>
                        <label for="description" class="block text-sm font-medium text-gray-700">Job Description</label>
                        <textarea name="description" id="description" rows="8" required
                                  class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-primary-indigo focus:border-primary-indigo"></textarea>
                    </div>
                    <button type="submit"
                            class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-primary-indigo hover:bg-indigo-700 transition duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-indigo">
                        Publish Job
                    </button>
                </form>
            </div>

        {% elif 'job_details' in request.path and job is defined %}
            <div class="max-w-4xl mx-auto space-y-8">
                <a href="{{ url_for('index') }}" class="inline-flex items-center text-primary-indigo hover:text-indigo-700 transition duration-150 font-medium">
                    &larr; Back to Job Listings
                </a>
                <div class="bg-white p-8 rounded-xl shadow-2xl border-t-4 border-primary-indigo">
                    <h1 class="text-4xl font-extrabold text-gray-900 mb-2">{{ job.title }}</h1>
                    <p class="text-xl text-gray-600 mb-4">{{ job.company }} &bull; {{ job.location }}</p>

                    <div class="prose max-w-none text-gray-700 border-t pt-6 mt-6">
                        <h3 class="text-2xl font-bold text-gray-800 mb-3">Job Summary</h3>
                        <p class="whitespace-pre-wrap">{{ job.description }}</p>
                    </div>

                    <div class="mt-8 pt-6 border-t">
                        {% if current_user.is_authenticated and current_user.role == 'seeker' %}
                            {% if application %}
                                <div class="bg-green-50 p-4 rounded-lg flex justify-between items-center border border-green-200">
                                    <p class="text-lg font-semibold text-green-700">
                                        You have applied for this job.
                                    </p>
                                    <span class="text-sm font-bold px-3 py-1 rounded-full text-white
                                        {% if application.status == 'Hired' %} bg-green-500
                                        {% elif application.status == 'Interviewing' %} bg-indigo-500
                                        {% elif application.status == 'Rejected' %} bg-red-500
                                        {% else %} bg-yellow-500
                                        {% endif %}">
                                        Status: {{ application.status }}
                                    </span>
                                </div>
                            {% else %}
                                <form action="{{ url_for('apply_for_job', job_id=job.id) }}" method="POST">
                                    <button type="submit"
                                            class="w-full sm:w-auto px-8 py-3 bg-secondary-green text-white font-bold rounded-lg hover:bg-green-600 transition duration-150 shadow-md">
                                        Apply Now
                                    </button>
                                </form>
                            {% endif %}
                        {% elif current_user.is_authenticated and current_user.role in ['employer', 'admin'] %}
                            <p class="text-lg text-gray-600 font-semibold">
                                You are logged in as a {{ current_user.role }}. View applications in your Dashboard.
                            </p>
                            <a href="{{ url_for('view_applicants', job_id=job.id) }}" class="mt-4 inline-block px-6 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-indigo-600 hover:bg-indigo-700">
                                View Applicants
                            </a>
                        {% else %}
                            <div class="bg-gray-100 p-4 rounded-lg text-center">
                                <p class="text-lg text-gray-700">
                                    <form action="{{ url_for('apply_for_job', job_id=job.id) }}" method="POST">
                                        <button type="submit"
                                                class="w-full sm:w-auto px-8 py-3 bg-secondary-green text-white font-bold rounded-lg hover:bg-green-600 transition duration-150 shadow-md">
                                            Apply Now (Requires Login)
                                        </button>
                                    </form>
                                </p>
                            </div>
                        {% endif %}
                    </div>
                </div>
            </div>

        {% elif request.path == url_for('employer_dashboard') and jobs is defined %}
            <div class="max-w-6xl mx-auto space-y-8">
                <h1 class="text-3xl font-extrabold text-gray-900">
                    {{ 'Admin' if current_user.is_admin() else 'Employer' }} Dashboard
                </h1>

                <div class="flex justify-between items-center border-b pb-4">
                    <p class="text-lg text-gray-600">Manage your posted jobs and applications.</p>
                    <a href="{{ url_for('post_job') }}" class="bg-primary-indigo text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition duration-150 shadow-lg font-medium">
                        + Post New Job
                    </a>
                </div>

                <div class="space-y-4">
                    {% if jobs %}
                        {% for job in jobs %}
                            <div class="bg-white p-6 rounded-xl shadow-md border-l-4 border-secondary-green flex justify-between items-center">
                                <div class="flex-grow">
                                    <h2 class="text-xl font-bold text-gray-900">
                                        <a href="{{ url_for('job_details', job_id=job.id) }}" class="hover:text-primary-indigo transition duration-150">{{ job.title }}</a>
                                    </h2>
                                    <p class="text-gray-600">{{ job.company }} &bull; {{ job.location }}</p>
                                    <div class="mt-2 text-sm text-gray-500">
                                        Total Applications: <span class="font-semibold text-gray-800">{{ job_stats[job.id]['total'] }}</span> |
                                        Pending Review: <span class="font-semibold text-red-500">{{ job_stats[job.id]['pending'] }}</span>
                                    </div>
                                </div>
                                <div class="space-x-4 flex-shrink-0">
                                    <a href="{{ url_for('view_applicants', job_id=job.id) }}"
                                       class="px-4 py-2 bg-indigo-100 text-indigo-700 rounded-lg hover:bg-indigo-200 transition duration-150 font-medium text-sm">
                                        View Applicants
                                    </a>
                                    <form action="{{ url_for('delete_job', job_id=job.id) }}" method="POST" class="inline">
                                        <button type="submit" onclick="return confirm('Are you sure you want to delete this job and all its applications?')"
                                                class="px-4 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 transition duration-150 font-medium text-sm">
                                            Delete Job
                                        </button>
                                    </form>
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <div class="text-center py-10 bg-white rounded-xl shadow-md">
                            <p class="text-lg text-gray-600">You have not posted any jobs yet.</p>
                            <a href="{{ url_for('post_job') }}" class="mt-4 inline-block text-primary-indigo font-medium hover:text-indigo-700">
                                Click here to post your first job!
                            </a>
                        </div>
                    {% endif %}
                </div>
            </div>

        {% elif 'view_applicants' in request.path and job is defined %}
            <div class="max-w-4xl mx-auto space-y-8">
                <a href="{{ url_for('employer_dashboard') }}" class="inline-flex items-center text-primary-indigo hover:text-indigo-700 transition duration-150 font-medium">
                    &larr; Back to Dashboard
                </a>
                <h1 class="text-3xl font-extrabold text-gray-900">
                    Applicants for: <span class="text-secondary-green">{{ job.title }}</span>
                </h1>

                <div class="space-y-4">
                    {% if applications %}
                        {% for application in applications %}
                            <div class="bg-white p-6 rounded-xl shadow-md flex justify-between items-center">
                                <div class="flex-grow">
                                    <h2 class="text-xl font-bold text-gray-900">{{ application.seeker.username }}</h2>
                                    <p class="text-gray-600">{{ application.seeker.email }}</p>
                                    <p class="mt-2 text-sm font-medium">
                                        Current Status:
                                        <span id="current-status-{{ application.id }}"
                                              class="px-2 py-1 rounded-full text-xs font-semibold text-white
                                              {% if application.status == 'Hired' %} bg-green-500
                                              {% elif application.status == 'Interviewing' %} bg-indigo-500
                                              {% elif application.status == 'Rejected' %} bg-red-500
                                              {% else %} bg-yellow-500
                                              {% endif %}">
                                            {{ application.status }}
                                        </span>
                                    </p>
                                </div>
                                <div class="dropdown flex-shrink-0">
                                    <button onclick="document.getElementById('dropdown-{{ application.id }}').classList.toggle('hidden')"
                                            class="bg-gray-200 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-300 transition duration-150 font-medium text-sm focus:outline-none">
                                        Update Status
                                    </button>

                                    <div id="dropdown-{{ application.id }}" class="hidden absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-xl z-10 border border-gray-100">
                                        {% for status in status_options %}
                                            <form action="{{ url_for('update_application_status', application_id=application.id) }}" method="POST" class="w-full">
                                                <input type="hidden" name="status" value="{{ status }}">
                                                <button type="submit"
                                                        class="w-full text-left px-4 py-2 text-sm hover:bg-gray-100 rounded-lg transition duration-100
                                                        {% if application.status == status %} font-bold text-primary-indigo {% else %} text-gray-700 {% endif %}">
                                                    {{ status }}
                                                </button>
                                            </form>
                                        {% endfor %}
                                    </div>
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <div class="text-center py-10 col-span-full bg-white rounded-xl shadow-md">
                            <p class="text-lg text-gray-600">No applicants have applied for this job yet.</p>
                        </div>
                    {% endif %}
                </div>
            </div>

        {% else %}
            <div class="space-y-8">
                <div class="text-center">
                    <h1 class="text-5xl font-extrabold text-gray-900 mb-2">Find Your Dream Job</h1>
                    <p class="text-xl text-gray-600">Browse the latest listings from top companies.</p>
                </div>

                <form action="{{ url_for('index') }}" method="GET" class="max-w-3xl mx-auto">
                    <div class="flex rounded-lg shadow-lg overflow-hidden">
                        <input type="search" name="search" placeholder="Search by title, company, or location..."
                               value="{{ search_query if search_query is defined else '' }}"
                               class="flex-grow px-6 py-4 border-2 border-gray-200 focus:border-primary-indigo focus:outline-none text-lg">
                        <button type="submit" class="bg-primary-indigo text-white px-6 py-4 hover:bg-indigo-700 transition duration-150">
                            Search
                        </button>
                    </div>
                </form>

                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {% if jobs %}
                        {% for job in jobs %}
                            <div class="bg-white p-6 rounded-xl shadow-lg hover:shadow-2xl transition duration-300 transform hover:-translate-y-1 border-t-4 border-secondary-green space-y-4">
                                <h2 class="text-2xl font-bold text-gray-900 line-clamp-1">{{ job.title }}</h2>
                                <p class="text-lg text-primary-indigo font-semibold">{{ job.company }}</p>
                                <p class="text-gray-600 text-sm">
                                    Location: <span class="font-medium text-gray-800">{{ job.location }}</span>
                                </p>
                                <p class="text-gray-700 line-clamp-3">{{ job.description }}</p>

                                <div class="flex justify-between items-center pt-2 border-t mt-4">
                                    <a href="{{ url_for('job_details', job_id=job.id) }}"
                                       class="text-primary-indigo hover:text-indigo-700 font-medium transition duration-150">
                                        View Details &rarr;
                                    </a>

                                    {% if current_user.is_authenticated and current_user.role == 'seeker' %}
                                        {% set status = application_statuses.get(job.id) %}
                                        {% if status %}
                                            <span class="text-xs font-bold px-3 py-1 rounded-full text-white
                                                {% if status == 'Hired' %} bg-green-500
                                                {% elif status == 'Interviewing' %} bg-indigo-500
                                                {% elif status == 'Rejected' %} bg-red-500
                                                {% else %} bg-yellow-500
                                                {% endif %}">
                                                Applied ({{ status }})
                                            </span>
                                        {% else %}
                                            <a href="{{ url_for('job_details', job_id=job.id) }}"
                                                class="text-secondary-green hover:text-green-600 font-medium transition duration-150 text-sm">
                                                Apply
                                            </a>
                                        {% endif %}
                                    {% else %}
                                         <a href="{{ url_for('job_details', job_id=job.id) }}"
                                                class="text-secondary-green hover:text-green-600 font-medium transition duration-150 text-sm">
                                                Apply
                                            </a>
                                    {% endif %}
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <div class="text-center py-20 col-span-full bg-white rounded-xl shadow-md">
                            <p class="text-xl text-gray-600">No job listings found.</p>
                            {% if current_user.is_authenticated and current_user.role in ['employer', 'admin'] %}
                                <a href="{{ url_for('post_job') }}" class="mt-4 inline-block text-primary-indigo font-medium hover:text-indigo-700">
                                    Post a Job to get started!
                                </a>
                            {% endif %}
                        </div>
                    {% endif %}
                </div>
            </div>

        {% endif %}
    </main>

    <script>
        // Simple script to handle status update dropdowns visibility
        window.onclick = function(event) {
            if (event.target.matches('.bg-gray-200')) {
                return;
            }

            var dropdowns = document.querySelectorAll(".dropdown > div[id^='dropdown-']");
            for (var i = 0; i < dropdowns.length; i++) {
                var openDropdown = dropdowns[i];
                if (!openDropdown.classList.contains('hidden')) {
                    let isInsideDropdown = openDropdown.contains(event.target);
                    if (!isInsideDropdown) {
                        openDropdown.classList.add('hidden');
                    }
                }
            }
        }

        // Script to automatically fade out flash messages after a few seconds
        document.addEventListener('DOMContentLoaded', () => {
            const messages = document.querySelectorAll('.flash-message');
            messages.forEach(msg => {
                setTimeout(() => {
                    msg.style.opacity = '0';
                    msg.style.transform = 'translateY(-20px)';
                    // Remove element from DOM after transition
                    setTimeout(() => msg.remove(), 300);
                }, 4000); // 4 seconds delay
            });
        });
    </script>
</body>
</html>
"""
# --- Main Execution Block ---

if __name__ == '__main__':
    # Initialize the database and create the admin user if needed
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)