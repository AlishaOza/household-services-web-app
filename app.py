from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from forms import ProfessionalProfileForm, RegisterForm, ServiceForm
from models import db , User, Service, ProfessionalProfile, ServiceRequest    

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

first_request = True
# Initialize the database
@app.before_request
def create_tables():
    global first_request
    if first_request:
        db.create_all()
        first_request = False

# Home Route
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter(User.username==username).filter(User.role.in_(['customer','professional'])).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.role == 'customer':
                return redirect(url_for('customer_dashboard'))
            elif user.role == 'professional':
                # Check if the professional profile is incomplete
                professionalProfile = ProfessionalProfile.query.filter_by(user_id = user.id).first()
                if not professionalProfile:
                    return redirect(url_for('professional_profile'))
                return redirect(url_for('professional_dashboard'))
        flash('Invalid Credentials', 'danger')
    return render_template('login.html')        

# Logout route for admin
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Admin Login Route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='admin').first()
        if user and check_password_hash(user.password, password):
            session['admin_user_id'] = user.id
            return redirect(url_for('admin_dashboard'))
        flash('Invalid Credentials', 'danger')
    return render_template('admin_login.html')

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_user_id' in session:
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    return redirect(url_for('admin_login'))

# Manage Users Route
@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if not session.get('admin_user_id'):
        return redirect(url_for('admin_login'))
    
    users = User.query.all()  # Assuming User model is already defined

    # Approve or Block/Unblock Users based on form inputs
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        user = User.query.get(user_id)

        if user and action == 'approve':
            user.approved = True
            flash('User approved successfully', 'success')
        elif user and action == 'block':
            user.blocked = True
            flash('User blocked successfully', 'danger')
        elif user and action == 'unblock':
            user.blocked = False
            flash('User unblocked successfully', 'success')

        # Save changes to the database
        db.session.commit()

    return render_template('manage_users.html', users=users)

# Manage Services Route (CRUD operations)
@app.route('/manage_services', methods=['GET', 'POST'])
def manage_services():
    if not session.get('admin_user_id'):
        return redirect(url_for('admin_login'))

    form = ServiceForm()

    # Create or Update Service
    if form.validate_on_submit():
        service_id = request.form.get('service_id')
        if service_id:
            service = Service.query.get(service_id)
            service.name = form.name.data
            service.price = form.price.data
            service.description = form.description.data
            flash('Service updated successfully', 'success')
        else:
            new_service = Service(
                name=form.name.data,
                price=form.price.data,
                description=form.description.data
            )
            db.session.add(new_service)
            flash('Service created successfully', 'success')
        
        db.session.commit()
        return redirect(url_for('manage_services'))

    # Handle delete operation
    if request.method == 'POST' and request.form.get('delete_service_id'):
        service_to_delete = Service.query.get(request.form.get('delete_service_id'))
        if service_to_delete:
            db.session.delete(service_to_delete)
            db.session.commit()
            flash('Service deleted successfully', 'success')
        return redirect(url_for('manage_services'))

    services = Service.query.all()
    return render_template('manage_services.html', form=form, services=services)


# Logout route for admin
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

# `Customer` Dashboard
@app.route('/customer/dashboard')
def customer_dashboard():
    if 'user_id' in session:
        services = Service.query.all()
        return render_template('customer_dashboard.html', services=services)
    return redirect(url_for('login'))

@app.route('/customer/create_service_request', methods=['POST'])
def create_service_request():
    if 'user_id' in session:
        service_id = request.form['service_id']
        customer_id = session['user_id']
        service_request = ServiceRequest(service_id=service_id, customer_id=customer_id, service_status='requested')
        db.session.add(service_request)
        db.session.commit()
        flash('Service request created successfully!', 'success')
        return redirect(url_for('customer_dashboard'))
    return redirect(url_for('login'))
    
@app.route('/professional/profile', methods=['GET', 'POST'])
def professional_profile():
    if not session.get('user_id'):
        flash('Please log in to complete your profile.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    form = ProfessionalProfileForm()
    form.user_id.data = user_id

    if form.validate_on_submit():
        new_professional_profile = ProfessionalProfile(
                user_id = form.user_id.data,
                service_type = form.service_type.data,
                experience = form.experience.data,
                description = form.description.data
            )            
        db.session.add(new_professional_profile)
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('professional_dashboard'))

    return render_template('professional_profile.html', form=form)

@app.route('/professional/dashboard')
def professional_dashboard():
    if 'user_id' in session:
        professional_id = session['user_id']
        service_requests = ServiceRequest.query.filter_by(professional_id=professional_id).all()
        return render_template('professional_dashboard.html', service_requests=service_requests)
    return redirect(url_for('login'))

@app.route('/professional/update_request_status/<int:request_id>', methods=['POST'])
def update_request_status(request_id):
    if 'user_id' in session:
        service_request = ServiceRequest.query.get_or_404(request_id)
        action = request.form['action']
        
        if action == 'complete':
            service_request.service_status = 'completed'
        elif action == 'reject':
            service_request.service_status = 'rejected'
        
        db.session.commit()
        flash('Service request updated successfully!', 'success')
        return redirect(url_for('professional_dashboard'))
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)