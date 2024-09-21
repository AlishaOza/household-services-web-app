import os
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CustomerProfileForm, ProfessionalProfileForm, RegisterForm, ServiceForm
from models import CustomerProfile, db , User, Service, ProfessionalProfile, ServiceRequest
from werkzeug.utils import secure_filename    

app = Flask(__name__)

# Configure file upload settings
app.config['UPLOAD_FOLDER'] = 'uploads/'  # Directory to save files
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file size to 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}  # Allowed file extensions

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

db.init_app(app)

first_request = True
# Initialize the database
@app.before_request
def create_tables():
    global first_request
    if first_request:
        db.create_all()
        first_request = False

# Serve downloadable files from a 'files' directory
@app.route('/download/<string:filename>')
def download_file(filename):
    # Set the directory where your files are located
    file_directory = os.path.join(app.root_path, 'uploads')
    
    # Serve the file from the directory as an attachment
    return send_from_directory(file_directory, filename, as_attachment=True)

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
        new_user = User(username=form.username.data, password=hashed_password, role=form.role.data, approve=False, blocked=True)
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
            session['role'] = user.role
            if user.role == 'customer':
                # Check if the customer profile is incomplete
                customer_profile = CustomerProfile.query.filter_by(user_id = user.id).first()
                if not customer_profile:
                    return redirect(url_for('customer_profile'))
                return redirect(url_for('customer_dashboard'))
            elif user.role == 'professional':
                # Check if the professional profile is incomplete
                professional_profile = ProfessionalProfile.query.filter_by(user_id = user.id).first()
                if not professional_profile:
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
            session['role'] = user.role
            return redirect(url_for('admin_dashboard'))
        flash('Invalid Credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if not session.get('admin_user_id'):
        flash('Admin! Please log in..', 'danger')
        return redirect(url_for('admin_login'))
    else:
        user_id = session['admin_user_id']
        username = User.query.get(user_id).username
        flash("Admin! You can't make changes to your profile", 'danger')
    return render_template('admin_profile.html')

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_user_id' in session:
        user_dict={}
        service_type={}
        services = Service.query.all()
        professional_profile = ProfessionalProfile.query.all()
        for profile in professional_profile:
            user_dict[profile.user_id] = User.query.filter_by(id=profile.user_id).first()
            service_type[profile.user_id] = Service.query.filter_by(id=profile.service_type).first()
        service_requests = ServiceRequest.query.all()
        return render_template('admin_dashboard.html', services=services, professional_profile=professional_profile, customer_profile=customer_profile, service_requests=service_requests,user_dict=user_dict,service_type=service_type)
    return redirect(url_for('admin_login'))

@app.route('/admin/search')
def admin_search():
    if 'admin_user_id' in session:
        services = Service.query.all()
        professional_profile = ProfessionalProfile.query.all()
        service_requests = ServiceRequest.query.all()
        return render_template('admin_dashboard.html', services=services, professional_profile=professional_profile, customer_profile=customer_profile, service_requests=service_requests)
    return redirect(url_for('admin_login'))

@app.route('/admin/summary')
def admin_summary():
    if 'admin_user_id' in session:
        services = Service.query.all()
        professional_profile = ProfessionalProfile.query.all()
        service_requests = ServiceRequest.query.all()
        return render_template('admin_summary.html', services=services, professional_profile=professional_profile, customer_profile=customer_profile, service_requests=service_requests)
    return redirect(url_for('admin_login'))

# Manage User Route
@app.route('/admin/manage_user/<int:user_id>/<string:field>/<string:value>', methods=['GET', 'POST'])
def manage_user(user_id,field,value):
    if not session.get('admin_user_id'):
        return redirect(url_for('admin_login'))
    print(user_id,field,value)
    user = User.query.filter_by(id=user_id).first()
    print(user)
    # Approve/Reject & Block/Unblock professional
    if user and  field == 'approve':
        if value == 'False':
            user.approve = True
            flash('Professional approved successfully', 'success')
        elif value == 'True':
            user.approve = False
            flash('Professional rejected successfully', 'danger')

    if user and field == 'blocked' :
        if value == 'False':
            user.blocked = True
            flash('User blocked successfully', 'danger')
        elif value == 'True':
            user.blocked = False
            flash('User unblocked successfully', 'success')

    # Save changes to the database
    db.session.commit()

    return redirect(url_for('admin_dashboard'))

# Manage Services Route (CRUD operations)
@app.route('/admin/services/create_services', methods=['GET', 'POST'])
def create_services():
    if not session.get('admin_user_id'):
        flash('Please log in to complete your profile.', 'danger')
        return redirect(url_for('admin_login'))
    
    form = ServiceForm()
    
    # Create Service
    if form.validate_on_submit():
        new_service = Service(
            service_type=form.service_type.data,
            name=form.name.data,
            price=form.price.data,
            description=form.description.data
        )
        db.session.add(new_service)
        flash('Service created successfully', 'success')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('create_services.html', form=form)

# Update Services Route (CRUD operations)
@app.route('/admin/services/update_service/<int:service_id>', methods=['GET', 'POST'])
def update_services(service_id):
    if not session.get('admin_user_id'):
        flash('Please log in to complete your profile.', 'danger')
        return redirect(url_for('admin_login'))
    service = Service.query.get_or_404(service_id)
    form = ServiceForm(obj=service)
    
    # Update Service
    if form.validate_on_submit():
        service.id = service_id
        service.service_type = form.service_type.data
        service.name = form.name.data
        service.price = form.price.data
        service.description = form.description.data
        flash('Service updated successfully', 'success')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('create_services.html', form=form,service=service,editing=True)

# Handle delete operation
@app.route('/admin/services/delete_service/<int:service_id>', methods=['GET', 'POST'])
def delete_services(service_id):
    service_to_delete = Service.query.get(service_id)
    if service_to_delete:
        db.session.delete(service_to_delete)
        db.session.commit()
        flash('Service deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# Logout route for admin
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/customer/profile', methods=['GET', 'POST'])
def customer_profile():
    if not session.get('user_id'):
        flash('Please log in to complete your profile.', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    form = CustomerProfileForm()
    form.user_id.data = user_id
    form.user_name.data = User.query.get(user_id).username

    if form.validate_on_submit():
        new_customer_profile = CustomerProfile(
                user_id = form.user_id.data,
                full_name = form.full_name.data,
                address = form.address.data,
                pin_code = form.pin_code.data
            )            
        db.session.add(new_customer_profile)
        db.session.commit()
        flash('Customer Profile updated successfully!', 'success')
        return redirect(url_for('customer_dashboard'))

    return render_template('customer_profile.html', form=form)


# `Customer` Dashboard
@app.route('/customer/dashboard', methods=['GET', 'POST'])
def customer_dashboard():
    if 'user_id' in session:
        if request.args.get("service_type"):
            services = Service.query.filter_by(service_type=request.args.get("service_type")).all()
        else:
            services = []
        return render_template('customer_dashboard.html', services=services)
    return redirect(url_for('login'))

@app.route('/customer/search')
def customer_search():
    if 'user_id' in session:
        services = Service.query.all()
        return render_template('customer_dashboard.html', services=services)
    return redirect(url_for('login'))

@app.route('/customer/summary')
def customer_summary():
    if 'user_id' in session:
        services = Service.query.all()
        return render_template('customer_summary.html', services=services)
    return redirect(url_for('login'))


@app.route('/customer/create_service_request', methods=['POST'])
def create_service_request():
    if 'user_id' in session:
        service_id = request.form['service_id']
        customer_id = session['user_id']
        professional_id = ProfessionalProfile.query.filter_by(service_type=service_id).first().user_id
        service_request = ServiceRequest(service_id=service_id, customer_id=customer_id, professional_id= professional_id, service_status='requested')
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
    form.user_name.data = User.query.get(user_id).username

    if form.validate_on_submit():
        # Handle file upload
        file = form.file.data
        if file and allowed_file(file.filename):
            # Secure the filename and save it to the UPLOAD_FOLDER
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Save file metadata and other form data to the database
            
            new_professional_profile = ProfessionalProfile(
                user_id = form.user_id.data,
                full_name = form.full_name.data,
                filename = filename,
                service_type = form.service_type.data,
                experience = form.experience.data,
                address = form.address.data,
                pin_code = form.pin_code.data
            )            
            db.session.add(new_professional_profile)
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('professional_dashboard'))
        else:
            flash('Invalid file format! Please upload only images and PDFs.', 'danger')
            print("in else block")
            return redirect(url_for('professional_profile'))
    return render_template('professional_profile.html', form=form)

@app.route('/professional/dashboard')
def professional_dashboard():
    if 'user_id' in session:
        professional_id = session['user_id']
        service_requests = ServiceRequest.query.filter_by(professional_id=professional_id).all()
        serviceIdList = []    
        for request in service_requests:
            serviceIdList.append(request.service_id)
        services = Service.query.filter(Service.id.in_(serviceIdList)).all()
        return render_template('professional_dashboard.html', service_requests=service_requests, services=services)
    return redirect(url_for('login'))

@app.route('/professional/search')
def professional_search():
    if 'user_id' in session:
        professional_id = session['user_id']
        service_requests = ServiceRequest.query.filter_by(professional_id=professional_id).all()
        serviceIdList = []    
        for request in service_requests:
            serviceIdList.append(request.service_id)
        services = Service.query.filter(Service.id.in_(serviceIdList)).all()
        return render_template('professional_dashboard.html', service_requests=service_requests, services=services)
    return redirect(url_for('login'))

@app.route('/professional/summary')
def professional_summary():
    if 'user_id' in session:
        professional_id = session['user_id']
        service_requests = ServiceRequest.query.filter_by(professional_id=professional_id).all()
        serviceIdList = []    
        for request in service_requests:
            serviceIdList.append(request.service_id)
        services = Service.query.filter(Service.id.in_(serviceIdList)).all()
        return render_template('professional_summary.html', service_requests=service_requests, services=services)
    return redirect(url_for('login'))


@app.route('/professional/update_request_status/<int:request_id>', methods=['POST'])
def update_request_status(request_id):
    if 'user_id' in session:
        service_request = ServiceRequest.query.get_or_404(request_id)
        action = request.form['action']
        
        if action == 'complete':
            service_request.service_status = 'completed'
            service_request.date_of_completion = db.func.current_timestamp()
        elif action == 'reject':
            service_request.service_status = 'rejected'
            service_request.date_of_completion = db.func.current_timestamp()
        
        db.session.commit()
        flash('Service request updated successfully!', 'success')
        return redirect(url_for('professional_dashboard'))
    return redirect(url_for('login'))

@app.route('/data1')
def data1():
    # Example data for Chart 1
    labels = ['January', 'February', 'March', 'April', 'May', 'June', 'July']
    values = [12, 19, 3, 5, 2, 3, 7]
    return jsonify(labels=labels, values=values)

@app.route('/data2')
def data2():
    # Example data for Chart 2
    labels = ['August', 'September', 'October', 'November', 'December']
    values = [10, 20, 15, 25, 30]
    return jsonify(labels=labels, values=values)

if __name__ == '__main__':
    app.run(debug=True)