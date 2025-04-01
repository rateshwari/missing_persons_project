from flask import Flask, request, jsonify, render_template, send_from_directory, redirect, url_for, flash
import mysql.connector
import os
from werkzeug.utils import secure_filename
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Email

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.secret_key = "your_secret_key_here"  # Secret key for sessions

# Ensure the upload folder exists
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

# MySQL connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",  # Replace with your MySQL password
    database="missing_persons_db"
)
cursor = db.cursor(dictionary=True)  # Fetch results as dictionaries

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Setup Flask-Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Create a User class for login management
class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

# Flask-WTF forms for login and registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=30)])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])


# Routes for login and registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        cursor.execute("INSERT INTO User (username, email, password) VALUES (%s, %s, %s)", (username, email, password))
        db.commit()

        flash("Registration successful. Please log in.", 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor.execute("SELECT * FROM User WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[3], password):  # user[3] is the hashed password
            logged_in_user = User(user[0], user[1], user[2], user[3])
            login_user(logged_in_user)
            flash("Login successful!", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.", 'danger')

    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))


# Function to load the current user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT * FROM User WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    return User(user[0], user[1], user[2], user[3]) if user else None


# Allowed file types for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# Home Route
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/add_missing_person', methods=['POST'])
def add_missing_person():
    if 'photo' not in request.files:
        return jsonify({"error": "No photo uploaded"}), 400

    photo = request.files['photo']
    if not allowed_file(photo.filename):
        return jsonify({"error": "Invalid file type. Only JPG, PNG, JPEG allowed."}), 400

    name = request.form.get('name')
    age = request.form.get('age')
    gender = request.form.get('gender')
    last_seen_location = request.form.get('last_seen_location')
    contact_info = request.form.get('contact_info')

    if not all([name, age, gender, last_seen_location, contact_info]):
        return jsonify({"error": "All fields are required"}), 400

    filename = secure_filename(photo.filename)
    photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    photo.save(photo_path)

    try:
        sql = "INSERT INTO missing_persons (name, age, gender, last_seen_location, contact_info, photo, status) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        values = (name, age, gender, last_seen_location, contact_info, filename, 'Still Missing')  # Default status to 'Still Missing'
        cursor.execute(sql, values)
        db.commit()
        return jsonify({"message": "Missing person added successfully"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500

@app.route('/view_reports', methods=['GET'])
def view_reports():
    search_query = request.args.get('search', '').strip()
    name = request.args.get('name', '').strip()
    age = request.args.get('age', '').strip()
    gender = request.args.get('gender', '').strip()
    location = request.args.get('location', '').strip()

    try:
        if search_query or name or age or gender or location:
            sql = """SELECT id, name, age, gender, last_seen_location, contact_info, report_date, photo, status
                     FROM missing_persons
                     WHERE name LIKE %s OR age LIKE %s OR gender LIKE %s OR last_seen_location LIKE %s"""
            values = (f"%{search_query}%", f"%{name}%", f"%{age}%", f"%{gender}%", f"%{location}%")
        else:
            sql = "SELECT id, name, age, gender, last_seen_location, contact_info, report_date, photo, status FROM missing_persons"
            values = ()

        cursor.execute(sql, values)
        reports = cursor.fetchall()

        reports_list = []
        for row in reports:
            reports_list.append({
                "id": row["id"],
                "name": row["name"],
                "age": row["age"],
                "gender": row["gender"],
                "last_seen_location": row["last_seen_location"],
                "contact_info": row["contact_info"],
                "report_date": row["report_date"],
                "photo": row["photo"],
                "status": row["status"]
            })

        return render_template('reports.html', reports=reports_list)

    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500

@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    try:
        cursor.execute("DELETE FROM missing_persons WHERE id = %s", (report_id,))
        db.commit()
        return redirect(url_for('view_reports'))
    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500

@app.route('/update_report_status/<int:report_id>', methods=['POST'])
def update_report_status(report_id):
    status = request.form.get('status')

    if status not in ['Still Missing', 'Found']:
        return jsonify({"error": "Invalid status value"}), 400

    try:
        cursor.execute("UPDATE missing_persons SET status = %s WHERE id = %s", (status, report_id))
        db.commit()
        return redirect(url_for('view_reports'))
    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500

@app.route('/edit_report/<int:report_id>', methods=['GET', 'POST'])
def edit_report(report_id):
    if request.method == 'GET':
        try:
            cursor.execute("SELECT * FROM missing_persons WHERE id = %s", (report_id,))
            report = cursor.fetchone()
            if report:
                return render_template("edit_report.html", report=report)
            else:
                return jsonify({"error": "Report not found"}), 404
        except mysql.connector.Error as err:
            return jsonify({"error": f"Database error: {err}"}), 500
    else:
        name = request.form.get('name')
        age = request.form.get('age')
        gender = request.form.get('gender')
        last_seen_location = request.form.get('last_seen_location')
        contact_info = request.form.get('contact_info')

        filename = None
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo.filename != '':
                if allowed_file(photo.filename):
                    filename = secure_filename(photo.filename)
                    photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    photo.save(photo_path)
                else:
                    return jsonify({"error": "Invalid file type. Only JPG, PNG, JPEG allowed."}), 400

        try:
            if filename:
                cursor.execute("""
                    UPDATE missing_persons 
                    SET name = %s, age = %s, gender = %s, last_seen_location = %s, contact_info = %s, photo = %s 
                    WHERE id = %s
                """, (name, age, gender, last_seen_location, contact_info, filename, report_id))
            else:
                cursor.execute("""
                    UPDATE missing_persons 
                    SET name = %s, age = %s, gender = %s, last_seen_location = %s, contact_info = %s 
                    WHERE id = %s
                """, (name, age, gender, last_seen_location, contact_info, report_id))

            db.commit()
            return redirect(url_for('view_reports'))
        except mysql.connector.Error as err:
            db.rollback()
            return jsonify({"error": f"Database error: {err}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
