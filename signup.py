from flask import Flask, request, render_template, redirect, url_for, flash, session
import mysql.connector
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO,emit

# Initialize Flask app
app = Flask(__name__)  # Flask app setup
app.secret_key = 'your_secret_key_here'  # Used for session management and flash messages
bcrypt = Bcrypt(app)

# Initialize the SocketIO instance
socketio = SocketIO(app)

# Database connection setup with your details
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='mansich@123',
            database='project'
        )
        return connection
    except mysql.connector.Error as err:
        flash(f"Database connection error: {err}", 'danger')
        return None

# Route for the home page (open_project.html)
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('tmp'))  # If logged in, go to open_project
    else:
        return redirect(url_for('login'))   # Else, go to login

@app.route('/open_project')
def result():
    return render_template('open_project.html')

@app.route('/tmp')
def tmp():
    return render_template('index.html')

# Route for the login page (login.html)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed', 'danger')
            return redirect(url_for('login'))

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM signup WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            # Check if the password matches
            if bcrypt.check_password_hash(user[3], password):  # user[3] is the password_hash column
                session['user_id'] = user[0]  # Save user_id in session
                session['email'] = user[2]  # Save user email in session
                session.permanent = True  # ✅ Keep user logged in for a long time
                flash('Login successful!', 'success')
                return redirect(url_for('tmp'))
            else:
                flash('Incorrect password!', 'danger')
        else:
            flash('Email not found!', 'danger')

        cursor.close()
        conn.close()

    return render_template('login.html')

# Route for the signup page (signup.html)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['fullName']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        agree = request.form.get('agree')

        # Validation checks
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        if not agree:
            flash('You must agree to the Terms and Conditions!', 'danger')
            return redirect(url_for('signup'))

        if '@' not in email or '.' not in email:
            flash('Invalid email format!', 'danger')
            return redirect(url_for('signup'))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed', 'danger')
            return redirect(url_for('signup'))

        cursor = conn.cursor()
        try:
            # Check if email already exists
            cursor.execute("SELECT * FROM signup WHERE email = %s", (email,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash('This email is already registered. Please log in instead.', 'danger')
                return redirect(url_for('signup'))

            # Insert new user
            cursor.execute(
                "INSERT INTO signup (username, email, password_hash) VALUES (%s, %s, %s)",
                (full_name, email, password_hash)
            )
            conn.commit()

            # Log the user in
            session['user_id'] = cursor.lastrowid
            session['email'] = email

            return redirect(url_for('index'))  # Redirect to index without flashing a message

        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
            conn.rollback()

        cursor.close()
        conn.close()

    return render_template('signup.html')


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to access your profile.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM signup WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()

    if user_data:
        username, email = user_data
        return render_template('profile.html', username=username, email=email)
    else:
        flash("User not found!", "danger")
        return redirect(url_for('login'))
    

# Route for the project details page (projectdetails.html)
@app.route('/projectdetails', methods=['GET', 'POST'])
def projectdetails():
    if request.method == 'POST':
        project_name = request.form['project-name']
        description = request.form['description']
        start_date = request.form['start-date']
        end_date = request.form['end-date']

        user_id = session.get('user_id')
        if not user_id:
            flash('You must be logged in to save project details!', 'danger')
            return redirect(url_for('login'))

        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed!', 'danger')
            return redirect(url_for('projectdetails'))

        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO details (project_name, description, start_date, end_date, user_id) "
                "VALUES (%s, %s, %s, %s, %s)",
                (project_name, description, start_date, end_date, user_id)
            )
            conn.commit()
            flash('Project details saved successfully!', 'success')
            return redirect(url_for('creategroup'))
        except mysql.connector.Error as err:
            flash(f"Error saving project details: {err}", 'danger')
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    return render_template('projectdetails.html')

# Route for the group creation page (creategroup.html)
@app.route('/creategroup', methods=['GET', 'POST'])
def creategroup():
    invite_link = None  # Initialize the invite_link variable

    if request.method == 'POST':
        # Get form data
        group_name = request.form['group-name']
        members = request.form.getlist('members[]')  # List of member emails
        roles = request.form.getlist('roles[]')      # List of roles corresponding to members
        
        # Get user_id of the group creator from session
        user_id = session.get('user_id')
        if not user_id:
            flash('You must be logged in to create a group!', 'danger')
            return redirect(url_for('login'))

        # Save group data to database
        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed!', 'danger')
            return redirect(url_for('creategroup'))

        cursor = conn.cursor()
        try:
            # Insert group details into groupp table
            cursor.execute(
                "INSERT INTO groupp (group_name, created_by) VALUES (%s, %s)",
                (group_name, user_id)
            )
            group_id = cursor.lastrowid  # Get the inserted group ID
            dynamic_invite_link = f"http://127.0.0.1:5000/workspace?id={group_id}"  # Generate link dynamically

            # Update invite link in the same group record
            cursor.execute(
                "UPDATE groupp SET invite_link = %s WHERE id = %s",
                (dynamic_invite_link, group_id)
            )

            # Insert group members into members table
            for email, role in zip(members, roles):
                cursor.execute(
                    "INSERT INTO members (groupp_id, member_email, role) VALUES (%s, %s, %s)",
                    (group_id, email, role)
                )
            
            conn.commit()
            flash(f'Group created successfully! Share this invite link: {dynamic_invite_link}', 'success')
            invite_link = dynamic_invite_link  # Store the generated invite link to pass to the frontend
        except mysql.connector.Error as err:
            print(f"SQL Error: {err}")  # Print the error for debugging
            flash(f"Error creating group: {err}", 'danger')
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    # Render the template and pass the invite_link to the frontend
    return render_template('creategroup.html', invite_link=invite_link)

# Other routes for project details, about, etc.
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/workspace')
def workspace():
    group_id = request.args.get('id')  # Get the group ID from the URL
    if not group_id:
        flash("Group ID is missing!", "danger")
        return redirect(url_for("tmp"))  # Change to 'tmp' or 'home', based on your needs

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed!", "danger")
        return redirect(url_for("tmp"))  # Change to 'tmp' or 'home', based on your needs

    cursor = conn.cursor(dictionary=True)
    try:
        # Get group info
        cursor.execute("SELECT * FROM groupp WHERE id = %s", (group_id,))
        group = cursor.fetchone()
        if not group:
            flash("Group not found!", "danger")
            return redirect(url_for("tmp"))  # Change to 'tmp' or 'home', based on your needs

        # Fetch project details associated with this group
        cursor.execute("SELECT project_name, description, start_date, end_date FROM details WHERE user_id = %s", (group['created_by'],))
        project = cursor.fetchone()

        # Ensure that any previous result set is consumed
        cursor.fetchall()  # Consume any unread results if necessary

        project_name = project['project_name'] if project else "No Project Name"
        project_description = project['description'] if project else "No Description"
        start_date = project['start_date'] if project else "No Start Date"
        end_date = project['end_date'] if project else "No End Date"

        # Get team members for this group
        cursor.execute("SELECT member_email, role FROM members WHERE groupp_id = %s", (group_id,))
        team = cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"SQL Error: {err}")
        flash("Something went wrong loading the workspace.", "danger")
        return redirect(url_for("tmp"))  # Change to 'tmp' or 'home', based on your needs
    finally:
        cursor.close()
        conn.close()

    return render_template("workspace.html", group=group, team=team, project_name=project_name, project_description=project_description, start_date=start_date, end_date=end_date)


@app.route('/edit_plan/<int:group_id>', methods=['GET', 'POST'])
def edit_plan(group_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Make sure to use dictionary=True

    if request.method == 'POST':
        updated_plan = request.form['plan']

        # Check if the group already has a plan
        cursor.execute("SELECT * FROM plans WHERE group_id = %s", (group_id,))
        existing_plan = cursor.fetchone()

        if existing_plan:
            # Update the existing plan
            cursor.execute("UPDATE plans SET plan_content = %s WHERE group_id = %s", (updated_plan, group_id))
        else:
            # Insert a new plan if it doesn't exist
            cursor.execute("INSERT INTO plans (group_id, plan_content) VALUES (%s, %s)", (group_id, updated_plan))

        conn.commit()
        flash('Plan updated successfully!', 'success')

        # After updating, redirect to the workspace page
        return redirect(url_for('workspace', id=group_id))

    # Retrieve the existing plan content
    cursor.execute("SELECT plan_content FROM plans WHERE group_id = %s", (group_id,))
    plan = cursor.fetchone()

    cursor.close()
    conn.close()

    # Handle the case where plan is None
    plan_content = plan['plan_content'] if plan else ''  # Ensure this is a string or empty string

    return render_template('edit_plan.html', plan=plan_content, group_id=group_id)


# Logout route to clear session
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    flash('You have logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/forgot')
def forgot():
    return render_template('forgot.html')

@socketio.on('message')
def handle_message(msg):
    print('Received message:', msg)
    emit('message', msg, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, debug=True)

