import os
from flask import Flask, render_template, session, redirect, url_for, flash, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField 
import sqlite3
import re
import hashlib
import pandas
from datetime import datetime # Packages needed

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asmodeus'

# Database intialization and table creation
# Opening a connection to (or creating if run first time) an sqlite database
conn = sqlite3.connect('itf.db')

# Creating a cursor object to execute SQL commands          
cursor = conn.cursor()

# Creating tables in the database with SQL commands
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    email TEXT PRIMARY KEY,
                    password TEXT,
                    name TEXT,
                    surname TEXT,
                    gender TEXT,
                    age INTEGER,
                    weight NUMERIC,
                    belt INTEGER                  
                )''')

cursor.execute('''CREATE TABLE IF NOT EXISTS competitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    caption TEXT,
                    description TEXT,
                    price_junior INTEGER,
                    price_adult INTEGER,
                    address TEXT,
                    date TEXT,
                    time TEXT,
                    table_name TEXT                  
                )''')

cursor.execute('''CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password TEXT                 
                )''')

conn.commit() # Saving changes to the database
cursor.close() # Closing the connection
conn.close() # Closing the connection

# Forms initialization for inputs from users 

class RegForm(FlaskForm):

    email = StringField("Email: ")
    name = StringField("First name: ")
    surname = StringField("Last name: ")
    gender = SelectField("Your gender: ", choices=[('Male', 'Male'), ('Female', 'Female')])
    age = StringField("Your age: ")
    weight = StringField("Your weight, kg: ")
    belt = SelectField("Your belt: ", choices=[('1', 'White'), ('2', 'White with yellow stripe'),
                                               ('3', 'Yellow'), ('4', 'Yellow with green stripe'),
                                               ('5', 'Green'), ('6', 'Green with blue stripe'),
                                               ('7', 'Blue'), ('8', 'Blue with red stripe'),
                                               ('9', 'Red'), ('10', 'Red with black stripe'),
                                               ('11', 'Black 1st Degree'), ('12', 'Black 2nd Degree'),
                                               ('13', 'Black 3rd Degree'), ('14', 'Black 4th Degree'),
                                               ('15', 'Black 5th Degree'), ('16', 'Black 6th Degree'),
                                               ('17', 'Black 7th Degree'), ('18', 'Black 8th Degree'),
                                               ('19', 'Black 9th Degree')])
    password = StringField("Password: ")
    submit = SubmitField("Register")

class LoginForm(FlaskForm):  
    # Creating and defining the type of form fields and adding submit button
    login_email = StringField("Email: ")
    login_password = StringField("Password: ")
    login = SubmitField("Login")

class AdminForm(FlaskForm):  

    admin_password = StringField("Password: ")
    admin_login = SubmitField("Login")

class ComeptitionForm(FlaskForm):

    caption = StringField("Caption: ")
    description = StringField("Description: ")
    price1 = StringField("Entry price, 5-17 years old: ")
    price2 = StringField("Entry price, 18+ years old: ")
    address = StringField("Address: ")
    time = StringField("Start time: ")
    date = StringField("Date: ")
    create = SubmitField("Create")

class ChangeForm(FlaskForm):

    name_change = StringField("Edit first name: ")
    surname_change = StringField("Edit last name: ")
    age_change = StringField("Change age: ")
    weight_change = StringField("Change weight: ")
    belt_change = SelectField("Change your belt: ", choices=[('0', 'No change'), ('1', 'White'), ('2', 'White with yellow stripe'),
                                               ('3', 'Yellow'), ('4', 'Yellow with green stripe'),
                                               ('5', 'Green'), ('6', 'Green with blue stripe'),
                                               ('7', 'Blue'), ('8', 'Blue with red stripe'),
                                               ('9', 'Red'), ('10', 'Red with black stripe'),
                                               ('11', 'Black 1st Degree'), ('12', 'Black 2nd Degree'),
                                               ('13', 'Black 3rd Degree'), ('14', 'Black 4th Degree'),
                                               ('15', 'Black 5th Degree'), ('16', 'Black 6th Degree'),
                                               ('17', 'Black 7th Degree'), ('18', 'Black 8th Degree'),
                                               ('19', 'Black 9th Degree')])
    change = SubmitField("Edit information")

class AdminChangeForm(FlaskForm):  

    admin_old = StringField("Old password: ")
    admin_new = StringField("New password: ")
    admin_pass_change = SubmitField("Change")

class UserChangeForm(FlaskForm):  

    user_old = StringField("Old password: ")
    user_new = StringField("New password: ")
    user_pass_change = SubmitField("Change password")

# Functions for validating users' and admin's inputs

def validate_email(email): # Validation of user email
    # Using possible expressions for email validation
    # 'r' means that the expression is a string
    # [\w\.-]+ --- matching word characters, dots, hyphens
    # @ --- @ symbol
    # \. --- dot symbol
    # \w+ --- matching word characters
    # ^ --- start; $ --- end
    pattern1 = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    pattern2 = r'^[\w\.-]+@[\w\.-]+\.\w+\.\w+$'
    # Using re library to match email and patterns
    if re.match(pattern1, email) or re.match(pattern2, email):
        return True
    else:
        return False
    
def validate_name(name): # Validation of user name

    pattern = r'^[a-zA-Z]+$'
    # Allowing only letters

    if re.match(pattern, name):
        return True
    else:
        return False
    
def validate_age(age): # Validation of user age

    pattern = r'^\d+$'

    if re.match(pattern, age):
        if int(age) > 3 and int(age) < 100:
            return True
        else:
            return False
    else:
        return False
    
def validate_weight(weight): # Validation of user weight

    pattern1 = r'^\d+\.\d+$'
    pattern2 = r'^\d+$'

    if re.match(pattern1, weight) or re.match(pattern2, weight):
        # Converting string to a float number
        if float(weight) > 10.0 and float(weight) < 200.0:
            return True
        else:
            return False
    else:
        return False
    
def validate_password(password): # Validation of user password

    if len(password) >= 6:
        return True
    else:
        return False
    
def validate_price(price): # Validation of competition price

    pattern = r'^\d+$'

    if re.match(pattern, price):
        return True
    else:
        return False
    
def validate_time(time): # Validation of time

    pattern1 = r'^\d{1}:\d{2}$'
    pattern2 = r'^\d{2}:\d{2}$'
    # Pattern for time

    if (re.match(pattern1, time)) or (re.match(pattern2, time)):
        return True
    else:
        return False
    
def validate_null(field): # Null validation

    if not field:
        return True
    else:
        return False
    
def validate_date(date): # Validation of competition date

    pattern = r'^\d{2}\.\d{2}\.\d{4}$'
    # Pattern for date format

    if (re.match(pattern, date)) or (re.match(pattern, date)):
        return True
    else:
        return False

# Functions for verifying data

def verify_email(email): # Verification of user email 

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()
    
    # Executing SELECT SQL command to find the user who has certain email in the table
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()  # Fetching the first matching record, which is the only one in the table

    cursor.close()
    conn.close()

    if user:
        return True 
    else:
        return False
    
def verify_password(email, password): # Verification of user password 

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()

    # Searching for user's password from the user table using user's email
    cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    # Acquiring the first matching record
    user_password = cursor.fetchone()

    cursor.close()
    conn.close()

    if user_password:
        # Hashing the password entered by user and comparing it with the already stored hashed password
        hashed_user_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_user_password == user_password[0]:
            return True         
    return False 

def verify_password_admin(password): # Verification of admin password 

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM admin")
    admin_password = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin_password:
        # Hashing the password and comparing with the already stored hashed password
        hashed_admin_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_admin_password == admin_password[0]:
            return True         
    return False 

# Pages routes 

@app.route('/') # Main page route
def index():
    return render_template('main.html') # Renders pre-created HTML template

@app.route('/events/<int:filter>') # Events page route
def eventpage(filter):

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()

    # Acquiring the information about competitions using SQL SELECT command
    cursor.execute("SELECT id, caption, description, price_junior, price_adult, address, date, time, table_name FROM competitions")
    allcompetitions = cursor.fetchall() # List of tuples
    
    # Defining the length of a list
    n = len(allcompetitions)

    # Bubble sort
    if filter == 1:
        for i in range(n - 1):
            # Going through the list and comparing two adjacent elements
            # With each next loop it compares 1 less times, because the element wit
            # the largest price is already at the end of the list.
            for j in range(n - i - 1):
                if allcompetitions[j][3] >= allcompetitions[j + 1][3]:
                    # Swap COMPETITIONS[j] and COMPETITIONS[j+1], moving larger element to the end
                    allcompetitions[j], allcompetitions[j + 1] = allcompetitions[j + 1], allcompetitions[j]

    if filter == 2:
        for i in range(n - 1):
            for j in range(n - i - 1):
                if allcompetitions[j][4] >= allcompetitions[j + 1][4]:
                    # Swap COMPETITIONS[j] and COMPETITIONS[j+1]
                    allcompetitions[j], allcompetitions[j + 1] = allcompetitions[j + 1], allcompetitions[j]

    if filter == 3:
        for i in range(n - 1):
            for j in range(n - i - 1):
                # datetime library is used to convert the string in format "dd.mm.yyyy" to date
                # %d - two numbers repr. day of month, %m - two num. repr. month, %Y - four num. repr. year
                date1 = datetime.strptime(allcompetitions[j][6], "%d.%m.%Y")
                date2 = datetime.strptime(allcompetitions[j+1][6], "%d.%m.%Y")
                if date1 >= date2: 
                    allcompetitions[j], allcompetitions[j + 1] = allcompetitions[j + 1], allcompetitions[j]
    
    # Array for checking whether the user is signed up for a competition
    reg_check = [0] * n
    for p in range(n):
        # Checking for every competition using a loop
        current_competition = allcompetitions[p][8]
        cursor.execute("SELECT email FROM {} WHERE email = ?".format(current_competition), (session['email'],))
        user = cursor.fetchone()
        if user:
            reg_check[p] = 1
        else:
            reg_check[p] = 0
                    
    cursor.close()
    conn.close()

    return render_template('events.html', allcompetitions=allcompetitions, filter=filter, reg_check=reg_check, n=n)

@app.route('/register', methods=['GET','POST']) # Register page route
def registerpage():
    
    form = RegForm()

    if form.validate_on_submit():

        session['email'] = form.email.data
        password = form.password.data
        session['name'] = form.name.data
        session['surname'] = form.surname.data
        session['gender'] = form.gender.data
        session['age'] = form.age.data
        session['weight'] = form.weight.data
        session['belt'] = int(form.belt.data)
        session['displbelt'] = dict(form.belt.choices).get(str(session['belt']))

        if   (verify_email(session['email']) == True):
            flash('This email already has a created account.', 'alert')

        # Calling different validation methods and passing session variables with data 
        # obtained from the form to make sure data is entered in the right format.
        elif (validate_email(session['email']) == False):
            flash('Please, enter the correct and legitimate email.', 'alert')
        
        elif (validate_name(session['name']) == False):
            flash('Your name should not inlude any numbers, special characters, etc.', 'alert')
        
        elif (validate_name(session['surname']) == False):
            flash('Your name should not inlude any numbers, special characters, etc.', 'alert')
        
        elif (validate_age(session['age']) == False):
            flash('Please, enter your true age.', 'alert')
        
        elif (validate_weight(session['weight']) == False):
            flash('Please, enter your true weight as an integer (e.g. 74), or a fractional number (e.g. 74.7).', 'alert')

        elif (validate_password(password) == False):
            flash('Your password should include more than 5 characters.', 'alert')          

        else:

            session['userlogin'] = True
            # Creating a separate sha256 object and converting it to a hexadecimal string
            password_hashed = hashlib.sha256(password.encode()).hexdigest()

            conn = sqlite3.connect('itf.db')
            cursor = conn.cursor()
            # User data is inserted into the users table using SQLite3 INSERT command.
            cursor.execute("INSERT INTO users (email, password, name, surname, gender, age, weight, belt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (session['email'],
                                                                                                                                             password_hashed,
                                                                                                                                             session['name'],
                                                                                                                                             session['surname'],
                                                                                                                                             session['gender'],
                                                                                                                                             session['age'],
                                                                                                                                             session['weight'],
                                                                                                                                             session['belt']))
            
            conn.commit()
            cursor.close()
            conn.close()

            flash('Sucessful registration! Thank you for joining!', 'success')
            return redirect(url_for('index'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST']) # User login page route
def loginpage():

    form = LoginForm()

    if form.validate_on_submit(): # When the form is submitted, following code is executed
        # Records the data from the form email field to the session variable
        session['email'] = form.login_email.data 
        # Records the data from the form password field to the variable
        password = form.login_password.data

        # Calling different verification methods and passing variables with data 
        # obtained from the form to make sure the user is trying to authorize correctly. 
        if verify_email(session['email']) == False:
            flash('This email does not have an account. Check if the email is entered correctly, or create a new account.', 'alert')

        elif verify_password(session['email'], password) == False:
            flash('Check whether an email or password are entered correctly.', 'alert')

        else:
            conn = sqlite3.connect('itf.db')
            cursor = conn.cursor()
            # Acquiring the user data from the database
            cursor.execute("SELECT name, surname, gender, age, weight, belt FROM users WHERE email = ?", (session['email'],))
            userdata = cursor.fetchone()  
            # Assigning user data to different session variables
            session['name'] = userdata[0]
            session['surname'] = userdata[1]
            session['gender'] = userdata[2]
            session['age'] = userdata[3]
            session['weight'] = userdata[4]
            session['belt'] = userdata[5]
            
            conn.close()

            # Variable which is used to indicate that user is logged in
            session['userlogin'] = True
            flash('Sucessful login! Welcome back.' , 'success')
            return redirect(url_for('index'))
    
    return render_template('login.html', form=form)

@app.route('/admin', methods=['GET','POST']) # Admin login page route
def adminpage():

    form = AdminForm()    

    if form.validate_on_submit():

        admin_pass = form.admin_password.data
        if verify_password_admin(admin_pass) == True:
            session['adminlogin'] = True
            flash('Sucessfully logged in! Welcome back!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Wrong password!', 'alert')
            return redirect(url_for('adminpage'))     
        
    return render_template('admin.html', form=form)

@app.route('/profile', methods=['GET','POST']) # Profile page route
def profilepage():

    form = ChangeForm() 
    form1 = UserChangeForm()
    form2 = AdminChangeForm()

    if form.validate_on_submit(): # Form for changing user's personal info

        conn = sqlite3.connect('itf.db') 
        cursor = conn.cursor() 

        session['name_change'] = form.name_change.data
        session['surname_change'] = form.surname_change.data
        session['age_change'] = form.age_change.data
        session['weight_change'] = form.weight_change.data
        session['belt_change'] = int(form.belt_change.data)      
        
         
        if session['belt_change'] != 0:

            session['belt'] = int(session['belt_change'])                  

            cursor.execute("UPDATE users SET belt = ? WHERE email = ?", ((session['belt']), (session['email'])))
            session['displbelt'] = dict(form.belt_change.choices).get(str(session['belt']))

            flash('Belt: successful change!', 'success')

        # Following code checks whether the field is not null
        # If not, it validates the information entered
        # And if no problems occur, it chnages information, updates it in the database
        # It is repeated for each form field
        if validate_null(session['name_change']) == False:

            if validate_name(session['name_change']) == False:

                flash('Your first name should not inlude any numbers, special characters, etc.', 'alert')

                conn.commit()
                cursor.close()
                conn.close()

                return redirect(url_for('profilepage'))   
                         
            else:

                session['name'] = session['name_change']                       
                cursor.execute("UPDATE users SET name = ? WHERE email = ?", ((session['name']), (session['email'])))                
                flash('First name: successful change!', 'success')
                
        if validate_null(session['surname_change']) == False:

            if validate_name(session['surname_change']) == False:

                flash('Your last name should not inlude any numbers, special characters, etc.', 'alert')

                conn.commit()
                cursor.close()
                conn.close()

                return redirect(url_for('profilepage'))
            
            else:

                session['surname'] = session['surname_change']   
                cursor.execute("UPDATE users SET surname = ? WHERE email = ?", ((session['surname']), (session['email'])))
                flash('Last name: successful change!', 'success')

        if validate_null(session['age_change']) == False:

            if validate_age(session['age_change']) == False:

                flash('Please, enter your real age.', 'alert')

                conn.commit()
                cursor.close()
                conn.close()

                return redirect(url_for('profilepage'))
            
            else:

                session['age'] = session['age_change']  
                cursor.execute("UPDATE users SET age = ? WHERE email = ?", ((session['age']), (session['email'])))
                flash('Age: successful change!', 'success')
               
        if validate_null(session['weight_change']) == False:

            if validate_weight(session['weight_change']) == False:

                flash('Please, enter your real weight.', 'alert') 

                conn.commit()
                cursor.close()
                conn.close()

                return redirect(url_for('profilepage'))
            
            else:

                session['weight'] = session['weight_change'] 
                cursor.execute("UPDATE users SET weight = ? WHERE email = ?", ((session['weight']), (session['email'])))  
                flash('Weight: successful change!', 'success')
        
        conn.commit()
        cursor.close()
        conn.close()
                 
        return redirect(url_for('profilepage'))

    if session['userlogin'] == True: # Checking who is signed in

        if form1.validate_on_submit():  # Form for changing user's password

            old_password_user = form1.user_old.data
            new_password_user = form1.user_new.data

            if verify_password(session['email'], old_password_user) == True:

                if validate_password(new_password_user) == False:

                    flash('Your password should include more than 5 characters.', 'alert') 
                    return redirect(url_for('profilepage'))   
                
                else:

                    conn = sqlite3.connect('itf.db')
                    cursor = conn.cursor()

                    # Converting the password using hashlib and updating it in the database with SQL Command
                    passs = hashlib.sha256(new_password_user.encode()).hexdigest()
                    cursor.execute("UPDATE users SET password = ? WHERE email = ?", (passs, session['email']))

                    conn.commit()
                    cursor.close()
                    conn.close()     

                    flash('Successfully changed.', 'success')     
                    return redirect(url_for('profilepage'))  
                         
            else:

                flash('Your old password is not right!', 'alert')            
                return redirect(url_for('profilepage'))
        
    if session['adminlogin'] == True: # Checking who is signed in

        if form2.validate_on_submit(): # Form for changing user's password

            old_password_admin = form2.admin_old.data
            new_password_admin = form2.admin_new.data

            if verify_password_admin(old_password_admin) == True:

                if validate_password(new_password_admin) == False:

                    flash('Your password should include more than 5 characters.', 'alert') 
                    return redirect(url_for('profilepage'))   
                
                else:

                    conn = sqlite3.connect('itf.db')
                    cursor = conn.cursor()
                    # Converting the password using hashlib and updating it in the database with SQL Command
                    passs = hashlib.sha256(new_password_admin.encode()).hexdigest()
                    cursor.execute("UPDATE admin SET password = ? WHERE id = ?", (passs, 1))

                    conn.commit()
                    cursor.close()
                    conn.close() 

                    flash('Successfully changed.', 'success')     
                    return redirect(url_for('profilepage'))      
                    
            else:

                flash('Your old password is not right!', 'alert')
                return redirect(url_for('profilepage'))    
    
    return render_template('profile.html', form=form, form1=form1, form2=form2)

@app.route('/loggingout') # Route for logging out
def loggingout():

    # Nulling session varibales
    session['userlogin'] = False
    session['adminlogin'] = False
    session['name'] = None
    session['surname'] = None
    session['gender'] = None
    session['age'] = None
    session['weight'] = None
    session['belt'] = None
    session['email'] = None

    flash('Sucessfully logged out!', 'info')
    return render_template('main.html')

@app.route('/competition', methods=['GET','POST']) # Competiton creation page route
def competitioncreation():

    form = ComeptitionForm()

    session['caption'] = form.caption.data
    session['description'] = form.description.data
    session['price1'] = form.price1.data
    session['price2'] = form.price2.data
    session['time'] = form.time.data
    session['address'] = form.address.data
    session['date'] = form.date.data

    if form.validate_on_submit():

        if (validate_null(session['caption']) == True) or (validate_null(session['description']) == True) or (validate_null(session['address']) == True):
            flash('Please, fill in all the fields.', 'alert')
        
        elif (validate_price(session['price1']) == False) or (validate_price(session['price2']) == False):
            flash('Please, enter the proper numerical price.', 'alert')
        
        elif (validate_date(session['date']) == False):
            flash('Please, enter the date in the proper format.', 'alert')

        elif (validate_time(session['time']) == False):
            flash('Please, enter the time in the proper format.', 'alert')       
        
        else:
            flash('Competition is created!', 'success')

            conn = sqlite3.connect('itf.db')
            cursor = conn.cursor()
            # Creating a row for a competition
            cursor.execute("INSERT INTO competitions (caption, description, price_junior, price_adult, address, date, time) VALUES (?, ?, ?, ?, ?, ?, ?)", (session['caption'],
                                                                                                                                                            session['description'],
                                                                                                                                                            session['price1'],
                                                                                                                                                            session['price2'],
                                                                                                                                                            session['address'],
                                                                                                                                                            session['date'],
                                                                                                                                                            session['time']))
            cursor.execute("SELECT id FROM competitions WHERE caption = ? AND address = ? AND date = ?", (session['caption'], session['address'], session['date']))
            number = cursor.fetchone()
            name_database = f"Competition_{number[0]}"  # Creating the name for the table

            # Creating the table using a formatted SQL command
            create_table_query = f"CREATE TABLE IF NOT EXISTS {name_database} (email TEXT PRIMARY KEY)"
            cursor.execute(create_table_query)
            # Add name of the new created table to the relevant competition row in competitions table
            conn.execute("UPDATE competitions SET table_name = ? WHERE id = ?", (name_database, number[0])) 

            conn.commit()
            cursor.close()
            conn.close()

            return redirect(url_for('eventpage', filter=0))

    return render_template('competition.html', form=form)

@app.route('/signingup/<competition>/<email>') # Route for signing up for a competition
def signingupforcomp(competition, email):

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()
   
   # Adding user's email to the relevant competition table
    adding = f"INSERT INTO {competition} VALUES (?)"
    cursor.execute(adding, (email,))          

    conn.commit()
    cursor.close()
    conn.close()

    flash('You successfully signed up!', 'success')
    return redirect(url_for('eventpage', filter=0))

@app.route('/signingout/<competition>/<email>') # Route for signing out from a competition
def signingoutofcomp(competition, email):

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()
   
   # Deleting user's email from the relevant competition table
    email_to_remove = f"DELETE FROM {competition} WHERE email = ?"
    cursor.execute(email_to_remove, (email,))          

    conn.commit()
    cursor.close()
    conn.close()

    flash('You signed out.', 'info')
    return redirect(url_for('eventpage', filter=0))

@app.route('/export/<competition>', methods=['GET']) # Route for exporting participants
def export(competition):

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()

    # Setting up an array with conditions for sorting people into categories
    conditions = ("belt < 11 AND gender = 'Male' AND age < 18",
                  "belt >= 11 AND gender = 'Male' AND age < 18",
                  "belt < 11 AND gender = 'Male' AND age >= 18",
                  "belt >= 11 AND gender = 'Male' AND age >= 18",
                  "belt < 11 AND gender = 'Female' AND age < 18",
                  "belt >= 11 AND gender = 'Female' AND age < 18",
                  "belt < 11 AND gender = 'Female' AND age >= 18",
                  "belt >= 11 AND gender = 'Female' AND age >= 18")
    
    # Setting up an array with names for each category to use in Excel file
    categories_names = ("M_J Gup", "M_J Dan", "M_A Gup", "M_A Dan",
                        "F_J Gup", "F_J Dan", "F_A Gup", "F_A Dan")
    
    info_df_dict = {} # Empty dictionary for storing dataframes with user information

    # Acquiring every email from the relevant competition table
    comp_emails_query = f"SELECT email FROM {competition}"
    cursor.execute(comp_emails_query)
    # Creating a list with all emails using cursor as iterator
    comp_emails = [row[0] for row in cursor]
    
    count = 0
    for i in conditions: # Iterating through the conditions array until the last condition
        # Creating a formatted query with needed condition and emails list
        info_query = f"SELECT name, surname, gender, age, weight, belt FROM users WHERE {i} AND email IN ({','.join(['?'] * len(comp_emails))})"
        # Using pandas library, executing SQL command and inserting results in the dataframe
        info_data_df = pandas.read_sql_query(info_query, conn, params=comp_emails)
        # Inserting a dataframe with competitors and an according category name in the dictionary
        info_df_dict[categories_names[count]] = info_data_df
        count += 1

    cursor.close()
    conn.close()

    # Creating an Excel file
    excel_file = 'competitors.xlsx'

    with pandas.ExcelWriter(excel_file) as writer:
        # Iterating through the dictionary
        for category_name, competitor_info in info_df_dict.items():
            # Inserting each dataframe to a new sheet with the name 'category_name'
            competitor_info.to_excel(writer, sheet_name = category_name, index=False)    

    # Send the Excel file for dowload to user with the competitors' information
    return send_file(excel_file, as_attachment=True)

@app.route('/delete/<competition>', methods=['GET']) # Route for deleting a competition
def delete(competition):

    conn = sqlite3.connect('itf.db')
    cursor = conn.cursor()

    # Deleting relevant competition from the competition table
    query_record_del = f"DELETE FROM competitions WHERE table_name = '{competition}'"
    cursor.execute(query_record_del)

    # Deleting relevant table which is responsible for holding signed up users for this competition
    query_table_del = f"DROP TABLE {competition}"
    cursor.execute(query_table_del)

    conn.commit()
    cursor.close()
    conn.close()

    flash('Competition is deleted.', 'info')
    return redirect(url_for('eventpage', filter=0))

if __name__ == '__main__':
    app.run(debug = False)