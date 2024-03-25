import binascii
import hashlib
import os
import random
import sqlite3
import string

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = ''


def current_directory_databese(): # function in order to know where the Databese is located

    data = 'data'
    cantorDatebase = 'agency.db'
    sql_DB_Directory = os.path.join(os.getcwd(),data, cantorDatebase)
    sql_DB_Directory = sql_DB_Directory.replace('\\','/')
    # print('sql_DB_Directory',sql_DB_Directory)
    return sql_DB_Directory


app_info = {
    'db_file' : current_directory_databese()
}


def get_db():
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


class Destination:
    def __init__(self, country):
        self.country = country

class ListDestinations:
    def __init__(self):
        self.list_of_destinations = []

    def load_destinations(self):
        self.list_of_destinations.append(Destination('Italy'))
        self.list_of_destinations.append(Destination('Poland'))
        self.list_of_destinations.append(Destination('France'))
        self.list_of_destinations.append(Destination('Germany'))
        self.list_of_destinations.append(Destination('Portugal'))
        self.list_of_destinations.append(Destination('Spain'))
        self.list_of_destinations.append(Destination('Georgia'))


class UserPass:
    def __init__(self, user='', passsword=''):
        self.user = user
        self.password = passsword
        self.email = ''
        self.is_valid = False 
        self.is_admin = False 
     


    def hash_password(self):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')
    
    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'),  100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password
    
    def get_random_user_pasword(self):
        random_user = ''.join(random.choice(string.ascii_lowercase)for i in range(3))
        self.user = random_user

        password_characters = string.ascii_letters #+ string.digits + string.punctuation
        random_password = ''.join(random.choice(password_characters)for i in range(3))
        self.password = random_password

    def login_user(self):
        db = get_db()
        sql_statement = 'SELECT id, name, email, password, is_active, is_admin from users where name=?;'
        cur = db.execute(sql_statement,[self.user])
        user_record = cur.fetchone()

        if user_record != None and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None
        
    def get_user_info(self):
        db = get_db()
        sql_statement = 'SELECT id, name, email, password, is_active, is_admin from users where name=?;'
        cur = db.execute(sql_statement,[self.user])
        db_user = cur.fetchone()

        if db_user  == None:
            self.is_valid = False
            self.is_admin = False
            self.email = ''
        elif db_user['is_active'] !=1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user['email']
        else:
            self.is_valid = True
            self.is_admin = db_user['is_admin']
            self.email = db_user['email']


@app.route('/init_app')
def init_app():
    

    # check if there are users defined (at least one active admin required)
    db=get_db()
    sql_statement= 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admins = cur.fetchone()

    if active_admins!=None and active_admins['cnt']>0:
        flash('Aplication is already set-up. Nothing to do.')
        return redirect(url_for('index'))

    # if not - create/update admin account with a new password and admin privileges, display random username    
    user_pass = UserPass()
    user_pass.get_random_user_pasword()
    db.execute(''' insert into users (name, email, password, is_active, is_admin)
                    values (?,?,?,True,True);''',
                    [user_pass.user, 'admin@admin.no', user_pass.hash_password()])
    
    db.commit()
    flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
    return(redirect(url_for('index')))


@app.route('/login', methods=['GET','POST'])
def login():

    login = UserPass(session.get('user'))
    login.get_user_info()

    if request.method == 'GET':
        return render_template('login.html', active_menu='login', login=login)
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        login = UserPass(user_name,user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash('Logon succesfull, welcome {}'.format(user_name))
            return redirect(url_for('index', active_menu='home'))
        else:
            flash('Logon failed, try again.')
            return render_template('login.html',  active_menu ='login',login=login)
        

@app.route('/logout')
def logout():
    
    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out.')
    return redirect(url_for('login'))


@app.route('/')
def index():

    login = UserPass(session.get('user'))
    login.get_user_info()

    return render_template('index.html', active_menu ='home',login=login)

@app.route('/trips')
def trips():

    login = UserPass(session.get('user'))
    login.get_user_info()


    db = get_db()
    sql_command = "select id, trip_name, cost, destination, description from trips;"
    cur = db.execute(sql_command)
    trips = cur.fetchall()


    return render_template('trips.html',trips=trips, active_menu ='trips',login=login )


@app.route('/add_trip', methods=['GET','POST'])
def add_trip():

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid:
        return redirect(url_for('login'))

    desination_list = ListDestinations()
    desination_list.load_destinations()

    if request.method == 'GET':
        return render_template('add_trip.html', desination_list = desination_list, active_menu ='staff',login=login)
    else:
        trip_name = request.form['trip_name'] if 'trip_name' in request.form else ''
        destination = request.form['destination'] if 'destination' in request.form else ''
        trip_cost = request.form['trip_cost'] if 'trip_cost' in request.form else ''
        description = request.form['description'] if 'description' in request.form else ''

        flash('The trip {} has been added.'.format(trip_name))

        db = get_db()
        sql_command = 'insert into trips(trip_name, destination, cost, description) values(?,?,?,?)'
        db.execute(sql_command, [trip_name,destination, trip_cost, description])
        db.commit()

        return render_template('get_added_trip.html',
                                active_menu ='staff',
                                trip_name=trip_name,
                                destination=destination,
                                desination_list = desination_list,
                                trip_cost=trip_cost,
                                description=description,
                                login=login)


@app.route('/trips_list', methods=['GET','POST'])
def trips_list():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))


    db = get_db()
    sql_command = 'select id, trip_name, destination, cost , adding_trip_date from trips;'
    cur = db.execute(sql_command)
    trips = cur.fetchall()

    return render_template('trips_list.html', trips=trips, active_menu ='staff',login=login)


@app.route('/delete_trip/<int:dest_id>', methods=['GET','POST'])
def delete_trip(dest_id):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    
    db = get_db()
    sql_statement = 'delete from trips where id=?'
    db.execute(sql_statement,[dest_id])
    db.commit()

    return redirect(url_for('trips_list'))


@app.route('/edit_trip/<int:dest_id>', methods=['GET','POST'])
def edit_trip(dest_id):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        return redirect(url_for('login'))

    desination_list = ListDestinations()
    desination_list.load_destinations()
    db = get_db()


    if request.method == 'GET':
        sql_command = 'select id, trip_name, destination, cost, description  from trips where id = ?;'
        cur = db.execute(sql_command, [dest_id])
        trip = cur.fetchone()
        

        if trip == None:
            flash('No such trip.')
            return redirect(url_for('trips_list'))
        else:
            return render_template('edit_trip.html',
                            desination_list = desination_list,
                            trip=trip,
                            active_menu ='staff',
                            login=login)

    else:
        trip_name = request.form['trip_name'] if 'trip_name' in request.form else ''
        destination = request.form['destination'] if 'destination' in request.form else ''
        trip_cost = request.form['trip_cost'] if 'trip_cost' in request.form else ''
        description = request.form['description'] if 'description' in request.form else ''

        sql_command = ''' update trips
                            set
                                trip_name=?,
                                destination=?,
                                cost=?,
                                description=?
                            where
                                id=?'''
        
        db.execute(sql_command,[trip_name,destination,trip_cost,description,dest_id])
        db.commit()

        flash('The trip "{}" has been updated.'.format(trip_name))

        return redirect(url_for('trips_list'))



#---- START - Admin Interface ----#


# list of all users/employees
@app.route('/users')
def users():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    
    db = get_db()
    sql_command = 'select id, name, email, is_active, is_admin from users;'
    cur = db.execute(sql_command)
    users = cur.fetchall()

    return render_template('users.html', active_menu ='admin', users=users,login=login)

# will allow changes to is_active is_admin
@app.route('/user_status_chenge/<action>/<user_name>')
def user_status_chenge(action,user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    
    # if 'user' not in session:
    #     return redirect(url_for('login'))
    # login = session['user']

    db = get_db()

    if action  =='active':
        db.execute(""" update users set is_active = (is_active + 1) % 2
                        where name = ? and name <> ?""", 
                        [user_name, login.user])
        db.commit()
    elif action == 'admin':
                db.execute(""" update users set is_admin = (is_admin + 1) % 2
                           where name = ? and name <> ?""", 
                            [user_name, login.user])
                db.commit()


    return redirect(url_for('users'))

# editing certain user information
@app.route('/edit_user/<user_name>', methods=['GET','POST'])
def edit_user(user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    
    db = get_db()
    cur =db.execute('select name, email from users where name = ?',[user_name])
    user = cur.fetchone()
    message = None

    if user ==None:
        flash('No such user')
        return redirect(url_for('users'))
    
    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='admin', user=user,login=login)
    else:
        new_email  = '' if not 'email' in request.form else request.form['email']
        new_password  = '' if not 'user_pass' in request.form else request.form['user_pass']

        if new_email != user['email']:
            sql_statement = "update users set email = ? where name = ?"
            db.execute(sql_statement, [new_email ,user_name ])
            db.commit()
            flash('Email was changes')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            sql_statement = "update users set password = ? where name = ?"
            db.execute(sql_statement, [user_pass.hash_password(),user_name ])
            db.commit()
            flash('Password was changes')

        return redirect(url_for('users'))

# deleting a user
@app.route('/user_delete/<user_name>')
def user_delete(user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    
    # if 'user' not in session:
    #     return redirect(url_for('login'))
    # login = session['user']

    db = get_db()
    sql_statement = 'delete from users where name=? and name <> ?'
    db.execute(sql_statement,[user_name, login.user])
    db.commit()

    return redirect(url_for('users'))


# adding a new user
@app.route('/new_user', methods=['GET','POST'] )
def new_user():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    
    
    # if 'user' not in session:
    #     return redirect(url_for('login'))
    # login = session['user']

    db= get_db()
    message = None
    user ={}
    
    if request.method == 'GET':
        return render_template('new_user.html', active_menu='admin', user=user,login=login)
    else:
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name'] 
        user['email'] = '' if not 'email' in request.form else request.form['email'] 
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass'] 
    
        cursor = db.execute('select count(*) as cnt from users where name =?', [user['user_name']])
        record = cursor.fetchone()
        is_user_name_unique = (record['cnt'] == 0)

        cursor = db.execute('select count(*) as cnt from users where email =?', [user['email']])
        record = cursor.fetchone()
        is_user_email_unique = (record['cnt'] == 0)


        if user['user_name']  == '':
            message = 'Name cannot be emtpy'
        elif user['email'] == '':
            message = 'email cannot be emtpy'
        elif user['user_pass'] == '':
            message = 'Password cannot be emtpy'
        elif not is_user_name_unique:
            message = 'User with the name {} already exists'.format(user['user_name'])
        elif not is_user_email_unique:
            message = 'User with the email {} already exists'.format(user['email'])

        
        if not message:
            user_pass = UserPass(user['user_name'] ,user['email'] )
            password_hash = user_pass.hash_password()
            sql_statement = '''insert into users
                                    (name,
                                    email,
                                    password,
                                    is_active,
                                    is_admin)
                                values
                                    (?,?,?, True, False);'''
            db.execute(sql_statement, [user['user_name'] ,user['email'], password_hash])
            db.commit()
            flash('User {} created.'.format(user['user_name']))
            return redirect(url_for('users'))
        else:
            flash('Correct error: {}.'.format(message))
            return render_template('new_user.html', active_menu='admin', user=user,login=login)




#---- END - Admin Interface ----#

if __name__=='__main__':
    app.run()