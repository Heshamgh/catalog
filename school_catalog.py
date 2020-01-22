#!/usr/bin/env python3
from flask import Flask, render_template, request
from flask import redirect, url_for, jsonify, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, School, Field, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
CLIENT_ID = json.loads(open('client_secrets.json',
                            'r').read())['web']['client_id']
APPLICATION_NAME = "University application"

engine = create_engine('sqlite:///universityusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# main page.
@app.route('/')
def main():
    schools = session.query(School)
    fields = session.query(Field).order_by(desc(Field.id)).limit(12).all()
    if 'username' in login_session:
        return render_template('mainUsers.html', schools=schools,
                               fields=fields,
                               username=login_session['username'],
                               userpic=login_session['picture'])
    else:
        return render_template('main.html', schools=schools, fields=fields)

# login page.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# Google login.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserID(login_session['email'])

    # Add new users to the database.
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px; \
                -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User help functions.
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except IndexError:
        return None

# Google disconnect.
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url1 = 'https://accounts.google.com/o/oauth2/revoke?token='
    url2 = login_session['access_token']
    url = url1 + url2
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Logged out Successfully!")
        return (redirect(url_for('main')))
    else:
        faild = 'Failed to revoke token for given user.'
        response = make_response(json.dumps(faild, 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# School Page.
@app.route('/school/<int:school_id>/')
def schoolMenu(school_id):
    school = session.query(School).filter_by(id=school_id).one()
    schools = session.query(School)
    fields = session.query(Field).filter_by(school_id=school_id)
    creator = getUserInfo(school.user_id)
    if 'username' in login_session:
        userid = getUserID(login_session['email'])
    if 'username' not in login_session:
        return render_template('school.html', school=school, schools=schools,
                               fields=fields, creator=creator)
    else:
        return render_template('schoolUser.html', school=school,
                               schools=schools, fields=fields,
                               username=login_session['username'],
                               userpic=login_session['picture'],
                               userid=userid, creator=creator)

# School add.
@app.route('/school/add', methods=['GET', 'POST'])
def schoolAdd():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newSchool = School(name=request.form['name'],
                           user_id=login_session['user_id'])
        session.add(newSchool)
        flash('" %s " Has been Created!' % newSchool.name)
        session.commit()
        return redirect(url_for('main'))
    else:
        return render_template('newSchool.html',
                               username=login_session['username'],
                               userpic=login_session['picture'])

# School Edit.
@app.route('/school/<int:school_id>/edit', methods=['GET', 'POST'])
def schoolEdit(school_id):
    if 'username' not in login_session:
        return redirect('/login')
    school = session.query(School).filter_by(id=school_id).one()
    if school.user_id != login_session['user_id']:
        msg1 = "<script>function myFunction() "
        msg2 = "{alert('You are not authorized to edit this school."
        msg3 = "Please create your own school in order to edit.');}"
        msg4 = "</script><body onload='myFunction()''>"
        return msg1+msg2+msg3+msg4
    if request.method == 'POST':
        if request.form['name']:
            school.name = request.form['name']
        session.add(school)
        flash('" %s " has been updated!' % school.name)
        session.commit()
        return redirect(url_for('main'))
    else:
        return render_template('editSchool.html', school=school,
                               school_id=school_id,
                               username=login_session['username'],
                               userpic=login_session['picture'])

# School Delete.
@app.route('/school/<int:school_id>/delete', methods=['GET', 'POST'])
def schoolDelete(school_id):
    if 'username' not in login_session:
        return redirect('/login')
    school = session.query(School).filter_by(id=school_id).one()
    if school.user_id != login_session['user_id']:
        msg1 = "<script>function myFunction() {alert('You are not "
        msg2 = "authorized to delete this school. Please create your"
        msg3 = " own school in order to delete.');}</script>"
        msg4 = "<body onload='myFunction()''>"
        return msg1+msg2+msg3+msg4
    if request.method == 'POST':
        schoolDelete = session.query(School).filter_by(id=school_id).one()
        session.delete(schoolDelete)
        flash('The School %s was deleated!' % schoolDelete.name)
        session.commit()
        return redirect(url_for('main'))
    else:
        return render_template('deleteSchool.html', school=school,
                               school_id=school_id,
                               username=login_session['username'],
                               userpic=login_session['picture'])

# Field page.
@app.route('/school/<int:school_id>/<int:field_id>/')
def fieldPage(school_id, field_id):
    school = session.query(School).filter_by(id=school_id).one()
    fields = session.query(Field).filter_by(school_id=school_id).all()
    field = session.query(Field).filter_by(school_id=school_id,
                                           id=field_id).one()
    creator = getUserInfo(field.user_id)
    if 'username' in login_session:
        userid = getUserID(login_session['email'])
    if 'username' not in login_session:
        return render_template('field.html', school=school, field=field,
                               fields=fields, creator=creator)
    else:
        return render_template('fieldUser.html', school=school, field=field,
                               fields=fields,
                               username=login_session['username'],
                               userpic=login_session['picture'],
                               userid=userid, creator=creator)

# Field Add.
@app.route('/school/<int:school_id>/add', methods=['GET', 'POST'])
def fieldAdd(school_id):
    if 'username' not in login_session:
        return redirect('/login')
    school = session.query(School).filter_by(id=school_id).one()
    if request.method == 'POST':
        newField = Field(name=request.form['name'], school_id=school_id,
                         description=request.form['description'],
                         crhours=request.form['crhours'],
                         crprice=request.form['crprice'],
                         user_id=login_session['user_id'])
        session.add(newField)
        flash('The field " %s " created!' % newField.name)
        session.commit()
        return redirect(url_for('schoolMenu', school_id=school_id))
    else:
        return render_template('newField.html', school_id=school_id,
                               username=login_session['username'],
                               userpic=login_session['picture'],
                               school=school)

# Field Edit.
@app.route('/school/<int:school_id>/<int:field_id>/edit',
           methods=['GET', 'POST'])
def fieldEdit(school_id, field_id):
    if 'username' not in login_session:
        return redirect('/login')
    school = session.query(School).filter_by(id=school_id).one()
    field = session.query(Field).filter_by(school_id=school_id,
                                           id=field_id).one()
    if field.user_id != login_session['user_id']:
        msg1 = "<script>function myFunction()"
        msg2 = " {alert('You are not authorized to edit this field."
        msg3 = " Please create your own field in order to edit.');}"
        msg4 = "</script><body onload='myFunction()''>"
        return msg1+msg2+msg3+msg4
    if request.method == 'POST':
        if request.form['name']:
            field.name = request.form['name']
        if request.form['description']:
            field.description = request.form['description']
        if request.form['crhours']:
            field.crhours = request.form['crhours']
        if request.form['crprice']:
            field.crprice = request.form['crprice']
        session.add(field)
        flash('The Field " %s " updated!' % field.name)
        session.commit()
        return redirect(url_for('fieldPage', school_id=school_id,
                                field_id=field_id))
    else:
        return render_template('editField.html', school=school, field=field,
                               school_id=school_id, field_id=field_id,
                               username=login_session['username'],
                               userpic=login_session['picture'])

# Field Delete.
@app.route('/school/<int:school_id>/<int:field_id>/delete',
           methods=['GET', 'POST'])
def fieldDelete(field_id, school_id):
    if 'username' not in login_session:
        return redirect('/login')
    fieldDelete = session.query(Field).filter_by(id=field_id).one()
    if fieldDelete.user_id != login_session['user_id']:
        msg1 = "<script>function myFunction() {alert('You are not authorized"
        msg2 = " to delete this field. Please create your own field in order"
        msg3 = " to field.');}</script><body onload='myFunction()''>"
        return msg1+msg2+msg3
    if request.method == 'POST':
        session.delete(fieldDelete)
        flash('The Field " %s " was deleated!' % fieldDelete.name)
        session.commit()
        return redirect(url_for('schoolMenu', school_id=school_id))
    else:
        return render_template('deleteField.html', field=fieldDelete,
                               field_id=field_id, school_id=school_id,
                               username=login_session['username'],
                               userpic=login_session['picture'])

# JSON pages.
@app.route('/school/<int:school_id>/JSON')
def schoolMenuJSON(school_id):
    school = session.query(School).filter_by(id=school_id).one()
    fields = session.query(Field).filter_by(school_id=school_id).all()
    return jsonify(Field=[f.serialize for f in fields])


@app.route('/school/<int:school_id>/<int:field_id>/JSON')
def fieldMenuJSON(school_id, field_id):
    school = session.query(School).filter_by(id=school_id).one()
    field = session.query(Field).filter_by(school_id=school_id,
                                           id=field_id).one()
    return jsonify(Field=field.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
