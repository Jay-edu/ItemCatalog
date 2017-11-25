import os
import random
import string
import datetime
import httplib2
import json
import requests

from flask import Flask, render_template, request, redirect, url_for
from flask import make_response, flash, jsonify
from flask import session as login_session

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Items, User

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from functools import wraps


app = Flask(__name__)

# Create session and connect to DB
engine = create_engine('sqlite:///itemCatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


# login page
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
    	string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, isAuth=True)


# To connect using google signin
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        return sendResponse('Invalid state parameter', 401)
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

    # Upgrade the authorization code into a credentials object
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        return sendResponse('Failed to upgrade the authorization code.', 401)

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        return sendResponse(result.get('error'), 500)

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return sendResponse("Token's user ID doesn't match given user ID", 401)

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        return sendResponse("Token's client ID does not match app's.", 401)

    # Check to see if user is already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        return sendResponse('Current user is already connected.', 200)

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in")
    return output


# Disconnect google signin and clear login session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        return sendResponse('Current user not connected.', 401)

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = redirect(url_for('showCatalog'))
        flash("You are now logged out.")
        return response
    else:
        return sendResponse('Failed to revoke token for given user.', 400)


# send respose
def sendResponse(msg, code):
    response = make_response(json.dumps(msg), code)
    response.headers['Content-Type'] = 'application/json'
    return response


# create new user
def createUser(login_session):
    newUser = User(
        name=login_session['username'], email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# get user by id
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# get user by email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# show catalog, home page
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Items).order_by(desc(Items.date)).limit(5)
    return render_template('index.html', categories=categories, items=items)


# show catagory details
@app.route('/catalog/<path:category_name>/items/')
def showCategory(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Items).filter_by(
        category=category).order_by(asc(Items.name)).all()

    creator = getUserInfo(category.user_id)
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return render_template(
            'public_catagories.html',
            category=category.name, categories=categories, items=items)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template(
            'catagories.html',
            category=category, categories=categories, items=items, user=user)


# add new category
@app.route('/catalog/addcategory', methods=['GET', 'POST'])
@login_required
def addCategory():
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        print (newCategory)
        session.add(newCategory)
        session.commit()
        flash('Category Successfully Added!')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('addcategory.html', isAuth=True)


# edit category
@app.route('/catalog/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def editCatalog(category_id):
    categoryToEdit = session.query(Category).filter_by(id=category_id).one()
    categories = session.query(Category).order_by(asc(Category.name))
    # See if the logged in user is the owner of item
    creator = getUserInfo(categoryToEdit.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != item owner redirect them
    if creator.id != login_session['user_id']:
        flash("You cannot edit this Category. This Category belongs to %s"
              % creator.name)
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        if request.form['name']:
            categoryToEdit.name = request.form['name']
        flash('Category Successfully Edited! ' + categoryToEdit.name)
        session.add(categoryToEdit)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'editcategory.html',
            category=categoryToEdit, categories=categories)


# delete category
@app.route('/catalog/<path:category_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    categoryToDelete = session.query(Category).filter_by(
        name=category_name).one()
    # See if the logged in user is the owner of item
    creator = getUserInfo(categoryToDelete.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != item owner redirect them
    if creator.id != login_session['user_id']:
        flash("You cannot delete this Category. This Category belongs to %s"
              % creator.name)
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('Category Successfully Deleted! '+categoryToDelete.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'deletecategory.html',
            category=categoryToDelete, isAuth=True)


# list items for category
@app.route('/catalog/<path:category_name>/<path:item_name>/')
def showItem(category_name, item_name):
    item = session.query(Items).filter_by(name=item_name).one()
    creator = getUserInfo(item.user_id)
    categories = session.query(Category).order_by(asc(Category.name))
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return render_template(
            'public_itemdetail.html', item=item, category=category_name,
            categories=categories, creator=creator)
    else:
        return render_template(
            'itemdetail.html', item=item, category=category_name,
            categories=categories, creator=creator, isAuth=True)


# add new item
@login_required
@app.route('/catalog/add', methods=['GET', 'POST'])
def addItem():
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        newItem = Items(
            name=request.form['name'],
            description=request.form['description'],
            category=session.query(Category).filter_by(
                name=request.form['category']).one(),
            date=datetime.datetime.now(),
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('Item Successfully Added!')
        return redirect(url_for('showCatalog'))
    else:
        return render_template(
            'additem.html', categories=categories, isAuth=True)


# edit item
@app.route('/catalog/<path:category_name>/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(category_name, item_id):
    editedItem = session.query(Items).filter_by(id=item_id).one()
    categories = session.query(Category).order_by(asc(Category.name))
    # See if the logged in user is the owner of item
    creator = getUserInfo(editedItem.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != item owner redirect them
    if creator.id != login_session['user_id']:
        flash("You cannot edit this item. This item belongs to %s"
              % creator.name)
        return redirect(url_for('showCatalog'))
    # POST methods
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            category = session.query(Category).filter_by(
                name=request.form['category']).one()
            editedItem.category = category
        time = datetime.datetime.now()
        editedItem.date = time
        session.add(editedItem)
        session.commit()
        flash('Category Item Successfully Edited!')
        return redirect(url_for(
            'showCategory',
            category_name=editedItem.category.name))
    else:
        return render_template(
            'edititem.html',
            item=editedItem, categories=categories, isAuth=True)


# delete item
@app.route('/catalog/<path:category_name>/<path:item_name>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_name, item_name):
    itemToDelete = session.query(Items).filter_by(name=item_name).one()
    category = session.query(Category).filter_by(name=category_name).one()
    categories = session.query(Category).order_by(asc(Category.name))
    # See if the logged in user is the owner of item
    creator = getUserInfo(itemToDelete.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != item owner redirect them
    if creator.id != login_session['user_id']:
        flash("You cannot delete this item. This item belongs to %s"
              % creator.name)
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted! ' + itemToDelete.name)
        return redirect(url_for('showCategory', category_name=category.name))
    else:
        return render_template(
            'deleteitem.html', item=itemToDelete, isAuth=True)


@app.route('/catalog/JSON')
def allItemsJSON():
    categories = session.query(Category).order_by(asc(Category.name))
    category_dict = [c.serialize for c in categories]
    for c in range(len(category_dict)):
        items = [i.serialize for i in session.query(Items).
                 filter_by(category_id=category_dict[c]["id"]).all()]
        if items:
            category_dict[c]["Item"] = items
    return jsonify(Category=category_dict)


@app.route('/catalog/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).order_by(asc(Category.name))
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/catalog/items/JSON')
def itemsJSON():
    items = session.query(Items).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<path:category_name>/items/JSON')
def categoryItemsJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Items).filter_by(category=category).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<path:category_name>/<path:item_name>/JSON')
def ItemJSON(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Items).filter_by(
        name=item_name, category=category).one()
    return jsonify(item=[item.serialize])


if __name__ == '__main__':
    app.secret_key = 'DEV_SECRET_KEY'
    app.debug = True
    app.run(host='0.0.0.0', port=5050)
