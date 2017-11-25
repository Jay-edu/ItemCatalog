# Item Catalog Web App

## About
This web application is to list and manipulate categoryies and items.
This project is a web application using the Flask framework and SQLLite database. 
OAuth2 is used to provide authentication for the user to perform CRUD functionality. OAuth2 is implemented for Google Account.
Authorization is done base on the user who create the item. Only the user who has created the item can either modify or delete it.
Working internet connection is required to download supporting JavaScript libraries


## How to run the application:

Assuming that Vagrant VM is already installed follow the steps to launch the application

1. Launch the Vagrant VM from inside the *vagrant* folder with: `vagrant up`

2. Access the shell with: `vagrant ssh`

3. Install the following libraries if not available in the Vagrant VM using the pip command:
	* Flask
	* sqlalchemy
	* requests
	* oauth2client
 
4. Move inside the ItemCatalog folder: `cd ItemCatalog`

5. Setup database for the project : `python database_setup.py`

6. Populate dummy fake data : `python database_setup.py`

7. Run the application: `python application.py`

8. Browse the application by using URL: `http://localhost:5050/`


## JSON Endpoints

The following Json endpoints are available :

`http://localhost:5050/catalog/JSON` - To get complete Catalog (i.e. Categories and items)

`http://localhost:5050/catalog/categories/JSON` - To get all Categories

`http://localhost:5050/catalog/items/JSON` - To get all items

`http://localhost:5050/catalog/<path:category_name>/items/JSON` - To get all items for a category

`http://localhost:5050/catalog/<path:category_name>/<path:item_name>/JSON` - To get an items for a category

