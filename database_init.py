from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime
from database_setup import *

engine = create_engine('sqlite:///itemCatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

session.query(Category).delete()
session.query(Items).delete()
session.query(User).delete()

# Create users
User1 = User(name="Jay", email="jay.ededu@gmail.com")
session.add(User1)
session.commit()

# Create categories
Category1 = Category(name="Soccer", user_id=1)
session.add(Category1)
session.commit()

Category2 = Category(name="Basketball", user_id=1)
session.add(Category2)
session.commit

Category3 = Category(name="Baseball", user_id=1)
session.add(Category3)
session.commit()

Category4 = Category(name="Snowboarding", user_id=1)
session.add(Category4)
session.commit()

Category5 = Category(name="Hockey", user_id=1)
session.add(Category5)
session.commit()

# Create Items
Item1 = Items(name="Soccer Cleats", date=datetime.datetime.now(),
              description="Soccer Cleats",
              category_id=1, user_id=1)
session.add(Item1)
session.commit()

Item2 = Items(name="Jersey", date=datetime.datetime.now(),
              description="Jersey",
              category_id=1, user_id=1)
session.add(Item2)
session.commit()

Item3 = Items(name="Shingurads", date=datetime.datetime.now(),
              description="Shingurads.", category_id=1, user_id=1)
session.add(Item3)
session.commit()

Item4 = Items(name="Snowboard", date=datetime.datetime.now(),
              description="Snowboard", category_id=4, user_id=1)
session.add(Item4)
session.commit()

Item5 = Items(name="Goggles", date=datetime.datetime.now(),
              description="Goggles", category_id=4, user_id=1)
session.add(Item5)
session.commit()

Item6 = Items(name="Stick", date=datetime.datetime.now(),
              description="Stick", category_id=5, user_id=1)
session.add(Item6)
session.commit()

print ("Database has been populated with fake data!")
