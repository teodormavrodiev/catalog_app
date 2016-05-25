from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker 

from database_setup import User, Category, Item, Base

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine 

DBSession = sessionmaker(bind=engine)

session = DBSession()

User1 = User(name = "Teodor Mavrodiev", email = "teodor.mavrodiev@gmail.com",
	picture_url = "http://fullyawaken.com/website/pictures/profile_pic.jpg")
session.add(User1)
session.commit()

category_to_add = Category(name ="Tennis", 
	picture_url = "http://www.cityofsunprairie.com/ImageRepository/Document?documentID=2726")
session.add(category_to_add)
session.commit()

item_to_add = Item(name = "Wilson Sporting Goods Championship Tennis Balls", description = "Wilson is the Official Ball of the US Open and the Australian Open Grand Slam Championships.",
	picture_url = "http://ecx.images-amazon.com/images/I/31ua-5oAY5L.jpg", category = category_to_add, user = User1)
session.add(item_to_add)
session.commit()

item_to_add = Item(name = "Tourna Mesh Carry Bag of Tennis Balls", description = "Ideal for practice and throwing machines. Includes 18 balls.",
	picture_url = "http://ecx.images-amazon.com/images/I/61V267mV2IL.jpg", category = category_to_add, user = User1)
session.add(item_to_add)
session.commit()

item_to_add = Item(name = "Penn Championship Tennis Balls", description = "America's #1 selling tennis ball.",
	picture_url = "http://ecx.images-amazon.com/images/I/91JATyFtZZL._SL1500_.jpg", category = category_to_add, user = User1)
session.add(item_to_add)
session.commit()

category_to_add = Category(name ="Soccer", 
	picture_url = "http://soccer.sincsports.com/photos/tid/CAMSLF/img/4.png?create=09132014")
session.add(category_to_add)
session.commit()

item_to_add = Item(name = "Wilson Traditional Soccer Ball", description = "Synthetic leather cover extremely soft touch and increased durability.",
	picture_url = "http://ecx.images-amazon.com/images/I/61HoMmeLxoL._SL1157_.jpg", category = category_to_add, user = User1)
session.add(item_to_add)
session.commit()

item_to_add = Item(name = "Adidas Performance Conext15 Glider Soccer Ball", description = "Just the right size to hone your touches or juggle around the park, this mini football features a durable machine-stitched body and a butyl bladder that holds its shape kick after kick.",
	picture_url = "http://ecx.images-amazon.com/images/I/81TAtFUc7LL._SL1500_.jpg", category = category_to_add, user = User1)
session.add(item_to_add)
session.commit()

item_to_add = Item(name = "Adidas Performance 2015 MLS Glider Soccer Ball", description = "Almost the right size to hone your touches or juggle around the park, this mini football features a durable machine-stitched body and a butyl bladder that holds its shape kick after kick.",
	picture_url = "http://ecx.images-amazon.com/images/I/71JcyYJw2qL._SL1000_.jpg", category = category_to_add, user = User1)
session.add(item_to_add)
session.commit()



print "added items and categories!"

