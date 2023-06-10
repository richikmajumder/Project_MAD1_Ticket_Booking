from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import *

app = Flask(__name__)
db = SQLAlchemy(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#db.init_app(app)


class Venue(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  name = db.Column(db.String(), nullable=False)
  place = db.Column(db.String(), nullable=False)
  location = db.Column(db.String(), nullable=False)
  capacity = db.Column(db.Integer, nullable=False)
  link = db.relationship("Link", backref="venue", cascade="all,delete")
  booking = db.relationship("Booking",backref="venue",cascade="all,delete")

class Show(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  name = db.Column(db.String(), unique=True, nullable=False)
  rating = db.Column(db.Integer, nullable=False)
  tags = db.Column(db.String(), nullable=False)
  link = db.relationship("Link", backref="show", cascade="all,delete")
  booking = db.relationship("Booking",backref="show",cascade="all,delete")


class Link(db.Model,UserMixin):
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  venue_id = db.Column(db.Integer, db.ForeignKey("venue.id"), nullable=False)
  show_id = db.Column(db.Integer,db.ForeignKey("show.id"),nullable=False)
  time = db.Column(db.String, nullable=False)
  ticket_price = db.Column(db.Integer, nullable=False)
  tickets_left = db.Column(db.Integer, nullable=False)


class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  username = db.Column(db.String(), nullable=False, unique=True)
  password = db.Column(db.String(), nullable=False)
  is_admin = db.Column(db.Boolean(), default=False)
  

class Booking(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  show_id  = db.Column(db.Integer,db.ForeignKey("show.id"),nullable=False)
  user_id = db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False)
  venue_id = db.Column(db.Integer, db.ForeignKey("venue.id"), nullable=False)
  tickets_booked = db.Column(db.Integer, nullable=False)
  ticket_price = db.Column(db.Integer, nullable=False)
  rating = db.Column(db.Integer)

  
class Admin(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True, autoincrement=True)
  username = db.Column(db.String(),
                       nullable=False,
                       unique=True,
                       autoincrement=True)
  password = db.Column(db.String(), nullable=False)
  is_admin = db.Column(db.Boolean(), default=True)

db.create_all()