from database import User, Admin, Booking, Venue, Show, Link, db, app
from flask import Flask, render_template, url_for, redirect, request, session, flash
from flask_login import *
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["SECRET_KEY"] = "secret"
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_id(id):
  if User.query.get(id):
    return User.query.get(id)
  elif Admin.query.get(id):
    return Admin.query.get(id)


class RegisterForm(FlaskForm):
  username = StringField(
    validators=[InputRequired(), Length(min=8, max=21)],
    render_kw={"placeholder": "Enter a username of your choice"})
  password = PasswordField(
    validators=[InputRequired(), Length(min=8, max=21)],
    render_kw={"placeholder": "Enter a password of your choice"})
  submit = SubmitField("Sign up")

  def validate_username(self, username):
    existing_username = User.query.filter_by(username=username.data).first()
    if existing_username:
      raise ValidationError(
        "Username already exists. Please select a different username.")


class LoginForm(FlaskForm):
  username = StringField(validators=[InputRequired(),
                                     Length(min=8, max=21)],
                         render_kw={"placeholder": "Enter your username"})
  password = PasswordField(validators=[InputRequired(),
                                       Length(min=8, max=21)],
                           render_kw={"placeholder": "Enter your password"})
  submit = SubmitField("Sign in")


@app.route("/")
def home():
  venues = Venue.query.all()
  shows = Show.query.all()
  print(session)
  print(current_user.is_authenticated)
  return render_template("Home.html",
                         venues=venues,
                         shows=shows,
                         current_user=current_user)


@app.route("/user/login", methods=["GET", "POST"])
def user_login():
  if current_user.is_authenticated and not current_user.is_admin:
    return render_template("User_logged_in.html",current_user=current_user)
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user and bcrypt.check_password_hash(user.password, form.password.data):
      login_user(user)
      session["user_type"] = "user"
      return render_template("User_logged_in.html",current_user=current_user)
  return render_template("User_login.html", form=form)


@app.route("/user/book_ticket/<int:sid>/<int:vid>", methods=["GET", "POST"])
@login_required
def book_ticket(sid,vid):
  if request.method == "GET" and not current_user.is_admin:
    show = Show.query.get(sid)
    venue = Venue.query.get(vid)
    link = Link.query.filter_by(show_id=sid,venue_id=vid).first()
    print(current_user.username)
    return render_template("Book_ticket.html", show=show, venue=venue, link=link)
  elif request.method == "POST" and not current_user.is_admin:
    booking = Booking(show_id=sid,
                      user_id=current_user.id,
                      venue_id=vid,
                      tickets_booked=request.form["tickets_booked"],
                      ticket_price=Link.query.filter_by(show_id=sid,venue_id=vid).first().ticket_price)
    ticket_count = Link.query.filter_by(show_id=sid,venue_id=vid).first().tickets_left - int(
      request.form["tickets_booked"])
    price = Link.query.filter_by(show_id=sid,venue_id=vid).first().ticket_price
    capacity = Venue.query.get(vid).capacity
    for i in range(1, 11):
      if ticket_count <= capacity - 0.1 * i * capacity and ticket_count > capacity - 0.1 * (
          i + 1) * capacity:
        price += price * 0.1 * i
    price=min(1000,int(price))
    db.session.add(booking)
    db.session.commit()
    Link.query.filter_by(show_id=sid,venue_id=vid).update(
      dict(tickets_left=ticket_count, ticket_price=price))
    db.session.commit()
    print("Holaemon")
    flash("Tickets booked successfully")
    return redirect(url_for("user_booking"))
  elif current_user.is_admin:
    return render_template("Authorization_failed.html",current_user=current_user)


@app.route("/user/booking", methods=["GET", "POST"])
@login_required
def user_booking():
  if not (current_user.is_admin):
    venues = Venue.query.all()
    shows = Show.query.all()
    links = Link.query.all()
    print(session)
    return render_template("User_booking.html", venues=venues, shows=shows, links=links)
  else:
    return render_template("Authorization_failed.html",current_user=current_user)


@app.route("/user/<int:id>/booking/history", methods=["GET", "POST"])
@login_required
def user_booking_history(id):
  if not (current_user.is_admin) and current_user.id == id:
    if request.method == "GET":
      booking = Booking.query.filter_by(user_id=id).all()
      show = Show.query.all()
      venue = Venue.query.all()
      link = Link.query.all()
      return render_template("User_booking_history.html",
                             booking=booking,
                             show=show,
                             venue=venue,
                             link=link)
  else:
    return render_template("Authorization_failed.html",current_user=current_user)


@app.route("/user/booking/history/rating/<int:sid>/<int:bid>",
           methods=["GET", "POST"])
@login_required
def rating(sid, bid):
  if not (current_user.is_admin) and Booking.query.get(bid).user_id==current_user.id:
    if request.method == "GET":
      return render_template("Rating.html")
    else:
      updated_booking = Booking.query.get(bid)
      updated_booking.rating = request.form['rating']
      db.session.commit()
      bookings = Booking.query.filter_by(show_id=sid).all()
      total = 0
      count = 0
      for booking in bookings:
        if booking.rating:
          total += booking.rating
          count += 1
      rating = total / count
      show = Show.query.get(sid)
      show.rating = rating
      db.session.commit()
      flash("Rated successfully")
      return redirect(url_for("user_booking_history", id=current_user.id))
  else:
    return render_template("Authorization_failed.html",current_user=current_user)


@app.route("/admin/signup", methods=["GET", "POST"])
def admin_sign_up():
  form = RegisterForm()
  if form.validate_on_submit():
    print(form.password.data)
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    new_user = Admin(username=form.username.data,
                     password=hashed_password,
                     is_admin=True)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("admin_login"))
  return render_template("Admin_sign_up.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def sign_up():
  form = RegisterForm()
  if form.validate_on_submit():
    print(form.password.data)
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    if not User.query.all():
      new_user = User(id=1000,
                      username=form.username.data,
                      password=hashed_password,
                      is_admin=False)
      db.session.add(new_user)
      db.session.commit()
      return redirect(url_for("user_login"))
    else:
      new_user = User(username=form.username.data,
                      password=hashed_password,
                      is_admin=False)
      db.session.add(new_user)
      db.session.commit()
      return redirect(url_for("user_login"))
  return render_template("User_sign_up.html", form=form)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
  form = LoginForm()
  if form.validate_on_submit():
    admin = Admin.query.filter_by(username=form.username.data).first()
    if admin and bcrypt.check_password_hash(admin.password,form.password.data):
      login_user(admin)
      session["user_type"] = "admin"
      print(current_user.username)
      print(session)
      return redirect(url_for(('admin_dashboard')))
  return render_template("Admin_login.html", form=form)


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
  if request.method == "GET" and current_user.is_admin:
    print(current_user.is_admin)
    show = Show.query.all()
    print(current_user.username)
    print(current_user.is_admin)
    print(session)
    return render_template("Admin_dashboard.html", show=show)


@app.route("/show")
def show():
  show = Show.query.all()
  print("this is", show)
  if show:
    return render_template("Show.html", show=show)
  else:
    return render_template("Empty_showlist.html")


@app.route('/show/<int:id>')#T.B.C
def show_detail(id):
  links = Link.query.filter_by(show_id=id).all()
  venues = Venue.query.all()
  return render_template("Show_detailed.html",links=links,venues=venues)


@app.route('/show/search')
def search():
  s = request.args.get("query")
  if s.isnumeric():
    s=float(s)
    s="{:.2f}".format(s)
  show_tags=Show.query.filter(Show.tags.contains(s)).all()
  show_name=Show.query.filter(Show.name.contains(s)).all()
  show_rating=Show.query.filter(Show.rating>=s).all()
  venue_location=Venue.query.filter(Venue.location.contains(s)).all()
  show=Show.query.all()
  venue=Venue.query.all()
  link=Link.query.all()
  if current_user.is_authenticated and not current_user.is_admin:
    authenticated=1
  elif current_user.is_authenticated and current_user.is_admin:
    authenticated=0
  else:
    authenticated=-1
  if s=="":
    return render_template("Search_not_found.html")
  elif venue_location:
    return render_template("Search_venue.html",venue_location=venue_location,show=show,venue=venue,link=link,authenticated=authenticated)
  elif show_tags:
    print(1)
    for i in show_tags:
      print(i)
    return render_template("Search_tags.html",show_tags=show_tags)
  elif show_name:
    print(2)
    return render_template("Search_show.html",show_name=show_name)
  elif show_rating:
    print(3)
    return render_template("Search_rating.html",show_rating=show_rating)
  else:
    print(4)
    return render_template("Search_not_found.html")


@app.route('/show/<int:id>/create', methods=['GET', 'POST'])
@login_required
def create_show(id):
  print(current_user.username)
  if request.method == "GET" and current_user.is_admin:
    venue = Venue.query.all()
    if venue:
      capacity = Venue.query.filter_by(id=id).first().capacity
      return render_template("Create_show.html", capacity=capacity)
    else:
      return """<!DOCTYPE html><html><title>Error</title><body>No venues added. Kindly add a venue first.</body><div><a href='/venue/create'>Click here to add a venue</a></div></html>"""
  elif request.method == "POST" and current_user.is_admin:
    print("Holaemon")
    capacity = Venue.query.filter_by(id=id).first().capacity
    if not Show.query.filter_by(name=request.form["name"]).first():
      show = Show(name=request.form["name"],
                  rating=request.form["rating"],
                  tags=request.form["tags"])
      db.session.add(show)
      db.session.commit()
      link = Link(show_id=show.id,venue_id=id,time=request.form["time"],ticket_price=request.form["price"],tickets_left=capacity)
      db.session.add(link)
      db.session.commit()
      print("done")
      flash("Show successfully added")
      return redirect(url_for("update_venue"))
    elif Link.query.filter_by(show_id=Show.query.filter_by(name=request.form["name"]).first().id,venue_id=id).first():
      print(Link.query.filter_by(show_id=Show.query.filter_by(name=request.form["name"]).first().id,venue_id=id))
      return """Show already added on this venue on another time slot"""     
    else:
      link = Link(show_id=Show.query.filter_by(name=request.form["name"]).first().id,venue_id=id,time=request.form["time"],ticket_price=request.form["price"],tickets_left=capacity)
      db.session.add(link)
      db.session.commit()
      print("done")
      flash("Show successfully added")
      return redirect(url_for("update_venue"))


@app.route('/<int:id>/show/update')
@login_required
def update_show(id):
  if current_user.is_admin:
    link = Link.query.filter_by(venue_id=id).all()
    show = Show.query.all()
    if link:
      venue = Venue.query.get(id)
      return render_template("Update_show.html",show=show,venue_id=id,venue=venue,link=link)
    else:
      return render_template("No_show.html", venue_id=id)


@app.route('/show/<int:sid>/venue/<int:vid>/update', methods=["GET", "POST"])
@login_required
def show_updation(sid,vid):
  if request.method == "GET" and current_user.is_admin:
    show = Show.query.filter_by(id=sid).first()
    link = Link.query.filter_by(show_id=sid,venue_id=vid).first()
    return render_template("Show_updation.html", show=show, link=link, vid=vid)
  elif request.method == "POST" and current_user.is_admin:
    Show.query.filter_by(id=sid).update(dict(rating=request.form['rating'],tags=request.form['tags']))
    Link.query.filter_by(show_id=sid,venue_id=vid).update(dict(time=request.form['time'],ticket_price=request.form['ticket_price'],tickets_left=request.form['tickets_left']))
    db.session.commit()
    return redirect(url_for("update_show", id=vid))


@app.route('/show/<int:sid>/update', methods=["GET", "POST"])
@login_required
def show_modification(sid):
  if request.method == "GET" and current_user.is_admin:
    show = Show.query.filter_by(id=sid).first()
    return render_template("Show_modification.html", show=show)
  elif request.method == "POST" and current_user.is_admin:
    Show.query.filter_by(id=sid).update(dict(name=request.form['name'],rating=request.form['rating'],tags=request.form['tags']))
    db.session.commit()
    return redirect(url_for("show_management"))


@app.route('/show/manage',methods=["GET","POST"])
@login_required
def show_management():
  if current_user.is_admin:
    shows=Show.query.all()
    if shows:
      return render_template("Manage_shows.html",shows=shows)
    else:
      return render_template("No_shows.html")


@app.route('/show/<int:sid>/venue/<int:vid>/delink')
@login_required
def show_delink(sid,vid):
  if current_user.is_admin:
    Link.query.filter_by(show_id=sid,venue_id=vid).delete()
    db.session.commit()
    return redirect(url_for("update_venue"))


@app.route('/show/<int:id>/remove')
@login_required
def show_removal(id):
  if current_user.is_admin:
    Show.query.filter_by(id=id).delete()
    db.session.commit()
    return redirect(url_for("update_venue"))


@app.route("/venue")
def venue():
  venue = Venue.query.all()
  if venue:
    return render_template("Venue.html", venue=venue)
  else:
    return "<h1>Venue list</h1><p>No venue found."


@app.route('/venue/creation', methods=['GET', 'POST'])
@login_required
def venue_creation():
  if request.method == "GET":
    return render_template("Create_venue.html")
  else:
    venue = Venue(name=request.form["name"],
                  place=request.form["place"],
                  location=request.form["location"],
                  capacity=request.form["capacity"])
    db.session.add(venue)
    db.session.commit()
    flash("Venue successfully added")
    venue = Venue.query.all()
    return render_template("Update_venue.html", venue=venue)


@app.route('/venue/create', methods=['GET', 'POST'])
@login_required
def create_venue():
  if current_user.is_admin:
    if request.method == "GET" and not Venue.query.all():
      return render_template("Create_venue.html")
    elif request.method == "GET":
      return redirect(url_for("update_venue"))
    elif request.method == "POST":
      venue = Venue(name=request.form["name"],
                    place=request.form["place"],
                    location=request.form["location"],
                    capacity=request.form["capacity"])
      db.session.add(venue)
      db.session.commit()
      flash("Venue successfully added")
      venue = Venue.query.all()
      return render_template("Update_venue.html", venue=venue)


@app.route('/venue/update', methods=['GET', 'POST'])
@login_required
def update_venue():
  if current_user.is_admin:
    venue = Venue.query.all()
    if venue:
      return render_template("Update_venue.html", venue=venue)
    else:
      return "<h1>Venue list</h1><p>No venue found.<p></p> <a href=\"/admin/dashboard\" type=\"button\">Back to admin dashboard</a>"


@app.route('/venue/<int:id>/update', methods=['GET', 'POST'])
@login_required
def venue_updation(id):
  if current_user.is_admin:
    if request.method == "GET":
      venue = Venue.query.filter_by(id=id).first()
      return render_template("Venue_updation.html", venue=venue)
    elif request.method == "POST":
      Venue.query.filter_by(id=id).update(
        dict(name=request.form["name"],
             place=request.form["place"],
             location=request.form["location"],
             capacity=request.form["capacity"]))
      db.session.commit()
      return redirect(url_for("update_venue"))


@app.route('/venue/remove', methods=['GET', 'POST'])
@login_required
def remove_venue():
  if current_user.is_admin:
    venue = Venue.query.all()
    if venue:
      return render_template("Remove_venue.html", venue=venue)
    else:
      return redirect(url_for("update_venue"))


@app.route('/venue/<int:id>/remove')
@login_required
def venue_removal(id):
  if current_user.is_admin:
    venue = Venue.query.get(id)
    db.session.delete(venue)
    db.session.commit()
    return redirect(url_for("create_venue"))


@app.route('/user/logout', methods=['GET', 'POST'])
@login_required
def user_logout():
  if session["user_type"] == "user":
    session.pop('user_type', None)
    logout_user()
    session.clear()
    print(session)
    return redirect(url_for('home'))


@app.route('/admin/logout', methods=['GET', 'POST'])
@login_required
def admin_logout():
  if session["user_type"] == "admin":
    session.pop('user_type', None)
    logout_user()
    session.clear()
    print(session)
    return redirect(url_for('home'))


if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0')
