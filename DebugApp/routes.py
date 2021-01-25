import secrets
import os
from PIL import Image
from flask import  request, render_template, url_for,redirect, flash, redirect, abort
from DebugApp import app, db, bcrypt
from DebugApp.forms import LoginForm, RegistrationForm, UpdateAccountForm, TicketForm
from DebugApp.models import User, Ticket
from flask_login import login_user, current_user, logout_user, login_required



@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/dashboard")
def dashboard():
    tickets = Ticket.query.all()
    return render_template('dashboard.html', tickets=tickets)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! YOu are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email= form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page= request.args.get('next')
            return redirect(next_page if next_page else url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)



@app.route("/ticket/new", methods=['GET', 'POST'])
@login_required
def new_ticket():
    form = TicketForm()
    if form.validate_on_submit():
        ticket = Ticket(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(ticket)
        db.session.commit()
        flash('Your ticket has been created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_ticket.html', title='New Ticket',
                           form=form, legend='New Ticket')

@app.route('/ticket/<int:ticket_id>')
def ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    return render_template('ticket.html', title=ticket.title, ticket=ticket)

@app.route("/ticket/<int:ticket_id>/update", methods=['GET', 'POST'])
@login_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.author != current_user:
        abort(403)
    form = TicketForm()
    if form.validate_on_submit():
        ticket.title = form.title.data
        ticket.content = form.content.data
        db.session.commit()
        flash('Your ticket has been updated!', 'success')
        return redirect(url_for('ticket', ticket_id=ticket.id))
    elif request.method == 'GET':
        form.title.data = ticket.title
        form.content.data = ticket.content
    return render_template('create_ticket.html', title='Update Ticket',
                           form=form, legend='Update Ticket')

@app.route("/ticket/<int:ticket_id>/delete", methods=['POST'])
@login_required
def delete_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.author != current_user:
        abort(403)
    db.session.delete(ticket)
    db.session.commit()
    flash('Your ticket has been deleted!', 'success')
    return redirect(url_for('dashboard'))
