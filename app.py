from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from models import db, User, Task

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_example'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_example'

db.init_app(app)
stripe.api_key = app.config['STRIPE_SECRET_KEY']

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

admin = Admin(app, name='Admin', template_mode='bootstrap3')

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'admin'

admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Task, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_tables_once():
    if not hasattr(app, 'tables_created'):
        db.create_all()
        app.tables_created = True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            flash('Usuário já existe')
            return redirect(url_for('register'))
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Credenciais inválidas')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if not current_user.premium:
        flash("Atualize para premium para acessar funcionalidades avançadas.")
    if request.method == 'POST':
        task = Task(title=request.form['title'], user_id=current_user.id)
        db.session.add(task)
        db.session.commit()
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', tasks=tasks)

@app.route('/complete/<int:task_id>')
@login_required
def complete(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/upgrade')
@login_required
def upgrade():
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {
                    'name': 'Premium SaaS Plan',
                },
                'unit_amount': 500,
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('payment_success', _external=True),
        cancel_url=url_for('dashboard', _external=True),
    )
    return redirect(session.url, code=303)

@app.route('/success')
@login_required
def payment_success():
    current_user.premium = True
    db.session.commit()
    flash("Você agora é um usuário Premium!")
    return redirect(url_for('dashboard'))

# API RESTful
@app.route('/api/tasks', methods=['GET'])
@login_required
def api_get_tasks():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return jsonify([{'id': t.id, 'title': t.title, 'completed': t.completed} for t in tasks])

@app.route('/api/tasks', methods=['POST'])
@login_required
def api_create_task():
    title = request.json.get('title')
    task = Task(title=title, user_id=current_user.id)
    db.session.add(task)
    db.session.commit()
    return jsonify({'id': task.id, 'title': task.title, 'completed': task.completed})

@app.route('/api/tasks/<int:task_id>', methods=['PATCH'])
@login_required
def api_toggle_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'not found'}), 404

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def api_delete_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
