# REST API dengan Flask, MySQL/MariaDB, dan Arsitektur MVC

# Tema API: "Manajemen Inventaris Perpustakaan"
# REST API ini menggunakan arsitektur MVC (Model-View-Controller) dengan Flask sebagai framework utama dan MySQL/MariaDB sebagai database.

# Instalasi dependensi yang diperlukan:
# pip install flask flask_sqlalchemy flask_marshmallow flask_bcrypt flask_jwt_extended pymysql flask-migrate

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_migrate import Migrate
from datetime import datetime

# Inisialisasi aplikasi
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@127.0.0.1/library_management'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'random_super_secret_key'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# Model (Database Schema)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')

class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)

class Member(db.Model):
    __tablename__ = 'members'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)

class Borrow(db.Model):
    __tablename__ = 'borrows'
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id'), nullable=False)
    borrow_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    return_date = db.Column(db.DateTime, nullable=True)

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)

# Controller: User Authentication
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Controller: Book Management
@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    books = Book.query.all()
    result = [{'id': book.id, 'title': book.title, 'author': book.author, 'category_id': book.category_id} for book in books]
    return jsonify(result), 200

@app.route('/books', methods=['POST'])
@jwt_required()
def add_book():
    data = request.get_json()
    new_book = Book(title=data['title'], author=data['author'], category_id=data['category_id'])
    db.session.add(new_book)
    db.session.commit()
    return jsonify({'message': 'Book added successfully'}), 201

@app.route('/books/<int:id>', methods=['PUT'])
@jwt_required()
def update_book(id):
    data = request.get_json()
    book = Book.query.get_or_404(id)
    book.title = data['title']
    book.author = data['author']
    book.category_id = data['category_id']
    db.session.commit()
    return jsonify({'message': 'Book updated successfully'}), 200

@app.route('/books/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_book(id):
    book = Book.query.get_or_404(id)
    db.session.delete(book)
    db.session.commit()
    return jsonify({'message': 'Book deleted successfully'}), 200

# View: Home Route
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Library Management API'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
