from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'  #figure out better storage of all this when deployed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'b7f5b7fc3d4a4a35b178b0e8f32b0f57e6c2a2bb8a77c09f3b9f61c6d4c86e12'
app.config['API_KEY'] = 'f2f7d3a6e1b4c9a8f7e0b1c2d3a4e5f6'
db = SQLAlchemy(app)

class VerifiedHash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(64), unique=True, nullable=False)

class BadHash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(64), unique=True, nullable=False)

class UnknownScript(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(64), unique=True, nullable=False)
    script = db.Column(db.Text, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

with app.app_context():
    db.create_all()

def create_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        print(f"User '{username}' already exists.")
        return
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    print(f"User '{username}' added successfully.")


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        print(f"Received API Key: {api_key}")
        print(f"Expected API Key: {app.config['API_KEY']}") 
        if api_key != app.config['API_KEY']:
            return jsonify({"error": "Unauthorized access"}), 401
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_hash_verified(script_hash):
    return VerifiedHash.query.filter_by(hash=script_hash).first() is not None

def clean_hashes_from_unknown():
    verified_hashes = set(hash.hash for hash in VerifiedHash.query.all())
    bad_hashes = set(hash.hash for hash in BadHash.query.all())
    unknown_scripts = UnknownScript.query.all()
    for script in unknown_scripts:
        if script.hash in verified_hashes or script.hash in bad_hashes:
            # Remove script with verified or malicious hash
            db.session.delete(script)
            db.session.commit()
            print(f"Removed script with hash: {script.hash}")

def add_verified_hash(hash_value):
    if VerifiedHash.query.filter_by(hash=hash_value).first():
        print(f"Hash {hash_value} is already verified.")
        return
    
    new_verified_hash = VerifiedHash(hash=hash_value)
    db.session.add(new_verified_hash)
    db.session.commit()
    print(f"Verified hash {hash_value} added successfully.")

def add_malicious_hash(hash_value):
    if BadHash.query.filter_by(hash=hash_value).first():
        print(f"Hash {hash_value} is already marked as malicious.")
        return
    
    new_bad_hash = BadHash(hash=hash_value)
    db.session.add(new_bad_hash)
    db.session.commit()
    print(f"Malicious hash {hash_value} added successfully.")

@app.route('/')
@login_required
def index():
    clean_hashes_from_unknown()
    unknown_scripts = UnknownScript.query.all()
    script_list = [{'hash': script.hash, 'script': script.script} for script in unknown_scripts]
    return render_template('index.html', unknown_scripts=script_list)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/scripts', methods=['POST'])
@require_api_key
def receive_scripts():
    try:
        data = request.json
        print("Received payload:", data)

        if not data or 'scripts' not in data:
            return jsonify({"error": "Missing 'scripts' key"}), 400
        
        for item in data['scripts']:
            if 'hash' not in item or 'script' not in item:
                return jsonify({"error": "Invalid data format"}), 400

            script_hash = item['hash']
            script_content = item['script']

            # Check if the hash is verified
            if is_hash_verified(script_hash):
                return jsonify({"error": f"Hash {script_hash} is verified sent as unknown"}), 400

            # Check if the hash is already in the unknown scripts table
            if not UnknownScript.query.filter_by(hash=script_hash).first():
                # Add new script to the unknown scripts table
                new_script = UnknownScript(hash=script_hash, script=script_content)
                db.session.add(new_script)
                db.session.commit()
                print(f"Added new script with hash: {script_hash}")
            else:
                print(f"Duplicate hash detected: {script_hash}")

        return jsonify({"message": "Scripts received"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/hashes', methods=['GET'])
def send_hashes():
    verified_hashes = set(hash.hash for hash in VerifiedHash.query.all())
    bad_hashes = set(hash.hash for hash in BadHash.query.all())
    unknown_hashes = set(script.hash for script in UnknownScript.query.all())
    filtered_unknown_hashes = list(unknown_hashes - verified_hashes - bad_hashes)
    return jsonify({
        "verified_hashes": list(verified_hashes),
        "bad_hashes": list(bad_hashes),
        "unknown_hashes": filtered_unknown_hashes 
    }), 200

@app.route('/verified')
@login_required
def verified_hashes():
    verified_hashes = VerifiedHash.query.all()
    hash_list = [{'hash': hash.hash} for hash in verified_hashes]
    return render_template('verified_hashes.html', verified_hashes=hash_list)

@app.route('/malicious')
@login_required
def malicious_hashes():
    bad_hashes = BadHash.query.all()
    hash_list = [{'hash': hash.hash} for hash in bad_hashes]
    return render_template('malicious_hashes.html', malicious_hashes=hash_list)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        #create_user('username', 'password')
  
    app.run(debug=True)
