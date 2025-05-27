from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os

# --- Configuração da Aplicação Flask ---
app = Flask(__name__)
# Para produção, você restringiria as origens:
# cors_origins = ["https://SEU_DOMINIO_FRONTEND.com"] # Substitua pelo seu domínio frontend quando tiver
# CORS(app, origins=cors_origins, supports_credentials=True)
CORS(app) # Para desenvolvimento e testes iniciais, manter aberto é mais fácil

# Configuração do Banco de Dados SQLite
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(instance_path, 'planejaplus.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Modelo do Banco de Dados (Tabela de Usuários) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# CRIA AS TABELAS SE NÃO EXISTIREM (IMPORTANTE PARA O PRIMEIRO DEPLOY)
# Em um ambiente de produção mais robusto, você usaria Flask-Migrate.
# Esta linha garante que, quando o app iniciar no servidor, as tabelas sejam criadas.
with app.app_context():
    db.create_all()

# --- Endpoints da API ---
@app.route('/api/register', methods=['POST'])
def register():
    # ... (seu código de registro aqui, sem alterações) ...
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Nome de usuário, e-mail e senha são obrigatórios!"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Nome de usuário já existe!"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "E-mail já cadastrado!"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Usuário registrado com sucesso!"}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erro ao registrar: {e}")
        return jsonify({"message": "Falha ao registrar usuário. Tente novamente mais tarde."}), 500


@app.route('/api/login', methods=['POST'])
def login():
    # ... (seu código de login aqui, sem alterações) ...
    data = request.get_json()
    login_credential = data.get('loginCredential')
    password = data.get('password')

    if not login_credential or not password:
        return jsonify({"message": "Credencial de login e senha são obrigatórias!"}), 400

    user = User.query.filter((User.username == login_credential) | (User.email == login_credential)).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({
            "message": "Login bem-sucedido!",
            "username": user.username
        }), 200
    else:
        return jsonify({"message": "Credenciais inválidas!"}), 401

# --- Execução da Aplicação ---
if __name__ == '__main__':
    # Esta parte é para desenvolvimento local. Em produção, o Gunicorn chamará o objeto 'app'.
    # A linha db.create_all() foi movida para cima para garantir que seja executada quando o módulo for carregado.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5001)))