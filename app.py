from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os

# --- Configuração da Aplicação Flask ---
app = Flask(__name__)

# --- INÍCIO DA MODIFICAÇÃO CORS ---
# Substitua 'SEU_USUARIO_GITHUB' pelo seu nome de usuário real do GitHub.
# Se o seu repositório do GitHub Pages for algo como SEU_USUARIO_GITHUB.github.io/NOME_DO_REPOSITORIO,
# a origem ainda é apenas https://SEU_USUARIO_GITHUB.github.io
frontend_gh_pages_origin = "https://carlosfaagundes.github.io/PlanejaPlus/" 

# Adicione a URL do seu ambiente de desenvolvimento local se você ainda o utiliza
# Exemplo para Live Server do VS Code rodando na porta 5500
local_dev_origin = "http://127.0.0.1:5500" 
# Se você abre o file:// diretamente (não recomendado para testes de API com CORS):
# local_dev_origin_file = "null" 

# Configura o CORS para permitir requisições apenas das origens especificadas.
# Adicione outras origens se seu frontend estiver em mais de um lugar.
# Para a URL do Render, não é necessário adicioná-la aqui, pois o backend está nela.
# Esta configuração é para quais *frontends* podem chamar seu backend.
CORS(app, origins=[frontend_gh_pages_origin, local_dev_origin], supports_credentials=True)
# Se você tiver problemas e quiser abrir temporariamente para todos para testar (NÃO RECOMENDADO PARA PRODUÇÃO):
# CORS(app) 
# --- FIM DA MODIFICAÇÃO CORS ---

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
with app.app_context():
    db.create_all()

# --- Endpoints da API ---
@app.route('/api/register', methods=['POST'])
def register():
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
    data = request.get_json()
    login_credential = data.get('loginCredential')
    password = data.get('password')

    if not login_credential or not password:
        return jsonify({"message": "Credencial de login e senha são obrigatórias!"}), 400

    user = User.query.filter((User.username == login_credential) | (User.email == login_credential)).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({
            "message": "Login bem-sucedido!",
            "username": user.username # Retorna o nome de usuário para o frontend
        }), 200
    else:
        return jsonify({"message": "Credenciais inválidas!"}), 401

# --- Execução da Aplicação ---
if __name__ == '__main__':
    # Esta parte é para desenvolvimento local. Em produção, o Gunicorn chamará o objeto 'app'.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5001)))
