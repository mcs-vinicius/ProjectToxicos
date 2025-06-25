from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
from sqlalchemy import text # Importante: Adicionar este import

app = Flask(__name__)

# Configurações do SQLAlchemy e Secret Key a partir de variáveis de ambiente
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

CORS(app, supports_credentials=True)
app.secret_key = os.environ.get('SECRET_KEY')

# --- Decorators de Proteção de Rota (sem alterações) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Acesso não autorizado. Por favor, faça login.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def roles_required(allowed_roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Acesso não autorizado.'}), 401
            if session.get('role') not in allowed_roles:
                return jsonify({'error': 'Permissão insuficiente para este recurso.'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# --- Endpoints de Autenticação e Sessão ---
@app.route('/register-user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    habby_id = data.get('habby_id')

    if not all([username, password, habby_id]):
        return jsonify({'error': 'Nome de usuário, senha e ID Habby são obrigatórios'}), 400

    try:
        # Verificar se usuário ou habby_id já existem
        query_check = text("SELECT id FROM users WHERE username = :username OR habby_id = :habby_id")
        result_check = db.session.execute(query_check, {'username': username, 'habby_id': habby_id})
        if result_check.fetchone():
            return jsonify({'error': 'Nome de usuário ou ID Habby já existem.'}), 409

        # Determinar a role (primeiro usuário é admin)
        query_admin = text("SELECT id FROM users WHERE role = 'admin'")
        result_admin = db.session.execute(query_admin)
        role = 'member' if result_admin.fetchone() else 'admin'
        
        hashed_password = generate_password_hash(password)
        
        # Inserir novo usuário e obter o ID retornado
        query_insert_user = text(
            "INSERT INTO users (username, password, role, habby_id) VALUES (:username, :password, :role, :habby_id) RETURNING id"
        )
        result_user = db.session.execute(
            query_insert_user,
            {'username': username, 'password': hashed_password, 'role': role, 'habby_id': habby_id}
        )
        user_id = result_user.scalar_one() # Pega o ID retornado

        # Inserir perfil do usuário
        query_insert_profile = text(
            "INSERT INTO user_profiles (user_id, habby_id, nick, profile_pic_url) VALUES (:user_id, :habby_id, :nick, :pic_url)"
        )
        db.session.execute(
            query_insert_profile,
            {'user_id': user_id, 'habby_id': habby_id, 'nick': username, 'pic_url': "https://ik.imagekit.io/wzl99vhez/toxicos/indefinido.png?updatedAt=1750707356953"}
        )
        
        db.session.commit()
        return jsonify({'message': f'Usuário cadastrado com sucesso como {role}!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao cadastrar usuário: {e}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    query = text("SELECT id, username, password, role, habby_id FROM users WHERE username = :username")
    result = db.session.execute(query, {'username': username})
    user = result.mappings().fetchone() # .mappings() permite acesso por nome de coluna

    if user and check_password_hash(user['password'], password):
        session['logged_in'] = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['habby_id'] = user['habby_id']
        return jsonify({
            'message': 'Login bem-sucedido!',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'habby_id': user['habby_id']
            }
        }), 200
    else:
        return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logout bem-sucedido'}), 200

@app.route('/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({
            'isLoggedIn': True,
            'user': {
                'id': session['user_id'],
                'username': session['username'],
                'role': session.get('role'),
                'habby_id': session.get('habby_id')
            }
        }), 200
    return jsonify({'isLoggedIn': False}), 200

# --- Endpoints de Gerenciamento de Usuários (Admin & Leader) ---
@app.route('/users', methods=['GET'])
@roles_required(['admin', 'leader'])
def get_users():
    query = text("""
        SELECT u.id, u.username, u.role, up.habby_id, up.nick, up.profile_pic_url 
        FROM users u
        LEFT JOIN user_profiles up ON u.id = up.user_id
        ORDER BY u.role, u.username
    """)
    result = db.session.execute(query)
    users = result.mappings().fetchall()
    return jsonify(users), 200

@app.route('/users/<int:user_id>/role', methods=['PUT'])
@roles_required(['admin'])
def update_user_role(user_id):
    data = request.json
    new_role = data.get('role')

    if new_role not in ['member', 'leader']:
        return jsonify({'error': 'Role inválida.'}), 400

    if session.get('user_id') == user_id:
        return jsonify({'error': 'O administrador não pode alterar seu próprio nível.'}), 403

    query = text("UPDATE users SET role = :new_role WHERE id = :user_id")
    db.session.execute(query, {'new_role': new_role, 'user_id': user_id})
    db.session.commit()
    return jsonify({'message': 'Nível de acesso atualizado com sucesso!'}), 200

@app.route('/users/<int:user_id>', methods=['DELETE'])
@roles_required(['admin', 'leader'])
def delete_user(user_id):
    logged_in_user_role = session.get('role')
    logged_in_user_id = session.get('user_id')

    if user_id == logged_in_user_id:
        return jsonify({'error': 'Você não pode excluir a si mesmo.'}), 403

    query_check = text("SELECT role FROM users WHERE id = :user_id")
    result = db.session.execute(query_check, {'user_id': user_id})
    user_to_delete = result.mappings().fetchone()

    if not user_to_delete:
        return jsonify({'error': 'Usuário não encontrado.'}), 404

    if logged_in_user_role == 'leader' and user_to_delete['role'] in ['leader', 'admin']:
        return jsonify({'error': 'Líderes só podem excluir membros.'}), 403

    query_delete = text("DELETE FROM users WHERE id = :user_id")
    db.session.execute(query_delete, {'user_id': user_id})
    db.session.commit()
    return jsonify({'message': 'Usuário excluído com sucesso!'}), 200

# --- Endpoints de Perfil de Usuário ---
@app.route('/search-users', methods=['GET'])
@login_required
def search_users():
    query_param = request.args.get('query', '')
    if len(query_param) < 2:
        return jsonify([])

    search_query = f"%{query_param}%"
    query = text("""
        SELECT up.habby_id, up.nick
        FROM user_profiles up
        WHERE up.nick ILIKE :search_query OR up.habby_id ILIKE :search_query
        LIMIT 10
    """) # Usando ILIKE para busca case-insensitive no PostgreSQL
    result = db.session.execute(query, {'search_query': search_query})
    users = result.mappings().fetchall()
    return jsonify(users)

@app.route('/profile/<string:habby_id>', methods=['GET'])
@login_required
def get_user_profile(habby_id):
    query = text("SELECT * FROM user_profiles WHERE habby_id = :habby_id")
    result = db.session.execute(query, {'habby_id': habby_id})
    profile = result.mappings().fetchone()
    if profile:
        return jsonify(profile), 200
    return jsonify({'error': 'Perfil não encontrado.'}), 404

@app.route('/profile', methods=['PUT'])
@login_required
def update_user_profile():
    data = request.json
    logged_in_habby_id = session.get('habby_id')

    if data.get('habby_id') != logged_in_habby_id:
        return jsonify({'error': 'Permissão negada para editar este perfil.'}), 403

    fields = [
        'nick', 'profile_pic_url', 'atk', 'hp', 'survivor_base_atk', 
        'survivor_base_hp', 'survivor_bonus_atk', 'survivor_bonus_hp', 
        'survivor_final_atk', 'survivor_final_hp', 'survivor_crit_rate', 
        'survivor_crit_damage', 'survivor_skill_damage', 'survivor_shield_boost',
        'survivor_poison_targets', 'survivor_weak_targets', 'survivor_frozen_targets',
        'pet_base_atk', 'pet_base_hp', 'pet_crit_damage', 'pet_skill_damage',
        'collect_final_atk', 'collect_final_hp', 'collect_crit_rate',
        'collect_crit_damage', 'collect_skill_damage', 'collect_poison_targets',
        'collect_weak_targets', 'collect_frozen_targets'
    ]
    
    query_parts = []
    values = {}
    
    for field in fields:
        if field in data:
            query_parts.append(f"{field} = :{field}")
            values[field] = data[field]

    if not query_parts:
        return jsonify({'error': 'Nenhum dado para atualizar.'}), 400
    
    values['habby_id'] = logged_in_habby_id
    
    query_str = f"UPDATE user_profiles SET {', '.join(query_parts)} WHERE habby_id = :habby_id"
    query = text(query_str)
    
    db.session.execute(query, values)
    db.session.commit()

    return jsonify({'message': 'Perfil atualizado com sucesso!'}), 200

# --- Endpoints de Temporadas e Ranking ---
@app.route('/seasons', methods=['GET'])
def get_seasons():
    query_seasons = text("SELECT id, start_date, end_date FROM seasons ORDER BY start_date ASC")
    result_seasons = db.session.execute(query_seasons)
    seasons = result_seasons.mappings().fetchall()
    
    result = []
    for s in seasons:
        season_id = s['id']
        query_participants = text(
            "SELECT id, habby_id, name, fase, r1, r2, r3, total FROM participants WHERE season_id = :season_id"
        )
        result_participants = db.session.execute(query_participants, {'season_id': season_id})
        participants = result_participants.mappings().fetchall()
        result.append({**s, 'participants': participants})
        
    return jsonify(result)

@app.route('/seasons', methods=['POST'])
@roles_required(['admin', 'leader'])
def create_season():
    data = request.json
    start_date = data.get('startDate')
    end_date = data.get('endDate')
    participants = data.get('participants', [])

    if not start_date or not end_date:
        return jsonify({'error': 'Data de início e fim obrigatórias'}), 400

    try:
        query_season = text("INSERT INTO seasons (start_date, end_date) VALUES (:start_date, :end_date) RETURNING id")
        result_season = db.session.execute(query_season, {'start_date': start_date, 'end_date': end_date})
        season_id = result_season.scalar_one()

        for p in participants:
            query_participant = text("""
                INSERT INTO participants (season_id, habby_id, name, fase, r1, r2, r3)
                VALUES (:season_id, :habby_id, :name, :fase, :r1, :r2, :r3)
            """)
            db.session.execute(query_participant, {
                'season_id': season_id,
                'habby_id': p.get('habby_id'),
                'name': p.get('name'),
                'fase': p.get('fase'),
                'r1': p.get('r1'),
                'r2': p.get('r2'),
                'r3': p.get('r3')
            })

        db.session.commit()
        return jsonify({'message': 'Temporada criada com sucesso!', 'seasonId': season_id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao criar temporada: {e}'}), 500

# --- Endpoints da Home Page e Histórico (Ajustados) ---

@app.route('/history/<string:habby_id>', methods=['GET'])
@login_required
def get_user_history(habby_id):
    try:
        query = text("""
            SELECT s.id as season_id, s.start_date, p.fase, p.total, p.name
            FROM seasons s
            JOIN participants p ON s.id = p.season_id
            WHERE p.habby_id = :habby_id
            ORDER BY s.start_date DESC
        """)
        result = db.session.execute(query, {'habby_id': habby_id})
        participations = result.mappings().fetchall()

        if not participations:
            return jsonify([]), 200

        # Para simplificar, o cálculo de posição e evolução pode ser feito no frontend
        # ou requer uma lógica de query mais complexa. Retornando os dados brutos.
        history = [
            {
                'season_id': p['season_id'],
                'start_date': p['start_date'].strftime('%Y-%m-%d'),
                'fase_acesso': p['fase'],
                'total': p['total'],
                'name': p['name']
            } for p in participations
        ]
        
        # Este endpoint parece querer retornar apenas o mais recente. Se for esse o caso:
        return jsonify(history[0] if history else {}), 200
        # Se quiser retornar todo o histórico, use:
        # return jsonify(history), 200
    except Exception as e:
        print(f"Error fetching history: {e}")
        return jsonify({'error': 'Erro ao buscar histórico.'}), 500

@app.route('/home-content', methods=['GET'])
def get_home_content():
    query = text("SELECT * FROM home_content WHERE id = 1")
    result = db.session.execute(query)
    content = result.mappings().fetchone()
    if content:
        # Cria uma cópia mutável para modificar
        mutable_content = dict(content)
        mutable_content['requirements'] = mutable_content['requirements'].split(';') if mutable_content.get('requirements') else []
        return jsonify(mutable_content)
    return jsonify({'error': 'Conteúdo não encontrado.'}), 404

@app.route('/home-content', methods=['PUT'])
@roles_required(['admin'])
def update_home_content():
    data = request.json
    requirements = ';'.join(data.get('requirements', []))

    try:
        query = text("""
            UPDATE home_content SET
                leader = :leader,
                focus = :focus,
                league = :league,
                requirements = :requirements,
                about_us = :about_us,
                content_section = :content_section
            WHERE id = 1
        """)
        db.session.execute(query, {
            'leader': data.get('leader'),
            'focus': data.get('focus'),
            'league': data.get('league'),
            'requirements': requirements,
            'about_us': data.get('about_us'),
            'content_section': data.get('content_section')
        })
        db.session.commit()
        return jsonify({'message': 'Conteúdo da Home atualizado com sucesso!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao atualizar conteúdo: {e}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)