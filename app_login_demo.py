from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'chave_super_secreta_123'  # Chave fraca propositalmente

# Templates HTML
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Portal de Acesso - Demonstração</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 420px; margin: 60px auto; padding: 24px; color: #222; }
        h2 { color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .error { color: #c00; margin-bottom: 12px; }
        .note { background: #f6f8fa; padding: 12px; margin: 16px 0; border-left: 4px solid #007bff; border-radius: 4px; color: #333; }
        footer { font-size: 0.9em; color: #666; margin-top: 18px; }
    </style>
</head>
<body>
    <h2>Portal de Acesso</h2>
    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}
    <form method="POST">
        <input type="text" name="username" placeholder="Usuário" required>
        <input type="password" name="password" placeholder="Senha" required>
        <button type="submit">Entrar</button>
    </form>

    <footer>
        <small>Se você recebeu credenciais para demonstração, utilize-as aqui. Caso contrário, contacte o administrador.</small>
    </footer>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 920px; margin: 40px auto; padding: 20px; color: #222; }
        .header { background: #007bff; color: white; padding: 20px; margin: -20px -20px 20px -20px; border-radius: 4px 4px 0 0; }
        .user-card { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 6px; }
        input { padding: 10px; margin: 10px 10px 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        a { color: #007bff; text-decoration: none; }
        .info { background: #eef6ff; padding: 12px; margin: 12px 0; border-left: 4px solid #007bff; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Bem-vindo, {{ username }}!</h2>
        <p>ID: {{ user_id }} | <a href="/logout" style="color: white;">Sair</a></p>
    </div>
    
    <h3>Buscar Usuários</h3>
    <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Digite o nome..." value="{{ search_query }}">
        <button type="submit">Buscar</button>
    </form>
    
    {% if search_query %}
        <div class="info">
            <p>Resultados para: {{ search_query }}</p>
        </div>
    {% endif %}
    
    <h3>Todos os Usuários</h3>
    {% for user in users %}
        <div class="user-card">
            <strong>{{ user[1] }}</strong> - {{ user[3] }}
            <br><a href="/profile/{{ user[0] }}">Ver perfil completo</a>
        </div>
    {% endfor %}
    
</body>
</html>
"""

USER_DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Minha Área</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 720px; margin: 40px auto; padding: 20px; color: #222; }
        .header { background: #17a2b8; color: white; padding: 16px; margin: -20px -20px 16px -20px; border-radius: 4px 4px 0 0; }
        .card { background: #fff; padding: 16px; margin: 10px 0; border-radius: 6px; border: 1px solid #e9ecef; }
        a { color: #17a2b8; text-decoration: none; }
        .note { font-size: 0.95em; color: #555; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Área do Usuário</h2>
        <p>{{ username }} | <a href="/logout" style="color: white;">Sair</a></p>
    </div>

    <div class="card">
        <h3>Bem-vindo, {{ username }}!</h3>
        <p class="note">Esta é a sua área pessoal. Você pode revisar seu perfil e as informações associadas à sua conta.</p>
        <ul>
            <li><strong>ID:</strong> {{ user[0] }}</li>
            <li><strong>Email:</strong> {{ user[3] }}</li>
            <li><strong>Telefone:</strong> {{ user[4] }}</li>
        </ul>
        <p><a href="/profile/{{ user[0] }}">Ver perfil completo</a></p>
    </div>

    <p><a href="/dashboard">Voltar</a></p>
</body>
</html>
"""

PROFILE_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Perfil de {{ user[1] }}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 640px; margin: 40px auto; padding: 20px; color: #222; }
        .profile { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        .info-row { padding: 10px 0; border-bottom: 1px solid #e9ecef; }
        a { color: #007bff; text-decoration: none; }
        .note { background: #eef6ff; padding: 10px; margin: 18px 0; border-left: 4px solid #007bff; border-radius: 4px; }
    </style>
</head>
<body>
    <h2>Perfil do Usuário</h2>
    <div class="profile">
        <div class="info-row"><strong>ID:</strong> {{ user[0] }}</div>
        <div class="info-row"><strong>Usuário:</strong> {{ user[1] }}</div>
        <div class="info-row"><strong>Email:</strong> {{ user[3] }}</div>
        <div class="info-row"><strong>Telefone:</strong> {{ user[4] }}</div>
        <div class="info-row"><strong>CPF:</strong> {{ user[5] }}</div>
    </div>
    
    <p><a href="/dashboard">← Voltar ao Dashboard</a></p>
</body>
</html>
"""

def init_db():
    """Inicializa o banco de dados com usuários de exemplo"""
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()

    # recria a tabela com campos para controle de tentativas e bloqueio
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, 
                  email TEXT, phone TEXT, cpf TEXT,
                  failed_attempts INTEGER DEFAULT 0,
                  lockout_until INTEGER DEFAULT 0)''')

    users = [
        (1, 'admin', generate_password_hash('admin123'),
         'admin@empresa.com', '11-98765-4321', '123.456.789-00', 0, 0),
        (2, 'user1', generate_password_hash('pass1'),
         'user1@email.com', '11-91234-5678', '987.654.321-00', 0, 0),
        (3, 'user2', generate_password_hash('pass2'),
         'user2@email.com', '11-95555-6666', '456.789.123-00', 0, 0)
    ]

    c.executemany('INSERT INTO users VALUES (?,?,?,?,?,?,?,?)', users)
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('vulnerable_app.db')
        c = conn.cursor()

        try:
            # Buscamos o usuário por username (query parametrizada)
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()

            if user:
                now = int(time.time())
                failed_attempts = user[6]
                lockout_until = user[7]

                # Verifica se a conta está em lockout
                if lockout_until and lockout_until > now:
                    wait = lockout_until - now
                    error = f"Conta bloqueada. Tente novamente em {wait} segundos."
                    conn.close()
                    return render_template_string(LOGIN_PAGE, error=error)

                # Verifica senha
                if check_password_hash(user[2], password):
                    # sucesso -> reset de tentativas
                    c.execute('UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE id = ?', (user[0],))
                    conn.commit()
                    conn.close()
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    return redirect(url_for('dashboard'))
                else:
                    # falha -> incrementa contador e aplica lockout se necessário
                    failed_attempts = failed_attempts + 1
                    lockout_until_new = 0
                    # Limite de tentativas antes do bloqueio
                    LIMIT = 5
                    if failed_attempts >= LIMIT:
                        # bloqueio progressivo: 2^(failed-LIMIT) minutos, limitado a 60 minutos
                        exponent = failed_attempts - LIMIT
                        minutes = min(60, 2 ** exponent)
                        lockout_until_new = now + (minutes * 60)

                    c.execute('UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?', (failed_attempts, lockout_until_new, user[0]))
                    conn.commit()
                    conn.close()
                    error = "Credenciais inválidas"
            else:
                # usuário não existe -> resposta genérica (não vazar existência)
                conn.close()
                error = "Credenciais inválidas"
        except Exception as e:
            error = f"Erro: {str(e)}"
    
    return render_template_string(LOGIN_PAGE, error=error)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Se não for admin, redireciona para a área de usuário
    if session.get('username') != 'admin':
        return redirect(url_for('user_home'))

    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, email FROM users')
    users = c.fetchall()
    conn.close()

    return render_template_string(DASHBOARD_PAGE, 
                                 username=session['username'],
                                 user_id=session['user_id'],
                                 users=users,
                                 search_query='')

@app.route('/search')
def search():

    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    search_query = request.args.get('q', '')
    
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, email FROM users')
    users = c.fetchall()
    conn.close()
    
    # Renderiza com | safe - permite execução de scripts
    return render_template_string(DASHBOARD_PAGE, 
                                 username=session['username'],
                                 user_id=session['user_id'],
                                 users=users,
                                 search_query=search_query)

@app.route('/user_home')
def user_home():
    """
    Página inicial para usuários não-admin.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()

    if not user:
        return "Usuário não encontrado", 404

    return render_template_string(USER_DASHBOARD_PAGE,
                                 username=session.get('username'),
                                 user=user)

@app.route('/profile/<int:user_id>')
def profile(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Verificação de autorização (corrige IDOR):
    # só permite ver o perfil se for o próprio usuário ou se for admin
    if session.get('user_id') != user_id and session.get('username') != 'admin':
        return "Proibido", 403

    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        return "Usuário não encontrado", 404

    return render_template_string(PROFILE_PAGE, 
                                 user=user, 
                                 session_user_id=session['user_id'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("Aplicação de Demonstração iniciada (execução local)")
    print("Acesse: http://localhost:5000")
    print("" + "="*60 + "\n")
    
    app.run(debug=True, port=5000)