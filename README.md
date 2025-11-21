### Desenvolvedores

- **Victor Aranda** - RM 99667
- **Julia Lins** - RM 98690
- **Luis Barreto** - RM 99210

---
## 🔗 Links Principais

🏆 **[Pitch do Projeto para Global Solution](https://youtu.be/9UL5fSXV-Ko)**

🌐 **[COMPASS Platform (Site Web)](https://compass-app-kappa.vercel.app/)**

---

# Demo: Aplicação Vulnerável (para estudo)

Este repositório contém uma aplicação Flask intencionalmente vulnerável para fins educacionais.
NUNCA utilize este código em produção.

Esta documentação descreve as principais vulnerabilidades implementadas em `app_login_demo.py`, mostra os trechos de código vulneráveis e fornece pequenas demonstrações de correção para cada uma.

---

## Vulnerabilidades implementadas

1. SQL Injection (login)
2. IDOR (Insecure Direct Object Reference) em `/profile/<id>`
3. Reflected XSS na busca (`/search`)
4. Falta de proteção contra brute-force no login (contagem/lockout)

---

## 1) SQL Injection (login)

Descrição:
- O código atual monta uma query SQL concatenando diretamente os valores do formulário. Isso permite injeção SQL quando o atacante controla `username` ou `password`.

Trecho vulnerável (extraído de `app_login_demo.py`):

```py
# VULNERÁVEL: concatenação direta na query
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
c.execute(query)
user = c.fetchone()
```

Correção recomendada: usar consultas parametrizadas (prepared statements) para separar SQL de dados. Exemplo seguro:

```py
query = 'SELECT * FROM users WHERE username = ? AND password = ?'
c.execute(query, (username, password_hash))
user = c.fetchone()
```

Notas:
- Em produção, use hashing forte (bcrypt, argon2) com salt, e não MD5.

---

## 2) IDOR (Insecure Direct Object Reference)

Descrição:
- A rota `/profile/<int:user_id>` retorna o perfil para qualquer `user_id` sem verificar se o usuário atual tem permissão para ver aquele recurso.

Trecho vulnerável:

```py
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # IDOR VULNERÁVEL - não verifica autorização
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    ...
```

Correção recomendada: validar autorização — por exemplo, somente permitir acesso ao próprio perfil ou checar papéis (roles):

```py
if session.get('user_id') != user_id and session.get('username') != 'admin':
    return "Proibido", 403
```

Ou implementar controle de acesso baseado em roles/ACLs.

---

## 3) Reflected XSS na busca

Descrição:
- O parâmetro de busca `q` é renderizado no template sem escape (usando `|safe`), permitindo injeção de scripts que serão refletidos na página do usuário.

Trecho vulnerável (atualmente no template `DASHBOARD_PAGE`):

```html
<input type="text" name="q" placeholder="Digite o nome..." value="{{ search_query|safe }}">
...
<p>Resultados para: {{ search_query|safe }}</p>
```

Correção recomendada (para neutralizar XSS refletido):

- Remova o `|safe` e deixe o Jinja2 escapar automaticamente:

```html
value="{{ search_query }}"
...
<p>Resultados para: {{ search_query }}</p>
```

- Se for necessário permitir HTML seguro, utilize uma sanitização robusta (por exemplo, Bleach) limitando tags e atributos permitidos.

---

## 4) Sem proteção contra brute-force no login

Descrição:
- A rota de login não impõe limite de tentativas ou bloqueio temporário para credenciais incorretas. Isso facilita ataques de força bruta.

Trecho vulnerável:

```py
if request.method == 'POST':
    username = request.form['username']
    password = request.form['password']
    ...
    # executa query e valida
```

Mitigações simples:

- Adicionar um contador de tentativas por sessão/IP e bloquear temporariamente após N tentativas falhas.
  Exemplo simples (não definitivo):

```py
failed = session.get('failed_attempts', 0)
if failed >= 5:
    error = 'Conta temporariamente bloqueada. Tente mais tarde.'
else:
    # processa tentativa
    if not user:
        session['failed_attempts'] = failed + 1
    else:
        session['failed_attempts'] = 0
```

- Em produção, prefira soluções robustas: rate-limiting por IP, proteção por account lockout, CAPTCHAs, e monitoramento de autenticações suspeitas.

---

## Como verificar manualmente

1. Executar a aplicação:

```powershell
python app_login_demo.py
```

2. Testar SQLi (exemplo)
- No campo Usuário da tela de login, usar payloads como:

```
' OR '1'='1
```

3. Testar XSS
- Em `/dashboard` → busca, enviar como query: `?q=<script>alert(1)</script>` e observar se o script roda.

4. Testar IDOR
- Acesse `/profile/1` estando logado como outro usuário; se conseguir ver o perfil do admin, é IDOR.

5. Testar brute-force
- Tente várias senhas inválidas para o mesmo usuário e observe que não há limitação.

---
 
