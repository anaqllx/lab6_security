import os 
from flask import Flask, render_template, request, redirect, url_for, session, current_app
from authlib.integrations.flask_client import OAuth 

from secure_auth import (
    register_user_full, login_user, activate_user,
    enable_2fa, disable_2fa, generate_recovery_token, reset_password,
    login_via_oauth, USERS, generate_captcha, log_login_attempt,
    MAX_LOGIN_ATTEMPTS,
    verify_password 
)

# ІНІЦІАЛІЗАЦІЯ FLASK та OAUTH
# ІНІЦІАЛІЗАЦІЯ FLASK та OAUTH
# 1. Створення основного об'єкту Flask 
app = Flask(__name__)
app.secret_key = os.urandom(24) 

GOOGLE_CLIENT_ID = "463820688884-cinqj4ruq3s8mqm5fqto4ibcs9tb95ol.apps.googleusercontent.com" 
GOOGLE_CLIENT_SECRET = "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" 

# 2. Ініціалізація OAuth
oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# 1. ДОМАШНЯ СТОРІНКА

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    username = session['username']
    user_data = USERS.get(username, {})
    
    is_2fa_enabled = bool(user_data.get('2fa_secret'))
    
    return render_template('profile.html', 
                           username=username, 
                           is_2fa_enabled=is_2fa_enabled,
                           message=request.args.get('message')) 

@app.route('/logout')
def logout():
    log_login_attempt(session.get('username', 'UNKNOWN'), success=True, reason="Logout")
    session.pop('username', None)
    return redirect(url_for('login'))

# 2. РЕЄСТРАЦІЯ

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'GET':
        correct_captcha = generate_captcha() 
        session['captcha_code'] = correct_captcha 
    elif request.method == 'POST':
        correct_captcha = session.pop('captcha_code', None)
        
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        captcha_input = request.form.get('captcha')
        
        # Перевірка CAPTCHA 
        if correct_captcha is None or captcha_input != correct_captcha:
            message = "Неправильний CAPTCHA або час очікування вичерпано. Спробуйте ще раз."
            new_captcha = generate_captcha()
            session['captcha_code'] = new_captcha
            
            return render_template('register.html', message=message)

        result_message = register_user_full(username, password, email)
            
        if "успішно зареєстрований" in result_message:
            return render_template('login.html', message=result_message)
        else:
            message = result_message
            new_captcha = generate_captcha()
            session['captcha_code'] = new_captcha
            return render_template('register.html', message=message)
            
    return render_template('register.html', message=message)

# 3. ВХІД

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = request.args.get('message') 
    ask_2fa = False
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp_code = request.form.get('otp_code') 
        
        is_logged_in = login_user(username, password, otp_code=otp_code)
        if is_logged_in:
            session['username'] = username 
            return redirect(url_for('index'))
        else:
            if username in USERS and USERS[username].get('2fa_secret'):
                if verify_password(USERS[username]['password_hash'], password) and otp_code is None:
                     ask_2fa = True
                     message = "Пароль вірний. Будь ласка, введіть 2FA код."
                else:
                    message = "Помилка входу: Невірний пароль або 2FA код."
            else:
                message = f"Помилка входу. Перевірте логін, пароль, або статус активації. (Спроб залишилось: {MAX_LOGIN_ATTEMPTS - USERS.get(username, {}).get('login_attempts', 0)})"

    return render_template('login.html', message=message, ask_2fa=ask_2fa)

# 4. АКТИВАЦІЯ ТА ВІДНОВЛЕННЯ

@app.route('/activate/<token>')
def activate(token):
    result_message = activate_user(token)
    return redirect(url_for('login', message=result_message))

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    message = None
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'get_token':
            email = request.form.get('email')
            message = generate_recovery_token(email)
            
        elif action == 'reset_password':
            token = request.form.get('token')
            new_password = request.form.get('new_password')
            message = reset_password(token, new_password)
            if "успішно змінено" in message:
                return redirect(url_for('login', message=message))
                
    return render_template('recover.html', message=message)

# 5. УПРАВЛІННЯ 2FA

@app.route('/2fa_manage', methods=['GET', 'POST'])
def manage_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    secret = None
    message = None

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'enable':
            secret = enable_2fa(username)
            if secret:
                message = f"2FA активовано. Введіть цей ключ у додаток-аутентифікатор."
            else:
                message = "Помилка активації 2FA."
                
        elif action == 'disable':
            if disable_2fa(username):
                message = "2FA успішно вимкнено."
            else:
                message = "Помилка вимкнення 2FA."

    user_data = USERS.get(username, {})
    is_enabled = bool(user_data.get('2fa_secret'))

    if is_enabled and not secret:
         secret = user_data.get('2fa_secret')

    return render_template('2fa_manage.html', 
                           message=message, 
                           is_enabled=is_enabled, 
                           secret=secret)

# 6. СПРАВЖНІЙ ВХІД ЧЕРЕЗ GOOGLE OAUTH

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/google/auth')
def authorize_google():
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.userinfo()
        
        google_id = user_info['sub'] 
        email = user_info.get('email')

        success, username = login_via_oauth('Google', google_id, email)
        
        if success:
            session['username'] = username
            log_login_attempt(username, success=True, reason="OAuth Login via Google")
            return redirect(url_for('index', message="Вхід через Google успішний!"))
        else:
            return redirect(url_for('login', message="Помилка при реєстрації через Google."))
            
    except Exception as e:
        log_login_attempt('UNKNOWN', success=False, reason=f"OAuth Error: {e}")
        print(f"Помилка OAuth: {e}") 
        return redirect(url_for('login', message="Помилка аутентифікації через Google. Спробуйте ще раз."))

if __name__ == '__main__':
    app.run(debug=True)
