import re
import hashlib
import os
import random
import uuid
import pyotp
from captcha.image import ImageCaptcha
from datetime import datetime, timedelta 

USERS = {}

# Шаблон даних користувача
USER_TEMPLATE = {
    'password_hash': None, 
    'is_active': False,       # Завдання 3: Активація
    'login_attempts': 0,      # Завдання 4: Лічильник невдалих спроб
    '2fa_secret': None,       # Завдання 5: Секрет для 2FA
    'oauth_id': None,         # Завдання 5-2: ID стороннього сервісу
    'email': None             # Для активації та відновлення
}

ACTIVATION_TOKENS = {} 
RECOVERY_TOKENS = {}
TOKEN_LIFETIME = timedelta(minutes=15)

# Завдання 4: Обмеження спроб
MAX_LOGIN_ATTEMPTS = 3 
LOGIN_ATTEMPTS = {}     # { 'username': count }
BLOCKED_USERS = set()   # Набір заблокованих користувачів

# 1

def is_valid_password(password):
    if len(password) < 8:
        return "Пароль має бути не менше 8 символів."
    if not re.search(r"[a-z]", password):
        return "Пароль повинен містити малі літери."
    if not re.search(r"[A-Z]", password):
        return "Пароль повинен містити великі літери."
    if not re.search(r"\d", password):
        return "Пароль повинен містити цифру."
    if not re.search(r"[^a-zA-Z0-9\s]", password):
        return "Пароль повинен містити спецсимвол (не літеру і не цифру)."
        
    return True

def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.scrypt(
        password.encode('utf-8'), 
        salt=salt, 
        n=2**14, 
        r=8, 
        p=1, 
        dklen=32
    ).hex()
    return f"{hashed}:{salt.hex()}"

def verify_password(stored_info, provided_password):
    try:
        hashed_password_hex, salt_hex = stored_info.split(':')
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False 

    provided_hashed = hashlib.scrypt(
        provided_password.encode('utf-8'),
        salt=salt,
        n=2**14, 
        r=8, 
        p=1, 
        dklen=32
    ).hex()

    return provided_hashed == hashed_password_hex

# 2

def log_login_attempt(username, success, reason=""):

    try:
        with open("login_log.txt", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status = "УСПІХ" if success else "НЕВДАЧА"
            log_entry = f"[{timestamp}] - Користувач: {username:<10} - Статус: {status:<10} - Причина: {reason}\n"
            f.write(log_entry)
    except Exception as e:
        print(f"Помилка логування: {e}") 

def handle_failed_login(username):
    current_attempts = LOGIN_ATTEMPTS.get(username, 0) + 1
    LOGIN_ATTEMPTS[username] = current_attempts
    
    log_login_attempt(username, success=False, reason="Incorrect Password")
    
    if current_attempts >= MAX_LOGIN_ATTEMPTS:
        BLOCKED_USERS.add(username)
        print(f"!!! УВАГА: Обліковий запис '{username}' заблоковано через {MAX_LOGIN_ATTEMPTS} невдалих спроб підряд.")

# 3

def generate_captcha():

    image = ImageCaptcha(width=280, height=90)
    captcha_text = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    file_path = os.path.join("static", "captcha_image.png") 
    image.write(captcha_text, file_path)
    
    print(f"\n[CAPTCHA СЛУЖБОВЕ]: Файл '{file_path}' оновлено.")
    return captcha_text

# 4

def send_activation_email(username, email):
    token = str(uuid.uuid4())
    ACTIVATION_TOKENS[token] = username
    
    print(f"\n[СЛУЖБОВЕ ПОВІДОМЛЕННЯ]: Токен активації для {username}: {token}")
    
    return f"Надіслано активаційний лист на {email}. Будь ласка, використайте токен для активації."

def activate_user(token):
    if token in ACTIVATION_TOKENS:
        username = ACTIVATION_TOKENS.pop(token)
        if username in USERS:
            USERS[username]['is_active'] = True
            return f"Обліковий запис '{username}' успішно активовано! Тепер ви можете увійти."
    
    return "Невірний або прострочений токен активації."

# 5-1

def register_user_full(username, password, email):
    if username in USERS:
        return "Користувач з таким ім'ям вже існує."

    policy_check = is_valid_password(password)
    if policy_check is not True:
        return policy_check
        
    hashed_pass = hash_password(password)
    
    user_data = USER_TEMPLATE.copy()
    user_data.update({'password_hash': hashed_pass, 'email': email})
    
    USERS[username] = user_data
    
    # Завдання 3: Активація
    send_activation_email(username, email)
    
    return f"Користувач '{username}' успішно зареєстрований. Потрібна активація!"


# Управління 2FA (Завдання 5)

def enable_2fa(username):
    """Генерує секретний ключ для 2FA і зберігає його. Повертає секрет."""
    if username not in USERS: return None
    secret = pyotp.random_base32()
    USERS[username]['2fa_secret'] = secret
    return secret 

def disable_2fa(username):
    """Вимикає 2FA. Повертає True або False."""
    if username in USERS and USERS[username].get('2fa_secret'):
        USERS[username]['2fa_secret'] = None
        return True
    return False

def verify_2fa(username, otp_code):
    """Перевіряє TOTP-код, наданий користувачем."""
    user_data = USERS.get(username)
    if not user_data or not user_data.get('2fa_secret'):
        return True

    secret = user_data['2fa_secret']
    totp = pyotp.TOTP(secret)
    
    return totp.verify(otp_code)

def login_user(username, password, otp_code=None):

    # Завдання 4: Перевірка на блокування
    if username in BLOCKED_USERS:
        log_login_attempt(username, success=False, reason="Account Blocked")
        return False

    # Завдання 1: Ідентифікація
    if username not in USERS:
        log_login_attempt(username, success=False, reason="User Not Found")
        return False
        
    user_data = USERS[username]

    # Завдання 3: Перевірка активації
    if not user_data['is_active']:
        return False
        
    # Завдання 1: Аутентифікація (Пароль)
    if not verify_password(user_data['password_hash'], password):
        handle_failed_login(username) # Завдання 4
        return False
    
    LOGIN_ATTEMPTS[username] = 0 
    
    # Завдання 5: Перевірка 2FA
    if user_data.get('2fa_secret'):
        if otp_code is None:
             return False 
        
        if not verify_2fa(username, otp_code):
            log_login_attempt(username, success=False, reason="Invalid 2FA Code")
            return False 
            
    log_login_attempt(username, success=True, reason="Login Success")
    return True

# 5-2

def login_via_oauth(provider, oauth_id, email):
    found_username = None
    for username, data in USERS.items():
        if data.get('oauth_id') == oauth_id:
            found_username = username
            break
            
    if found_username:
        log_login_attempt(found_username, success=True, reason=f"OAuth Login via {provider}")
        return True, found_username

    username = f"{provider.lower()}_{oauth_id[:8]}" 
    
    random_password = os.urandom(16).hex()
    hashed_pass = hash_password(random_password) 
    
    user_data = USER_TEMPLATE.copy()
    user_data.update({
        'password_hash': hashed_pass, 
        'is_active': True,         
        'email': email,
        'oauth_id': oauth_id      
    })
    
    USERS[username] = user_data
    
    log_login_attempt(username, success=True, reason=f"OAuth Registration via {provider}")
    return True, username

# 7

def generate_recovery_token(email):
    username = None
    for uname, data in USERS.items():
        if data.get('email') == email:
            username = uname
            break
            
    if not username:
        return "Користувача з таким email не знайдено."
        
    token = str(uuid.uuid4())
    expiry = datetime.now() + TOKEN_LIFETIME
    
    RECOVERY_TOKENS[token] = {'username': username, 'expiry': expiry}
    
    print(f"\n[СЛУЖБОВЕ ПОВІДОМЛЕННЯ]: Токен відновлення для {username} (дійсний до {expiry.strftime('%Y-%m-%d %H:%M:%S')}): {token}")
    return "Надіслано лист для відновлення пароля. Використайте токен для скидання."

def reset_password(token, new_password):
    token_data = RECOVERY_TOKENS.get(token)
    
    if not token_data:
        return "Невірний токен."
        
    if datetime.now() > token_data['expiry']:
        del RECOVERY_TOKENS[token]
        return "Термін дії токена закінчився."
        
    policy_check = is_valid_password(new_password)
    if policy_check is not True:
        return policy_check
        
    RECOVERY_TOKENS.pop(token) 
    
    new_hashed_pass = hash_password(new_password)
    username = token_data['username']
    USERS[username]['password_hash'] = new_hashed_pass
    
    return f"Пароль для '{username}' успішно змінено. Тепер можете увійти."