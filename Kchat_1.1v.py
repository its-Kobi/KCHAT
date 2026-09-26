import socket
import sys
import threading
import json
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog
import os
import time
import struct
import io
import base64
import re
import uuid
import hashlib
import platform
from queue import Queue, Empty

try:
    from PIL import Image, ImageTk, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ====================== APP DATA LOCATION ======================

def _script_dir():
    """Directory containing this script (source checkout).

    Never used for writable data: inside a PyInstaller bundle, an
    AppImage, or a macOS .app this location may be read-only or
    ephemeral. Only used to find legacy files for migration and to
    resolve bundled resources in development.
    """
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        try:
            return os.getcwd()
        except Exception:
            return ""


def resource_path(*parts):
    """Resolve a bundled resource (e.g. icon) both in source and frozen.

    Under PyInstaller, data files are extracted to sys._MEIPASS;
    otherwise they live next to this script. Never write here.
    """
    base = getattr(sys, "_MEIPASS", None) or _script_dir()
    return os.path.join(base, *parts)


def _app_data_dir():
    """Return the per-user application data directory for KCHAT."""
    try:
        if os.name == 'nt':
            base = os.environ.get('APPDATA') or os.path.join(
                os.path.expanduser('~'), 'AppData', 'Roaming')
        elif sys.platform == 'darwin':
            base = os.path.join(os.path.expanduser('~'), 'Library',
                                'Application Support')
        else:
            base = os.environ.get('XDG_DATA_HOME') or os.path.join(
                os.path.expanduser('~'), '.local', 'share')
        path = os.path.join(base, 'KCHAT')
        os.makedirs(path, exist_ok=True)
        return path
    except Exception:
        return _script_dir()


APP_DATA_DIR = _app_data_dir()

# ====================== CONFIGURATION ======================

FORBIDDEN_WORDS = ["زبي", "زب", "لخرا", "يلعن", "fuck", "shit", "bitch", "cunt", "خرا", "الله يلعن", "يدك فيه", "قود", "تقود", "تحوى", "تحوا", "لحوا", "الزنا", "مك"]
SPAM_LIMIT = 5
SPAM_WINDOW = 10
MAX_MESSAGE_LENGTH = 500

DISCOVERY_PSK = b"KCHAT_SECURE_LAN_SALT_2026"

# Language preference lives in the per-user data dir so the app can
# always write it (exe dir / AppImage / .app bundle may be read-only).
CONFIG_PATH = os.path.join(APP_DATA_DIR, "kchat_config.json")

# Previous location (next to the script) — read once for migration.
LEGACY_CONFIG_PATH = os.path.join(_script_dir(), "kchat_config.json")

# Encrypted account store, kept in the user's AppData / Application Support
ACCOUNTS_PATH = os.path.join(APP_DATA_DIR, "kchat_accounts.enc")

# Old plaintext file (in the script folder) — auto-migrated on first run.
LEGACY_ACCOUNTS_PATH = os.path.join(_script_dir(), "kchat_accounts.json")

VALID_PERMISSIONS = ("admin", "vip", "sudo")
PERM_LEVEL = {"vip": 1, "admin": 2, "sudo": 3}

# ====================== SYSTEM ACCOUNTS ======================

# Envelope format:
#   Crypto path : MAGIC_CRYPTO   + 12-byte nonce + AES-256-GCM ciphertext
#   Fallback    : MAGIC_FALLBACK + 16-byte nonce + XOR(SHA256 keystream)
#   Legacy      : raw UTF-8 JSON  (auto-migrated on first load)
_ACCOUNTS_MAGIC_CRYPTO   = b'KCHATAC1'
_ACCOUNTS_MAGIC_FALLBACK = b'KCHATAF1'
_ACCOUNTS_AAD            = b'KCHAT-ACCOUNTS-V1'
_ACCOUNTS_SALT           = b'KCHAT-ACCOUNTS-SALT-2026'

_accounts_key_cache = None


def _accounts_key_material():
    """Machine + user specific material used to derive the storage key.

    This ties the encrypted file to the current OS user on the current
    machine: copying kchat_accounts.enc to another PC (or another user
    profile) will make it unreadable.
    """
    try:
        user = os.environ.get('USERNAME') or os.environ.get('USER') or ''
    except Exception:
        user = ''
    parts = [
        platform.system(),
        platform.machine(),
        platform.node(),
        user,
        str(uuid.getnode()),
        os.path.expanduser('~'),
    ]
    return '|'.join(parts).encode('utf-8', errors='ignore')


def _derive_accounts_key():
    """Derive a 32-byte key for the account store (cached)."""
    global _accounts_key_cache
    if _accounts_key_cache is not None:
        return _accounts_key_cache

    material = _accounts_key_material()
    if HAS_CRYPTO:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_ACCOUNTS_SALT,
            iterations=200_000,
        )
        key = kdf.derive(material)
    else:
        key = hashlib.sha256(b'KCHAT-ACCOUNTS-FB-' + material).digest()

    _accounts_key_cache = key
    return key


def _sha256_keystream(length, key, nonce):
    """SHA256-based keystream generator (fallback cipher only)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(
            key + nonce + counter.to_bytes(8, 'big')).digest())
        counter += 1
    return bytes(out[:length])


def _encrypt_accounts_blob(data: bytes) -> bytes:
    key = _derive_accounts_key()
    if HAS_CRYPTO:
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, data, _ACCOUNTS_AAD)
        return _ACCOUNTS_MAGIC_CRYPTO + nonce + ct

    # Fallback when 'cryptography' isn't installed.
    nonce = os.urandom(16)
    ks = _sha256_keystream(len(data), key, nonce)
    ct = bytes(a ^ b for a, b in zip(data, ks))
    return _ACCOUNTS_MAGIC_FALLBACK + nonce + ct


def _decrypt_accounts_blob(blob: bytes):
    """Return the decrypted JSON bytes, or None on failure."""
    if blob.startswith(_ACCOUNTS_MAGIC_CRYPTO):
        if not HAS_CRYPTO:
            return None
        nonce, ct = blob[8:20], blob[20:]
        try:
            return AESGCM(_derive_accounts_key()).decrypt(
                nonce, ct, _ACCOUNTS_AAD)
        except Exception:
            return None

    if blob.startswith(_ACCOUNTS_MAGIC_FALLBACK):
        nonce, ct = blob[8:24], blob[24:]
        key = _derive_accounts_key()
        ks = _sha256_keystream(len(ct), key, nonce)
        return bytes(a ^ b for a, b in zip(ct, ks))

    # Legacy plaintext JSON — accept it so we can migrate.
    try:
        text = blob.decode('utf-8').strip()
        if text.startswith('[') or text.startswith('{'):
            return text.encode('utf-8')
    except Exception:
        pass
    return None


def hash_password(password):
    return hashlib.sha256(("KCHAT_ACCT_" + password).encode("utf-8")).hexdigest()


def load_system_accounts():
    """Load accounts from the encrypted AppData store.

    If the store is missing but the old plaintext kchat_accounts.json
    exists next to the script, it is imported and re-written encrypted.
    """
    for path in (ACCOUNTS_PATH, LEGACY_ACCOUNTS_PATH):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                blob = f.read()
        except Exception:
            continue

        data = _decrypt_accounts_blob(blob)
        if data is None:
            continue

        try:
            accounts = json.loads(data.decode("utf-8"))
        except Exception:
            continue

        if not isinstance(accounts, list):
            continue

        # Migrate legacy plaintext file to encrypted AppData store.
        if path == LEGACY_ACCOUNTS_PATH:
            if save_system_accounts(accounts):
                try:
                    os.remove(LEGACY_ACCOUNTS_PATH)
                except Exception:
                    pass
        return accounts

    return []


def save_system_accounts(accounts):
    """Encrypt and atomically write accounts to the AppData store."""
    try:
        os.makedirs(APP_DATA_DIR, exist_ok=True)
        data = json.dumps(accounts, indent=2).encode("utf-8")
        blob = _encrypt_accounts_blob(data)

        tmp = ACCOUNTS_PATH + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, ACCOUNTS_PATH)

        # Restrict permissions on POSIX systems.
        try:
            if os.name != 'nt':
                os.chmod(ACCOUNTS_PATH, 0o600)
        except Exception:
            pass

        return True
    except Exception:
        return False


def verify_system_account(username, password):
    for acct in load_system_accounts():
        if acct.get("username") == username:
            if acct.get("password_hash") == hash_password(password):
                return acct
            return None
    return None


def user_level(perms):
    if not perms:
        return 0
    return max(PERM_LEVEL.get(p, 0) for p in perms)


def cli_create_account():
    print("=" * 52)
    print("  KCHAT - Create System Account")
    print("=" * 52)
    username = input("Username: ").strip()
    if not username:
        print("Error: username required.")
        return
    password = input("Password: ").strip()
    if not password:
        print("Error: password required.")

    print("Permissions - comma separated, choose from: admin, vip, sudo")
    perms_raw = input("Permissions: ").strip().lower()
    perms = [p.strip() for p in perms_raw.split(",") if p.strip() in VALID_PERMISSIONS]
    if not perms:
        print("Error: at least one valid permission required.")
        return

    tag = input("Tag (shown next to your name): ").strip()
    if not tag:
        print("Error: tag required.")
        return
    tag = tag[:20]

    color = input("Tag color (hex, e.g. #e11d48): ").strip()
    if not color:
        color = "#e11d48"
    ok = (color.startswith("#") and len(color) in (4, 7)) or color.isalpha()
    if not ok:
        print("Warning: unusual color, using default #e11d48.")
        color = "#e11d48"

    accounts = load_system_accounts()
    for a in accounts:
        if a.get("username") == username:
            print(f"Error: account '{username}' already exists.")
            return

    accounts.append({
        "username": username,
        "password_hash": hash_password(password),
        "permissions": perms,
        "tag": tag,
        "color": color,
    })
    if save_system_accounts(accounts):
        print()
        print(f"  Account '{username}' created.")
        print(f"  Permissions: {', '.join(perms)}")
        print(f"  Tag: {tag}  |  Color: {color}")
        print(f"  Stored (encrypted) at: {ACCOUNTS_PATH}")
    else:
        print("Error: could not save.")


def cli_list_accounts():
    accounts = load_system_accounts()
    if not accounts:
        print("No system accounts.")
        return
    print(f"{len(accounts)} account(s):")
    for a in accounts:
        print(f"  - {a.get('username')}  [{', '.join(a.get('permissions', []))}]  tag={a.get('tag')}  color={a.get('color')}")


def cli_delete_account():
    username = input("Username to delete: ").strip()
    if not username:
        return
    accounts = load_system_accounts()
    new_list = [a for a in accounts if a.get("username") != username]
    if len(new_list) == len(accounts):
        print("Account not found.")
        return
    if save_system_accounts(new_list):
        print(f"Deleted '{username}'.")


# ====================== LANGUAGES / i18n ======================

LANGUAGE_NAMES = {
    "ar": "العربية",
    "en": "English",
    "fr": "Français",
    "es": "Español",
    "de": "Deutsch",
    "tr": "Türkçe",
}

STRINGS = {
    "ar": {
        "app_header_title": "KCHAT",
        "login_title": "KCHAT",
        "login_subtitle": "دردشة مشفرة آمنة للشبكات المحلية",
        "language_label": "اللغة",
        "username_label": "اسم المستخدم",
        "login_button": "دخول آمن",
        "login_with_system_account": "الدخول بحساب النظام",
        "rooms_panel_title": "الغرف",
        "join_button": "دخول",
        "create_room_button": "غرفة جديدة",
        "leave_button": "خروج",
        "send_button": "إرسال",
        "status_offline": "غير متصل",
        "status_host": "أنت المضيف",
        "status_connected": "متصل",
        "status_searching": "جاري البحث...",
        "status_reconnecting": "إعادة الاتصال...",
        "dialog_create_room_title": "إنشاء غرفة مشفرة",
        "dialog_room_name_label": "اسم الغرفة",
        "dialog_room_password_label": "كلمة المرور (اختياري)",
        "dialog_create_confirm": "إنشاء",
        "dialog_protected_title": "غرفة محمية",
        "dialog_enter_password_label": "أدخل كلمة المرور",
        "dialog_join_confirm": "دخول",
        "dialog_cancel": "إلغاء",
        "dialog_system_login_title": "الدخول بحساب النظام",
        "dialog_system_username_label": "اسم حساب النظام",
        "dialog_system_password_label": "كلمة المرور",
        "dialog_system_login_confirm": "دخول",
        "toast_avatar_updated": "تم تحديث الصورة الشخصية",
        "msg_rooms_updated": "تم تحديث الغرف",
        "msg_you_are_host": "أنت الآن المضيف",
        "msg_connection_lost": "انقطع الاتصال",
        "err_username_required": "الرجاء إدخال اسم المستخدم",
        "err_username_taken": "اسم المستخدم مستخدم بالفعل",
        "err_room_name_required": "الرجاء إدخال اسم الغرفة",
        "err_room_not_found": "الغرفة غير موجودة",
        "err_wrong_password": "كلمة المرور غير صحيحة",
        "err_message_too_long": "الرسالة طويلة جدًا",
        "err_message_blocked": "الرسالة تحتوي على محتوى غير مسموح",
        "err_rate_limit": "أنت ترسل رسائل بسرعة كبيرة!",
        "err_unknown": "خطأ غير معروف",
        "err_system_account_invalid": "حساب النظام أو كلمة المرور غير صحيحة",
        "err_system_account_missing": "لا توجد حسابات نظام على هذا الجهاز",
        "err_no_permission": "ليس لديك صلاحية لهذا الإجراء",
        "err_ban_denied": "لا يمكنك حظر مستخدم بمستوى أعلى أو مساوٍ",
        "err_banned": "تم حظرك من هذا الخادم",
        "sys_joined_room": "دخلت الغرفة: {room}",
        "sys_user_joined_public": "{user} دخل الغرفة العامة",
        "sys_user_left": "{user} غادر",
        "sys_left_room": "غادرت الغرفة",
        "sys_user_banned": "تم حظر {user} من الخادم",
        "sys_you_were_banned": "تم حظرك من الخادم",
        "sys_message_deleted": "تم حذف رسالة",
        "ctx_delete_message": "حذف الرسالة",
        "ctx_ban_user": "حظر المستخدم",
        "empty_chat_title": "اختر غرفة للبدء",
        "empty_chat_subtitle": "اختر غرفة من القائمة أو أنشئ غرفة جديدة",
        "empty_rooms": "لا توجد غرف بعد",
    },
    "en": {
        "app_header_title": "KCHAT",
        "login_title": "KCHAT",
        "login_subtitle": "Secure encrypted chat for local networks",
        "language_label": "Language",
        "username_label": "Username",
        "login_button": "Secure login",
        "login_with_system_account": "Login with system account",
        "rooms_panel_title": "Rooms",
        "join_button": "Join",
        "create_room_button": "New room",
        "leave_button": "Leave",
        "send_button": "Send",
        "status_offline": "Offline",
        "status_host": "You are the host",
        "status_connected": "Connected",
        "status_searching": "Searching...",
        "status_reconnecting": "Reconnecting...",
        "dialog_create_room_title": "Create an encrypted room",
        "dialog_room_name_label": "Room name",
        "dialog_room_password_label": "Password (optional)",
        "dialog_create_confirm": "Create",
        "dialog_protected_title": "Protected room",
        "dialog_enter_password_label": "Enter password",
        "dialog_join_confirm": "Join",
        "dialog_cancel": "Cancel",
        "dialog_system_login_title": "Login with system account",
        "dialog_system_username_label": "Account username",
        "dialog_system_password_label": "Password",
        "dialog_system_login_confirm": "Login",
        "toast_avatar_updated": "Avatar updated",
        "msg_rooms_updated": "Rooms updated",
        "msg_you_are_host": "You are now the host",
        "msg_connection_lost": "Connection lost",
        "err_username_required": "Please enter a username",
        "err_username_taken": "Username already taken",
        "err_room_name_required": "Please enter a room name",
        "err_room_not_found": "Room not found",
        "err_wrong_password": "Incorrect password",
        "err_message_too_long": "Message is too long",
        "err_message_blocked": "Message blocked: contains disallowed content",
        "err_rate_limit": "You're sending messages too fast!",
        "err_unknown": "Unknown error",
        "err_system_account_invalid": "Invalid system account or password",
        "err_system_account_missing": "No system accounts on this device",
        "err_no_permission": "You don't have permission for this action",
        "err_ban_denied": "You can't ban a user at the same or higher level",
        "err_banned": "You have been banned from this server",
        "sys_joined_room": "Joined room: {room}",
        "sys_user_joined_public": "{user} joined the public room",
        "sys_user_left": "{user} left",
        "sys_left_room": "You left the room",
        "sys_user_banned": "{user} was banned from the server",
        "sys_you_were_banned": "You were banned from the server",
        "sys_message_deleted": "A message was deleted",
        "ctx_delete_message": "Delete message",
        "ctx_ban_user": "Ban user",
        "empty_chat_title": "Select a room to start",
        "empty_chat_subtitle": "Pick a room from the list or create a new one",
        "empty_rooms": "No rooms yet",
    },
    "fr": {
        "app_header_title": "KCHAT",
        "login_title": "KCHAT",
        "login_subtitle": "Chat chiffré et sécurisé pour réseaux locaux",
        "language_label": "Langue",
        "username_label": "Nom d'utilisateur",
        "login_button": "Connexion sécurisée",
        "login_with_system_account": "Connexion avec un compte système",
        "rooms_panel_title": "Salons",
        "join_button": "Rejoindre",
        "create_room_button": "Nouveau salon",
        "leave_button": "Quitter",
        "send_button": "Envoyer",
        "status_offline": "Hors ligne",
        "status_host": "Vous êtes l'hôte",
        "status_connected": "Connecté",
        "status_searching": "Recherche...",
        "status_reconnecting": "Reconnexion...",
        "dialog_create_room_title": "Créer un salon chiffré",
        "dialog_room_name_label": "Nom du salon",
        "dialog_room_password_label": "Mot de passe (optionnel)",
        "dialog_create_confirm": "Créer",
        "dialog_protected_title": "Salon protégé",
        "dialog_enter_password_label": "Entrez le mot de passe",
        "dialog_join_confirm": "Rejoindre",
        "dialog_cancel": "Annuler",
        "dialog_system_login_title": "Connexion compte système",
        "dialog_system_username_label": "Nom du compte",
        "dialog_system_password_label": "Mot de passe",
        "dialog_system_login_confirm": "Connexion",
        "toast_avatar_updated": "Avatar mis à jour",
        "msg_rooms_updated": "Salons mis à jour",
        "msg_you_are_host": "Vous êtes désormais l'hôte",
        "msg_connection_lost": "Connexion perdue",
        "err_username_required": "Veuillez entrer un nom d'utilisateur",
        "err_username_taken": "Nom d'utilisateur déjà pris",
        "err_room_name_required": "Veuillez entrer un nom de salon",
        "err_room_not_found": "Salon introuvable",
        "err_wrong_password": "Mot de passe incorrect",
        "err_message_too_long": "Message trop long",
        "err_message_blocked": "Message bloqué : contenu non autorisé",
        "err_rate_limit": "Vous envoyez des messages trop vite !",
        "err_unknown": "Erreur inconnue",
        "err_system_account_invalid": "Compte système ou mot de passe invalide",
        "err_system_account_missing": "Aucun compte système sur cet appareil",
        "err_no_permission": "Permission refusée",
        "err_ban_denied": "Impossible de bannir un niveau égal ou supérieur",
        "err_banned": "Vous avez été banni de ce serveur",
        "sys_joined_room": "Vous avez rejoint : {room}",
        "sys_user_joined_public": "{user} a rejoint le salon public",
        "sys_user_left": "{user} est parti",
        "sys_left_room": "Vous avez quitté le salon",
        "sys_user_banned": "{user} a été banni du serveur",
        "sys_you_were_banned": "Vous avez été banni du serveur",
        "sys_message_deleted": "Un message a été supprimé",
        "ctx_delete_message": "Supprimer le message",
        "ctx_ban_user": "Bannir l'utilisateur",
        "empty_chat_title": "Sélectionnez un salon",
        "empty_chat_subtitle": "Choisissez un salon dans la liste ou créez-en un",
        "empty_rooms": "Aucun salon",
    },
    "es": {
        "app_header_title": "KCHAT",
        "login_title": "KCHAT",
        "login_subtitle": "Chat cifrado y seguro para redes locales",
        "language_label": "Idioma",
        "username_label": "Nombre de usuario",
        "login_button": "Acceso seguro",
        "login_with_system_account": "Entrar con cuenta del sistema",
        "rooms_panel_title": "Salas",
        "join_button": "Entrar",
        "create_room_button": "Nueva sala",
        "leave_button": "Salir",
        "send_button": "Enviar",
        "status_offline": "Desconectado",
        "status_host": "Eres el anfitrión",
        "status_connected": "Conectado",
        "status_searching": "Buscando...",
        "status_reconnecting": "Reconectando...",
        "dialog_create_room_title": "Crear una sala cifrada",
        "dialog_room_name_label": "Nombre de la sala",
        "dialog_room_password_label": "Contraseña (opcional)",
        "dialog_create_confirm": "Crear",
        "dialog_protected_title": "Sala protegida",
        "dialog_enter_password_label": "Introduce la contraseña",
        "dialog_join_confirm": "Entrar",
        "dialog_cancel": "Cancelar",
        "dialog_system_login_title": "Entrar con cuenta del sistema",
        "dialog_system_username_label": "Nombre de la cuenta",
        "dialog_system_password_label": "Contraseña",
        "dialog_system_login_confirm": "Entrar",
        "toast_avatar_updated": "Avatar actualizado",
        "msg_rooms_updated": "Salas actualizadas",
        "msg_you_are_host": "Ahora eres el anfitrión",
        "msg_connection_lost": "Conexión perdida",
        "err_username_required": "Introduce un nombre de usuario",
        "err_username_taken": "Ese nombre de usuario ya está en uso",
        "err_room_name_required": "Introduce un nombre de sala",
        "err_room_not_found": "Sala no encontrada",
        "err_wrong_password": "Contraseña incorrecta",
        "err_message_too_long": "El mensaje es demasiado largo",
        "err_message_blocked": "Mensaje bloqueado: contenido no permitido",
        "err_rate_limit": "¡Estás enviando mensajes demasiado rápido!",
        "err_unknown": "Error desconocido",
        "err_system_account_invalid": "Cuenta del sistema o contraseña inválida",
        "err_system_account_missing": "No hay cuentas del sistema en este equipo",
        "err_no_permission": "No tienes permiso para esta acción",
        "err_ban_denied": "No puedes banear a un nivel igual o superior",
        "err_banned": "Has sido baneado de este servidor",
        "sys_joined_room": "Entraste a la sala: {room}",
        "sys_user_joined_public": "{user} entró a la sala pública",
        "sys_user_left": "{user} salió",
        "sys_left_room": "Saliste de la sala",
        "sys_user_banned": "{user} fue baneado del servidor",
        "sys_you_were_banned": "Fuiste baneado del servidor",
        "sys_message_deleted": "Se eliminó un mensaje",
        "ctx_delete_message": "Eliminar mensaje",
        "ctx_ban_user": "Banear usuario",
        "empty_chat_title": "Selecciona una sala",
        "empty_chat_subtitle": "Elige una sala de la lista o crea una nueva",
        "empty_rooms": "Sin salas",
    },
    "de": {
        "app_header_title": "KCHAT",
        "login_title": "KCHAT",
        "login_subtitle": "Sicherer verschlüsselter Chat für lokale Netzwerke",
        "language_label": "Sprache",
        "username_label": "Benutzername",
        "login_button": "Sicher anmelden",
        "login_with_system_account": "Mit Systemkonto anmelden",
        "rooms_panel_title": "Räume",
        "join_button": "Beitreten",
        "create_room_button": "Neuer Raum",
        "leave_button": "Verlassen",
        "send_button": "Senden",
        "status_offline": "Offline",
        "status_host": "Du bist der Host",
        "status_connected": "Verbunden",
        "status_searching": "Suche...",
        "status_reconnecting": "Neuverbindung...",
        "dialog_create_room_title": "Verschlüsselten Raum erstellen",
        "dialog_room_name_label": "Raumname",
        "dialog_room_password_label": "Passwort (optional)",
        "dialog_create_confirm": "Erstellen",
        "dialog_protected_title": "Geschützter Raum",
        "dialog_enter_password_label": "Passwort eingeben",
        "dialog_join_confirm": "Beitreten",
        "dialog_cancel": "Abbrechen",
        "dialog_system_login_title": "Mit Systemkonto anmelden",
        "dialog_system_username_label": "Kontoname",
        "dialog_system_password_label": "Passwort",
        "dialog_system_login_confirm": "Anmelden",
        "toast_avatar_updated": "Avatar aktualisiert",
        "msg_rooms_updated": "Räume aktualisiert",
        "msg_you_are_host": "Du bist jetzt der Host",
        "msg_connection_lost": "Verbindung getrennt",
        "err_username_required": "Bitte gib einen Benutzernamen ein",
        "err_username_taken": "Benutzername bereits vergeben",
        "err_room_name_required": "Bitte gib einen Raumnamen ein",
        "err_room_not_found": "Raum nicht gefunden",
        "err_wrong_password": "Falsches Passwort",
        "err_message_too_long": "Nachricht ist zu lang",
        "err_message_blocked": "Nachricht blockiert: unzulässiger Inhalt",
        "err_rate_limit": "Du sendest Nachrichten zu schnell!",
        "err_unknown": "Unbekannter Fehler",
        "err_system_account_invalid": "Ungültiges Systemkonto oder Passwort",
        "err_system_account_missing": "Keine Systemkonten auf diesem Gerät",
        "err_no_permission": "Keine Berechtigung",
        "err_ban_denied": "Kein Bann gegen gleiche oder höhere Stufe möglich",
        "err_banned": "Du wurdest von diesem Server gebannt",
        "sys_joined_room": "Raum betreten: {room}",
        "sys_user_joined_public": "{user} ist dem öffentlichen Raum beigetreten",
        "sys_user_left": "{user} hat den Chat verlassen",
        "sys_left_room": "Du hast den Raum verlassen",
        "sys_user_banned": "{user} wurde vom Server gebannt",
        "sys_you_were_banned": "Du wurdest vom Server gebannt",
        "sys_message_deleted": "Eine Nachricht wurde gelöscht",
        "ctx_delete_message": "Nachricht löschen",
        "ctx_ban_user": "Benutzer bannen",
        "empty_chat_title": "Raum auswählen",
        "empty_chat_subtitle": "Wähle einen Raum oder erstelle einen neuen",
        "empty_rooms": "Keine Räume",
    },
    "tr": {
        "app_header_title": "KCHAT",
        "login_title": "KCHAT",
        "login_subtitle": "Yerel ağlar için güvenli, şifreli sohbet",
        "language_label": "Dil",
        "username_label": "Kullanıcı adı",
        "login_button": "Güvenli giriş",
        "login_with_system_account": "Sistem hesabıyla giriş",
        "rooms_panel_title": "Odalar",
        "join_button": "Katıl",
        "create_room_button": "Yeni oda",
        "leave_button": "Ayrıl",
        "send_button": "Gönder",
        "status_offline": "Çevrimdışı",
        "status_host": "Sunucusun",
        "status_connected": "Bağlandı",
        "status_searching": "Aranıyor...",
        "status_reconnecting": "Yeniden bağlanılıyor...",
        "dialog_create_room_title": "Şifreli oda oluştur",
        "dialog_room_name_label": "Oda adı",
        "dialog_room_password_label": "Şifre (isteğe bağlı)",
        "dialog_create_confirm": "Oluştur",
        "dialog_protected_title": "Korumalı oda",
        "dialog_enter_password_label": "Şifreyi girin",
        "dialog_join_confirm": "Katıl",
        "dialog_cancel": "İptal",
        "dialog_system_login_title": "Sistem hesabıyla giriş",
        "dialog_system_username_label": "Hesap adı",
        "dialog_system_password_label": "Şifre",
        "dialog_system_login_confirm": "Giriş",
        "toast_avatar_updated": "Avatar güncellendi",
        "msg_rooms_updated": "Odalar güncellendi",
        "msg_you_are_host": "Artık sunucusun",
        "msg_connection_lost": "Bağlantı kesildi",
        "err_username_required": "Lütfen bir kullanıcı adı girin",
        "err_username_taken": "Bu kullanıcı adı zaten alınmış",
        "err_room_name_required": "Lütfen bir oda adı girin",
        "err_room_not_found": "Oda bulunamadı",
        "err_wrong_password": "Yanlış şifre",
        "err_message_too_long": "Mesaj çok uzun",
        "err_message_blocked": "Mesaj engellendi: izin verilmeyen içerik",
        "err_rate_limit": "Çok hızlı mesaj gönderiyorsun!",
        "err_unknown": "Bilinmeyen hata",
        "err_system_account_invalid": "Geçersiz sistem hesabı veya şifre",
        "err_system_account_missing": "Bu cihazda sistem hesabı yok",
        "err_no_permission": "Bu işlem için yetkin yok",
        "err_ban_denied": "Aynı veya daha yüksek seviyeyi yasaklayamazsın",
        "err_banned": "Bu sunucudan yasaklandın",
        "sys_joined_room": "Katıldığın oda: {room}",
        "sys_user_joined_public": "{user} genel odaya katıldı",
        "sys_user_left": "{user} ayrıldı",
        "sys_left_room": "Odadan ayrıldın",
        "sys_user_banned": "{user} sunucudan yasaklandı",
        "sys_you_were_banned": "Sunucudan yasaklandın",
        "sys_message_deleted": "Bir mesaj silindi",
        "ctx_delete_message": "Mesajı sil",
        "ctx_ban_user": "Kullanıcıyı yasakla",
        "empty_chat_title": "Bir oda seç",
        "empty_chat_subtitle": "Listeden bir oda seç veya yeni bir tane oluştur",
        "empty_rooms": "Henüz oda yok",
    },
}

DEFAULT_LANGUAGE = "ar"


def load_saved_language():
    for path in (CONFIG_PATH, LEGACY_CONFIG_PATH):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                lang = data.get("language")
                if lang in STRINGS:
                    return lang
        except Exception:
            continue
    return DEFAULT_LANGUAGE


def save_language(lang_code):
    try:
        os.makedirs(APP_DATA_DIR, exist_ok=True)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"language": lang_code}, f)
        os.replace(tmp, CONFIG_PATH)
    except Exception:
        pass


def tr(lang_code, key, **kwargs):
    table = STRINGS.get(lang_code, STRINGS[DEFAULT_LANGUAGE])
    text = table.get(key) or STRINGS[DEFAULT_LANGUAGE].get(key, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text


# ====================== SECURITY / ENCRYPTION ======================

if HAS_CRYPTO:
    _discovery_aesgcm = AESGCM(hashlib.sha256(DISCOVERY_PSK).digest())
else:
    _discovery_aesgcm = None


def encrypt_discovery(obj):
    plaintext = json.dumps(obj).encode("utf-8")
    if not HAS_CRYPTO:
        return base64.b64encode(plaintext).decode("utf-8")
    nonce = os.urandom(12)
    ct = _discovery_aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode("utf-8")


def decrypt_discovery(b64_str):
    try:
        raw = base64.b64decode(b64_str.encode("utf-8"))
        if not HAS_CRYPTO:
            return json.loads(raw.decode("utf-8"))
        nonce, ct = raw[:12], raw[12:]
        plaintext = _discovery_aesgcm.decrypt(nonce, ct, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return priv, pub_bytes


def x25519_derive_session_key(private_key, peer_public_bytes):
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=b"KCHAT-SESSION-SALT", info=b"kchat-v2-session-key")
    return hkdf.derive(shared_secret)


class SecureChannel:
    def __init__(self, sock, session_key):
        self.sock = sock
        self.aesgcm = AESGCM(session_key)
        self._send_lock = threading.Lock()

    def _send_raw(self, data):
        self.sock.sendall(struct.pack(">I", len(data)) + data)

    def _recv_raw(self):
        header = _recv_exact(self.sock, 4)
        if header is None:
            return None
        (length,) = struct.unpack(">I", header)
        if length <= 0 or length > 20 * 1024 * 1024:
            return None
        return _recv_exact(self.sock, length)

    def send_json(self, obj):
        plaintext = json.dumps(obj).encode("utf-8")
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext, None)
        with self._send_lock:
            self._send_raw(nonce + ct)

    def recv_json(self):
        raw = self._recv_raw()
        if raw is None or len(raw) < 13:
            return None
        nonce, ct = raw[:12], raw[12:]
        try:
            plaintext = self.aesgcm.decrypt(nonce, ct, None)
            return json.loads(plaintext.decode("utf-8"))
        except Exception:
            return None

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def server_handshake(client_sock):
    client_sock.settimeout(5)
    try:
        client_pub_bytes = _recv_exact(client_sock, 32)
        if client_pub_bytes is None:
            return None
        server_priv, server_pub_bytes = x25519_keypair()
        client_sock.sendall(server_pub_bytes)
        session_key = x25519_derive_session_key(server_priv, client_pub_bytes)
    except Exception:
        return None
    finally:
        try:
            client_sock.settimeout(None)
        except Exception:
            pass
    return SecureChannel(client_sock, session_key)


def client_handshake(sock):
    try:
        client_priv, client_pub_bytes = x25519_keypair()
        sock.sendall(client_pub_bytes)
        server_pub_bytes = _recv_exact(sock, 32)
        if server_pub_bytes is None:
            return None
        session_key = x25519_derive_session_key(client_priv, server_pub_bytes)
    except Exception:
        return None
    return SecureChannel(sock, session_key)


# ====================== NETWORKING ======================

def get_local_ip():
    try:
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for addr in addrs:
            ip = addr[4][0]
            if ip != '127.0.0.1' and not ip.startswith('169.254'):
                parts = ip.split('.')
                first = int(parts[0])
                if (first == 10) or (first == 172 and 16 <= int(parts[1]) <= 31) or (first == 192 and int(parts[1]) == 168):
                    return ip
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def get_broadcast_ip():
    ip = get_local_ip()
    if ip == '127.0.0.1':
        return '255.255.255.255'
    parts = ip.split('.')
    parts[-1] = '255'
    return '.'.join(parts)


class ReplicatedState:
    def __init__(self):
        self.lock = threading.Lock()
        self.version = 0
        self.rooms = {'public': {'name': 'public', 'code': 'public', 'is_protected': False}}

    def update(self, version, rooms):
        with self.lock:
            if version > self.version:
                self.version = version
                self.rooms = rooms
                return True
            return False

    def get_rooms(self):
        with self.lock:
            return dict(self.rooms)

    def get_version(self):
        with self.lock:
            return self.version

    def increment_and_set_rooms(self, rooms):
        with self.lock:
            self.version += 1
            cleaned_rooms = {}
            for code, data in rooms.items():
                cleaned_rooms[code] = {
                    'name': data['name'],
                    'code': code,
                    'is_protected': data.get('is_protected', False)
                }
            self.rooms = cleaned_rooms

    def to_dict(self):
        with self.lock:
            return {'version': self.version, 'rooms': dict(self.rooms)}

    def clear(self):
        with self.lock:
            self.version = 0
            self.rooms = {'public': {'name': 'public', 'code': 'public', 'is_protected': False}}


class DiscoveryManager:
    DISCOVERY_PORT = 5001
    HEARTBEAT_INTERVAL = 2.0
    ELECTION_TIMEOUT = 5.0
    DISCOVER_WAIT = 2.0
    STATE_SYNC_INTERVAL = 10.0

    def __init__(self, on_host_elected, on_client_connect, on_status_update):
        self.on_host_elected = on_host_elected
        self.on_client_connect = on_client_connect
        self.on_status_update = on_status_update
        self.local_ip = get_local_ip()
        self.broadcast_ip = get_broadcast_ip()
        self.host_ip = None
        self.is_host = False
        self.running = False
        self.udp_sock = None
        self.election_in_progress = False
        self.last_heartbeat = 0
        self.stop_event = threading.Event()
        self.pending_election_responses = set()
        self.state = ReplicatedState()
        self.server = None

    def start(self):
        self.running = True
        self.stop_event.clear()
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind(('', self.DISCOVERY_PORT))
            self.udp_sock.settimeout(1.0)
        except Exception:
            self.on_status_update("status_searching")
            return

        threading.Thread(target=self._receiver_loop, daemon=True).start()
        self.on_status_update("status_searching")
        self._send_discover()
        time.sleep(self.DISCOVER_WAIT)

        if not self.running:
            return
        if not self.host_ip and not self.is_host:
            self._become_host()
        elif self.host_ip:
            self.on_client_connect(self.host_ip, 5000)

    def _receiver_loop(self):
        while self.running and not self.stop_event.is_set():
            try:
                data, addr = self.udp_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                break
            if not data:
                continue
            msg = decrypt_discovery(data.decode(errors="ignore"))
            if msg is None:
                continue
            msg_type = msg.get('type')
            sender_ip = addr[0]
            if sender_ip == self.local_ip:
                continue
            try:
                if msg_type == 'DISCOVER':
                    if self.is_host:
                        self._send_host_announce(to_addr=(sender_ip, self.DISCOVERY_PORT))
                elif msg_type == 'HOST_ANNOUNCE':
                    if not self.is_host:
                        self.host_ip = sender_ip
                        self.last_heartbeat = time.time()
                        if self.election_in_progress:
                            self.election_in_progress = False
                elif msg_type == 'ELECTION_REQUEST':
                    if not self.is_host:
                        self._send_election_response((sender_ip, self.DISCOVERY_PORT))
                elif msg_type == 'ELECTION_RESPONSE':
                    if not self.is_host and self.election_in_progress:
                        self.pending_election_responses.add(sender_ip)
                elif msg_type == 'HOST_ELECTED':
                    if sender_ip != self.local_ip:
                        self.host_ip = sender_ip
                        self.last_heartbeat = time.time()
                        self.is_host = False
                        self.election_in_progress = False
                        self.on_client_connect(self.host_ip, 5000)
                elif msg_type == 'HOST_SHUTDOWN':
                    if not self.is_host and self.host_ip == sender_ip:
                        self.host_ip = None
                        self._start_election()
            except Exception:
                continue

    def _send_discover(self):
        self._broadcast({'type': 'DISCOVER', 'sender': self.local_ip})

    def _send_host_announce(self, to_addr=None):
        msg = {'type': 'HOST_ANNOUNCE', 'host': self.local_ip}
        if to_addr:
            try:
                if not self.udp_sock:
                    return
                encrypted = encrypt_discovery(msg)
                self.udp_sock.sendto(encrypted.encode(), to_addr)
            except Exception:
                pass
        else:
            self._broadcast(msg)

    def _send_election_request(self):
        self.election_in_progress = True
        self.pending_election_responses.clear()
        self._broadcast({'type': 'ELECTION_REQUEST', 'sender': self.local_ip})

    def _send_election_response(self, to_addr):
        try:
            if not self.udp_sock:
                return
            msg = {'type': 'ELECTION_RESPONSE', 'sender': self.local_ip}
            encrypted = encrypt_discovery(msg)
            self.udp_sock.sendto(encrypted.encode(), to_addr)
        except Exception:
            pass

    def _send_host_elected(self):
        self._broadcast({'type': 'HOST_ELECTED', 'host': self.local_ip})

    def _send_host_shutdown(self):
        self._broadcast({'type': 'HOST_SHUTDOWN', 'host': self.local_ip})

    def _broadcast(self, msg):
        try:
            if not self.udp_sock:
                return
            encrypted = encrypt_discovery(msg)
            self.udp_sock.sendto(encrypted.encode(), (self.broadcast_ip, self.DISCOVERY_PORT))
        except Exception:
            pass

    def _become_host(self):
        self.is_host = True
        self.host_ip = self.local_ip
        self.on_status_update("status_host")
        self.on_host_elected()
        self._send_host_elected()
        self._start_heartbeat()
        self._start_state_sync_timer()

    def _start_heartbeat(self):
        def loop():
            while self.running and self.is_host and not self.stop_event.is_set():
                self._send_host_announce()
                if self.stop_event.wait(self.HEARTBEAT_INTERVAL):
                    break
        threading.Thread(target=loop, daemon=True).start()

    def _start_state_sync_timer(self):
        def loop():
            while self.running and self.is_host and not self.stop_event.is_set():
                if self.stop_event.wait(self.STATE_SYNC_INTERVAL):
                    break
                if self.is_host and self.server:
                    state_dict = self.state.to_dict()
                    self.server.broadcast_to_all({
                        'type': 'state_sync',
                        'version': state_dict['version'],
                        'state': state_dict['rooms']
                    })
        threading.Thread(target=loop, daemon=True).start()

    def _start_election(self):
        if self.election_in_progress:
            return
        self.on_status_update("status_reconnecting")
        self.election_in_progress = True
        self._send_election_request()

        def timeout():
            if not self.running:
                return
            if self.election_in_progress and not self.is_host:
                if not self.host_ip:
                    self._become_host()
                self.election_in_progress = False
        threading.Timer(1.5, timeout).start()

    def shutdown(self):
        self.running = False
        self.stop_event.set()
        if self.is_host:
            self._send_host_shutdown()
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
            self.udp_sock = None

    def receive_state_update(self, version, rooms):
        if self.is_host:
            return
        if self.state.update(version, rooms):
            self.on_status_update("msg_rooms_updated")

    def get_state(self):
        return self.state.get_rooms()

    def clear_state(self):
        self.state.clear()

    def on_state_changed(self, new_rooms):
        if not self.is_host:
            return
        self.state.increment_and_set_rooms(new_rooms)
        state_dict = self.state.to_dict()
        if self.server:
            self.server.broadcast_to_all({
                'type': 'state_update',
                'version': state_dict['version'],
                'state': state_dict['rooms']
            })


class ChatServer:
    def __init__(self, host='0.0.0.0', port=5000, initial_state=None, state_change_callback=None):
        self.host = host
        self.port = port
        self.rooms = {'public': {'name': 'public', 'clients': set(), 'password': '', 'is_protected': False}}
        if initial_state:
            for code, data in initial_state.items():
                if code != 'public':
                    self.rooms[code] = {
                        'name': data['name'], 'clients': set(),
                        'password': data.get('password', ''),
                        'is_protected': data.get('is_protected', False)
                    }
        self.clients = {}
        self.lock = threading.Lock()
        self.running = True
        self.state_change_callback = state_change_callback
        self.server_sock = None
        self.banned_users = set()
        self.message_counter = 0

    def _normalize_text(self, text):
        text = text.lower()
        text = re.sub(r'[^\w]', '', text)
        text = re.sub(r'(.)\1+', r'\1', text)
        return text

    def _contains_forbidden(self, text):
        norm = self._normalize_text(text)
        for word in FORBIDDEN_WORDS:
            wnorm = self._normalize_text(word)
            if wnorm and wnorm in norm:
                return True
        return False

    def _check_rate_limit(self, channel):
        now = time.time()
        with self.lock:
            if channel not in self.clients:
                return False
            timestamps = self.clients[channel].get('msg_timestamps', [])
            timestamps = [t for t in timestamps if now - t < SPAM_WINDOW]
            if len(timestamps) >= SPAM_LIMIT:
                return True
            timestamps.append(now)
            self.clients[channel]['msg_timestamps'] = timestamps
            return False

    def _send(self, channel, msg_dict):
        try:
            channel.send_json(msg_dict)
        except Exception:
            pass

    def broadcast(self, message, room_code, exclude_channel=None):
        with self.lock:
            if room_code not in self.rooms:
                return
            targets = [c for c in self.rooms[room_code]['clients'] if c != exclude_channel]
        for channel in targets:
            self._send(channel, message)

    def broadcast_to_all(self, message):
        with self.lock:
            targets = list(self.clients.keys())
        for channel in targets:
            self._send(channel, message)

    def broadcast_room_list(self):
        rooms_info = []
        with self.lock:
            for code, data in self.rooms.items():
                rooms_info.append({'name': data['name'], 'code': code, 'is_protected': data.get('is_protected', False)})
            targets = list(self.clients.keys())
        response = {'type': 'room_list', 'rooms': rooms_info}
        for channel in targets:
            self._send(channel, response)

    def handle_client(self, raw_sock, addr):
        channel = server_handshake(raw_sock)
        if channel is None:
            try:
                raw_sock.close()
            except Exception:
                pass
            return

        username = None
        try:
            while self.running:
                msg = channel.recv_json()
                if msg is None:
                    break
                msg_type = msg.get('type')

                if msg_type == 'login':
                    username = msg.get('username')
                    avatar = msg.get('avatar', '')
                    sys_acct = msg.get('system_account') or {}

                    if not username:
                        self.send_error(channel, "err_username_required")
                        continue

                    with self.lock:
                        if username in self.banned_users:
                            self.send_error(channel, "err_banned")
                            continue
                        taken = any(c['username'] == username for c in self.clients.values())
                    if taken:
                        self.send_error(channel, "err_username_taken")
                        continue

                    if avatar:
                        try:
                            if len(base64.b64decode(avatar)) > 100 * 1024:
                                avatar = ''
                        except Exception:
                            avatar = ''

                    permissions = sys_acct.get('permissions', []) or []
                    tag = sys_acct.get('tag', '') or ''
                    color = sys_acct.get('color', '') or ''

                    with self.lock:
                        self.clients[channel] = {
                            'username': username, 'room_code': None,
                            'avatar': avatar, 'msg_timestamps': [],
                            'permissions': permissions,
                            'tag': tag,
                            'color': color,
                        }
                    self._internal_join_room(channel, 'public')
                    rooms_info = []
                    with self.lock:
                        for code, data_rm in self.rooms.items():
                            rooms_info.append({'name': data_rm['name'], 'code': code, 'is_protected': data_rm.get('is_protected', False)})
                    self._send(channel, {'type': 'room_list', 'rooms': rooms_info})
                    self.broadcast({'type': 'system', 'code': 'sys_user_joined_public',
                                    'params': {'user': username}}, 'public', exclude_channel=channel)

                elif msg_type == 'create_room':
                    room_name = msg.get('room_name')
                    room_pass = msg.get('room_password', '')
                    if not room_name:
                        self.send_error(channel, "err_room_name_required")
                        continue
                    new_code = str(uuid.uuid4())
                    is_protected = len(room_pass) > 0
                    with self.lock:
                        self.rooms[new_code] = {
                            'name': room_name, 'clients': set(),
                            'password': room_pass, 'is_protected': is_protected
                        }
                    self.broadcast_room_list()
                    if self.state_change_callback:
                        with self.lock:
                            rooms_copy = {c: {'name': d['name'], 'is_protected': d['is_protected']} for c, d in self.rooms.items()}
                        self.state_change_callback(rooms_copy)
                    self._send(channel, {'type': 'room_created_success', 'room_code': new_code, 'name': room_name})

                elif msg_type == 'join_room':
                    room_code = msg.get('room_code')
                    supplied_password = msg.get('password', '')
                    if not room_code:
                        continue
                    with self.lock:
                        if room_code not in self.rooms:
                            self.send_error(channel, "err_room_not_found")
                            continue
                        target_room = self.rooms[room_code]
                        if target_room['is_protected'] and target_room['password'] != supplied_password:
                            self.send_error(channel, "err_wrong_password")
                            continue
                    self._internal_join_room(channel, room_code)

                elif msg_type == 'send_message':
                    room_code = msg.get('room_code')
                    text = msg.get('message')
                    if not room_code or not text:
                        continue
                    if len(text) > MAX_MESSAGE_LENGTH:
                        self.send_error(channel, "err_message_too_long")
                        continue
                    if self._contains_forbidden(text):
                        self.send_error(channel, "err_message_blocked")
                        continue
                    if self._check_rate_limit(channel):
                        self.send_error(channel, "err_rate_limit")
                        continue
                    with self.lock:
                        if channel not in self.clients or self.clients[channel]['room_code'] != room_code:
                            continue
                        info = self.clients[channel]
                        sender = info['username']
                        avatar = info.get('avatar', '')
                        tag = info.get('tag', '')
                        color = info.get('color', '')
                        perms = info.get('permissions', [])
                        self.message_counter += 1
                        msg_id = f"m{self.message_counter}"
                    is_privileged = user_level(perms) >= 2  # admin or sudo
                    self.broadcast({
                        'type': 'message',
                        'room_code': room_code,
                        'msg_id': msg_id,
                        'sender': sender,
                        'text': text,
                        'avatar': avatar,
                        'tag': tag,
                        'color': color,
                        'is_privileged': is_privileged,
                    }, room_code)

                elif msg_type == 'set_avatar':
                    avatar = msg.get('avatar', '')
                    try:
                        if avatar and len(base64.b64decode(avatar)) > 100 * 1024:
                            avatar = ''
                    except Exception:
                        avatar = ''
                    with self.lock:
                        if channel in self.clients:
                            self.clients[channel]['avatar'] = avatar

                elif msg_type == 'delete_message':
                    room_code = msg.get('room_code')
                    msg_id = msg.get('msg_id')
                    with self.lock:
                        info = self.clients.get(channel)
                    if not info or user_level(info.get('permissions', [])) < 2:
                        self.send_error(channel, "err_no_permission")
                        continue
                    if not room_code or not msg_id:
                        continue
                    self.broadcast({
                        'type': 'message_deleted',
                        'room_code': room_code,
                        'msg_id': msg_id,
                    }, room_code)

                elif msg_type == 'ban_user':
                    target = msg.get('target')
                    with self.lock:
                        info = self.clients.get(channel)
                    if not info:
                        continue
                    requester_level = user_level(info.get('permissions', []))
                    if requester_level < 2:
                        self.send_error(channel, "err_no_permission")
                        continue
                    if not target or target == info['username']:
                        continue

                    target_channel = None
                    target_level = 0
                    with self.lock:
                        for ch, cinfo in self.clients.items():
                            if cinfo['username'] == target:
                                target_channel = ch
                                target_level = user_level(cinfo.get('permissions', []))
                                break
                        if target_level >= requester_level:
                            self.send_error(channel, "err_ban_denied")
                            continue
                        self.banned_users.add(target)

                    if target_channel:
                        try:
                            target_channel.send_json({'type': 'kicked', 'reason': 'banned'})
                        except Exception:
                            pass
                        target_channel.close()

                    self.broadcast_to_all({'type': 'user_banned', 'username': target})

                elif msg_type == 'leave_room':
                    with self.lock:
                        if channel in self.clients:
                            rc = self.clients[channel]['room_code']
                            if rc and rc in self.rooms:
                                self.rooms[rc]['clients'].discard(channel)
                            self.clients[channel]['room_code'] = None
                    self.broadcast_room_list()
                    self._send(channel, {'type': 'system', 'code': 'sys_left_room'})
        except Exception:
            pass
        finally:
            last_room = None
            with self.lock:
                if channel in self.clients:
                    username = self.clients[channel]['username']
                    last_room = self.clients[channel]['room_code']
                    if last_room and last_room in self.rooms:
                        self.rooms[last_room]['clients'].discard(channel)
                    del self.clients[channel]
            channel.close()
            if username:
                room_for_announce = last_room if last_room else 'public'
                self.broadcast({'type': 'system', 'code': 'sys_user_left',
                                'params': {'user': username}}, room_for_announce)
            self.broadcast_room_list()

    def _internal_join_room(self, channel, room_code):
        with self.lock:
            if channel not in self.clients or room_code not in self.rooms:
                return
            old_room = self.clients[channel]['room_code']
            if old_room and old_room in self.rooms:
                self.rooms[old_room]['clients'].discard(channel)
            self.rooms[room_code]['clients'].add(channel)
            self.clients[channel]['room_code'] = room_code
            room_name = self.rooms[room_code]['name']
        self._send(channel, {'type': 'system', 'code': 'sys_joined_room', 'params': {'room': room_name}})
        self._send(channel, {'type': 'join_success', 'room_code': room_code})

    def send_error(self, channel, code):
        self._send(channel, {'type': 'error', 'code': code})

    def start(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(10)
            self.server_sock.settimeout(1.0)
        except Exception:
            return
        while self.running:
            try:
                client_sock, addr = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                break
            threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
        try:
            self.server_sock.close()
        except Exception:
            pass

    def shutdown(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass


class ChatClient:
    def __init__(self, server_ip, port, username, avatar, system_account,
                 on_message, on_room_list, on_error, on_system,
                 on_state_update, on_state_sync, on_join_success,
                 on_message_deleted, on_user_banned, on_kicked):
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.avatar = avatar
        self.system_account = system_account
        self.sock = None
        self.channel = None
        self.running = True
        self._closed_deliberately = False
        self.on_message = on_message
        self.on_room_list = on_room_list
        self.on_error = on_error
        self.on_system = on_system
        self.on_state_update = on_state_update
        self.on_state_sync = on_state_sync
        self.on_join_success = on_join_success
        self.on_message_deleted = on_message_deleted
        self.on_user_banned = on_user_banned
        self.on_kicked = on_kicked

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.server_ip, self.port))
            self.channel = client_handshake(self.sock)
            if self.channel is None:
                self._safe_close_sock()
                return False
            self.sock.settimeout(None)

            payload = {'type': 'login', 'username': self.username, 'avatar': self.avatar}
            if self.system_account:
                payload['system_account'] = {
                    'username': self.system_account.get('username'),
                    'tag': self.system_account.get('tag', ''),
                    'color': self.system_account.get('color', ''),
                    'permissions': self.system_account.get('permissions', []),
                }
            self.send(payload)
            threading.Thread(target=self.receive, daemon=True).start()
            return True
        except Exception:
            self._safe_close_sock()
            return False

    def _safe_close_sock(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def receive(self):
        while self.running:
            try:
                msg = self.channel.recv_json()
            except Exception:
                break
            if msg is None:
                break
            msg_type = msg.get('type')
            try:
                if msg_type == 'message':
                    self.on_message(
                        msg.get('room_code'), msg.get('sender'), msg.get('text'),
                        msg.get('avatar', ''), msg.get('msg_id'),
                        msg.get('tag', ''), msg.get('color', ''),
                        msg.get('is_privileged', False))
                elif msg_type == 'room_list':
                    self.on_room_list(msg.get('rooms', []))
                elif msg_type == 'system':
                    self.on_system(msg.get('code', ''), msg.get('params', {}))
                elif msg_type == 'error':
                    self.on_error(msg.get('code', 'err_unknown'), msg.get('params', {}))
                elif msg_type == 'room_created_success':
                    self.send({'type': 'join_room', 'room_code': msg.get('room_code'), 'password': ''})
                elif msg_type == 'join_success':
                    self.on_join_success(msg.get('room_code'))
                elif msg_type == 'state_update':
                    self.on_state_update(msg.get('version', 0), msg.get('state', {}))
                elif msg_type == 'state_sync':
                    self.on_state_sync(msg.get('version', 0), msg.get('state', {}))
                elif msg_type == 'message_deleted':
                    self.on_message_deleted(msg.get('room_code'), msg.get('msg_id'))
                elif msg_type == 'user_banned':
                    self.on_user_banned(msg.get('username', ''))
                elif msg_type == 'kicked':
                    self.on_kicked(msg.get('reason', ''))
            except Exception:
                continue

        was_running = self.running
        self.running = False
        if was_running and not self._closed_deliberately:
            try:
                self.on_system('msg_connection_lost', {})
            except Exception:
                pass

    def send(self, msg_dict):
        if self.channel and self.running:
            try:
                self.channel.send_json(msg_dict)
            except Exception:
                pass

    def set_avatar(self, avatar_data):
        self.avatar = avatar_data
        self.send({'type': 'set_avatar', 'avatar': avatar_data})

    def close(self):
        self._closed_deliberately = True
        self.running = False
        if self.channel:
            self.channel.close()
        elif self.sock:
            self._safe_close_sock()


# ====================== THEME ======================

COLORS = {
    'bg_root':       '#f0f2f5',
    'bg_main':       '#ffffff',
    'bg_sidebar':    '#f7f8fa',
    'bg_header':     '#ffffff',
    'bg_card':       '#ffffff',
    'bg_input':      '#f0f2f5',
    'bg_hover':      '#e4e6eb',
    'bg_selected':   '#e7f3ff',
    'border':        '#e4e6eb',
    'border_soft':   '#dddfe2',
    'accent':        '#2563eb',
    'accent_hover':  '#1d4ed8',
    'accent_press':  '#1e40af',
    'accent_soft':   '#dbeafe',
    'text':          '#050505',
    'text_soft':     '#65676b',
    'text_muted':    '#8a8d91',
    'success':       '#31a24c',
    'warning':       '#f7b928',
    'danger':        '#dc2626',
    'danger_hover':  '#b91c1c',
    'bubble_own':    '#2563eb',
    'bubble_other':  '#f0f2f5',
    'bubble_own_tx': '#ffffff',
    'bubble_otr_tx': '#050505',
    'avatar_bg':     '#dbeafe',
    'avatar_tx':     '#2563eb',
}

FONT_FAMILY = "Tahoma"


def detect_font(root):
    global FONT_FAMILY
    try:
        families = set(tkfont.families(root))
        for f in ['Tahoma', 'Segoe UI', 'Arial', 'Helvetica', 'DejaVu Sans']:
            if f in families:
                FONT_FAMILY = f
                return
    except Exception:
        pass


def fnt(size, weight='normal'):
    return (FONT_FAMILY, size, weight)


def round_rect(canvas, x1, y1, x2, y2, r=14, **kwargs):
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [
        x1 + r, y1, x2 - r, y1, x2, y1,
        x2, y1 + r, x2, y2 - r, x2, y2,
        x2 - r, y2, x1 + r, y2, x1, y2,
        x1, y2 - r, x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(pts, smooth=True, **kwargs)


def contrast_text_color(hex_color):
    try:
        c = (hex_color or '#000000').lstrip('#')
        if len(c) == 3:
            c = ''.join([ch * 2 for ch in c])
        if len(c) != 6:
            return '#ffffff'
        r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        lum = 0.299 * r + 0.587 * g + 0.114 * b
        return '#000000' if lum > 150 else '#ffffff'
    except Exception:
        return '#ffffff'


def make_flat_button(parent, text, command, style='primary', font_size=10, **kwargs):
    if style == 'primary':
        bg, hover, fg = COLORS['accent'], COLORS['accent_hover'], '#ffffff'
    elif style == 'success':
        bg, hover, fg = COLORS['success'], '#2d9044', '#ffffff'
    elif style == 'danger':
        bg, hover, fg = COLORS['danger'], COLORS['danger_hover'], '#ffffff'
    elif style == 'ghost':
        bg, hover, fg = COLORS['bg_input'], COLORS['bg_hover'], COLORS['text']
    else:
        bg, hover, fg = COLORS['bg_input'], COLORS['bg_hover'], COLORS['text']

    btn = tk.Button(
        parent, text=text, command=command,
        font=fnt(font_size, 'bold'),
        bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
        relief='flat', bd=0, padx=14, pady=8, cursor='hand2',
        highlightthickness=0, **kwargs
    )
    btn.bind('<Enter>', lambda e: btn.config(bg=hover))
    btn.bind('<Leave>', lambda e: btn.config(bg=bg))
    return btn


# ====================== MESSAGE CANVAS ======================

class MessageCanvas(tk.Canvas):
    def __init__(self, parent, on_right_click=None, **kwargs):
        super().__init__(parent, bg=COLORS['bg_main'], highlightthickness=0, bd=0, **kwargs)
        self.messages = []
        self._img_refs = []
        self._avatar_cache = {}
        self.padding_x = 24
        self.padding_y = 16
        self.bubble_pad_x = 14
        self.bubble_pad_y = 9
        self.bubble_radius = 16
        self.avatar_size = 36
        self.avatar_gap = 10
        self.max_bubble_ratio = 0.62
        self._next_y = self.padding_y
        self._last_width = 0
        self.on_right_click = on_right_click

        self.bind('<Configure>', self._on_resize)
        self.bind('<MouseWheel>', self._on_wheel)
        self.bind('<Button-4>', lambda e: self.yview_scroll(-2, 'units'))
        self.bind('<Button-5>', lambda e: self.yview_scroll(2, 'units'))
        self.bind('<Button-3>', self._on_right_button)

    def _on_right_button(self, event):
        if self.on_right_click is None:
            return
        msg = self.get_msg_at(event.x, event.y)
        if msg is not None:
            try:
                self.on_right_click(msg, event.x_root, event.y_root)
            except Exception:
                pass

    def get_msg_at(self, x, y):
        try:
            items = self.find_overlapping(x - 1, y - 1, x + 1, y + 1)
            for item in items:
                tags = self.gettags(item)
                for t in tags:
                    if t.startswith('msg_'):
                        mid = t[4:]
                        for m in self.messages:
                            if str(m.get('msg_id')) == mid:
                                return m
        except Exception:
            pass
        return None

    def _on_wheel(self, e):
        delta = int(-e.delta / 120) if e.delta else 0
        if delta == 0:
            delta = -1 if e.delta > 0 else 1
        self.yview_scroll(delta, 'units')

    def _on_resize(self, e):
        if abs(e.width - self._last_width) > 8:
            self._last_width = e.width
            self.redraw()

    def clear(self):
        self.messages = []
        self._img_refs = []
        self.delete('all')
        self._next_y = self.padding_y
        self.config(scrollregion=(0, 0, self.winfo_width(), self.padding_y))

    def set_messages(self, messages):
        self.messages = list(messages)
        self.redraw()

    def add_message(self, entry):
        self.messages.append(entry)
        width = self.winfo_width() or 700
        max_bubble_w = max(180, int(width * self.max_bubble_ratio))
        self._next_y = self._draw_message(entry, self._next_y, max_bubble_w, width)
        self.config(scrollregion=(0, 0, width, self._next_y + self.padding_y))
        self.yview_moveto(1.0)

    def add_system(self, text):
        width = self.winfo_width() or 700
        y = self._next_y + 4
        self.create_text(width // 2, y + 8, text=text, fill=COLORS['text_muted'],
                         font=fnt(9, 'italic'), anchor='n')
        self._next_y = y + 26
        self.config(scrollregion=(0, 0, width, self._next_y + self.padding_y))
        self.yview_moveto(1.0)

    def redraw(self):
        self.delete('all')
        self._img_refs = []
        width = self.winfo_width()
        if width < 50:
            width = 700
        max_bubble_w = max(180, int(width * self.max_bubble_ratio))
        y = self.padding_y
        for msg in self.messages:
            y = self._draw_message(msg, y, max_bubble_w, width)
        self._next_y = y
        self.config(scrollregion=(0, 0, width, y + self.padding_y))
        self.yview_moveto(1.0)

    def _measure_text(self, text, max_width, font):
        tid = self.create_text(0, 0, text=text, font=font, anchor='nw', width=max_width)
        bbox = self.bbox(tid)
        self.delete(tid)
        if bbox is None:
            return max_width, 20
        return bbox[2] - bbox[0], bbox[3] - bbox[1]

    def _get_avatar_photo(self, b64):
        if not b64 or not HAS_PIL:
            return None
        if b64 in self._avatar_cache:
            return self._avatar_cache[b64]
        try:
            size = self.avatar_size
            img = Image.open(io.BytesIO(base64.b64decode(b64))).convert('RGBA')
            img = img.resize((size, size), Image.LANCZOS)
            mask = Image.new('L', (size, size), 0)
            d = ImageDraw.Draw(mask)
            d.ellipse((0, 0, size, size), fill=255)
            bg = Image.new('RGBA', (size, size), (0, 0, 0, 0))
            bg.paste(img, (0, 0), mask)
            photo = ImageTk.PhotoImage(bg)
            self._avatar_cache[b64] = photo
            return photo
        except Exception:
            return None

    def _draw_avatar(self, x, y, sender, b64):
        size = self.avatar_size
        photo = self._get_avatar_photo(b64)
        if photo:
            self.create_image(x + size / 2, y + size / 2, image=photo, anchor='center')
            self._img_refs.append(photo)
        else:
            self.create_oval(x, y, x + size, y + size,
                             fill=COLORS['avatar_bg'], outline='')
            initial = (sender or '?')[:1].upper()
            self.create_text(x + size / 2, y + size / 2, text=initial,
                             fill=COLORS['avatar_tx'], font=fnt(13, 'bold'))

    def _draw_name_with_tag(self, x, y, sender, tag, color, anchor='nw'):
        """Draw 'sender [TAG]' where sender is colored, tag is a pill."""
        name_font = fnt(9, 'bold')
        if color:
            name_color = color
        else:
            name_color = COLORS['text_soft']

        if not tag:
            self.create_text(x, y, text=sender, anchor=anchor,
                             fill=name_color, font=name_font)
            return

        # Draw name first
        tid = self.create_text(x, y, text=sender, anchor=anchor,
                               fill=name_color, font=name_font)
        bbox = self.bbox(tid)
        name_w = (bbox[2] - bbox[0]) if bbox else len(sender) * 7

        # Draw tag pill
        pill_x1 = x + name_w + 6
        pill_y1 = y
        tf = tkfont.Font(family=FONT_FAMILY, size=8, weight='bold')
        tag_w = tf.measure(tag)
        pill_w = tag_w + 12
        pill_h = 15

        bg_color = color or COLORS['accent_soft']
        round_rect(self, pill_x1, pill_y1, pill_x1 + pill_w, pill_y1 + pill_h,
                   r=7, fill=bg_color, outline='')
        self.create_text(pill_x1 + pill_w / 2, pill_y1 + pill_h / 2 + 1,
                         text=tag, fill=contrast_text_color(bg_color),
                         font=fnt(8, 'bold'))

    def _draw_message(self, msg, y, max_bubble_w, canvas_w):
        is_own = msg['own']
        sender = msg['sender'] or ''
        text = msg['text']
        avatar_b64 = msg.get('avatar', '')
        tag = msg.get('tag', '') or ''
        color = msg.get('color', '') or ''
        is_privileged = msg.get('is_privileged', False)
        msg_id = msg.get('msg_id', '')

        text_font = fnt(11, 'bold') if is_privileged else fnt(11)

        text_max_w = max_bubble_w - 2 * self.bubble_pad_x
        text_w, text_h = self._measure_text(text, text_max_w, text_font)
        bubble_w = min(max_bubble_w, text_w + 2 * self.bubble_pad_x)
        bubble_h = max(text_h + 2 * self.bubble_pad_y, self.avatar_size)

        av_size = self.avatar_size
        gap = self.avatar_gap
        px = self.padding_x
        show_header = (not is_own) or bool(tag)

        header_height = 18 if show_header else 0
        canvas_tag = f"msg_{msg_id}" if msg_id else ""

        if is_own:
            av_x = canvas_w - px - av_size
            av_y = y
            self._draw_avatar(av_x, av_y, sender, avatar_b64)

            bubble_x2 = av_x - gap
            bubble_x1 = bubble_x2 - bubble_w
            bubble_y1 = y + header_height
            bubble_y2 = bubble_y1 + bubble_h

            fill = COLORS['bubble_own']
            fg = COLORS['bubble_own_tx']

            if show_header:
                # Right-aligned header above bubble. Draw name+tag right-aligned.
                # Simplest: compute total width, place starting x.
                name_font = fnt(9, 'bold')
                temp = self.create_text(0, 0, text=sender, anchor='nw', font=name_font)
                b = self.bbox(temp)
                self.delete(temp)
                name_w = (b[2] - b[0]) if b else len(sender) * 7
                total_w = name_w
                if tag:
                    tf = tkfont.Font(family=FONT_FAMILY, size=8, weight='bold')
                    total_w += 6 + tf.measure(tag) + 12
                start_x = bubble_x2 - total_w
                if start_x < bubble_x1:
                    start_x = bubble_x1
                self._draw_name_with_tag(start_x, y, sender, tag, color)
        else:
            av_x = px
            av_y = y
            self._draw_avatar(av_x, av_y, sender, avatar_b64)

            bubble_x1 = av_x + av_size + gap
            bubble_x2 = bubble_x1 + bubble_w
            bubble_y1 = y + header_height
            bubble_y2 = bubble_y1 + bubble_h

            self._draw_name_with_tag(bubble_x1 + 2, y, sender, tag, color)

            fill = COLORS['bubble_other']
            fg = COLORS['bubble_otr_tx']

        # Draw bubble
        if canvas_tag:
            round_rect(self, bubble_x1, bubble_y1, bubble_x2, bubble_y2,
                       r=self.bubble_radius, fill=fill, outline='', tags=canvas_tag)
            self.create_text(bubble_x1 + self.bubble_pad_x,
                             bubble_y1 + self.bubble_pad_y,
                             text=text, anchor='nw', width=text_max_w,
                             fill=fg, font=text_font, tags=canvas_tag)
        else:
            round_rect(self, bubble_x1, bubble_y1, bubble_x2, bubble_y2,
                       r=self.bubble_radius, fill=fill, outline='')
            self.create_text(bubble_x1 + self.bubble_pad_x,
                             bubble_y1 + self.bubble_pad_y,
                             text=text, anchor='nw', width=text_max_w,
                             fill=fg, font=text_font)

        bottom = max(bubble_y2, av_y + av_size)
        return bottom + 12


# ====================== APP ======================

class KCHATApp:
    def __init__(self, root):
        self.root = root
        self.lang = load_saved_language()
        self.root.title("KCHAT")
        self.root.geometry("1000x680")
        self.root.minsize(820, 560)
        self.root.configure(bg=COLORS['bg_root'])
        self._closing = False

        self._set_icon()

        if not HAS_CRYPTO:
            tk.Label(self.root, text="pip install cryptography",
                     font=fnt(14, 'bold'), fg=COLORS['danger'],
                     bg=COLORS['bg_root']).pack(expand=True)
            return

        self.client = None
        self.discovery = None
        self.server = None
        self.username = None
        self.current_room = None
        self.rooms = {}
        self.room_codes = []
        self.running = True
        self.gui_queue = Queue()
        self.room_messages = {}
        self.avatar_data = ''
        self.system_account = None
        self._toast_ref = None

        self._configure_ttk_styles()
        self._build_login_view()
        self._build_chat_view()
        self._build_overlay()

        self.process_gui_queue()
        self.retranslate_ui()
        self.show_login()

    def _set_icon(self):
        try:
            block = tk.PhotoImage(width=32, height=32)
            block.put(COLORS['accent'], to=(0, 0, 32, 32))
            self.root.iconphoto(False, block)
            self._icon_ref = block
        except Exception:
            pass

    def _configure_ttk_styles(self):
        try:
            style = ttk.Style()
            style.theme_use('clam')
            style.configure(
                'Light.TCombobox',
                fieldbackground=COLORS['bg_card'],
                background=COLORS['bg_card'],
                foreground=COLORS['text'],
                arrowcolor=COLORS['text_soft'],
                bordercolor=COLORS['border_soft'],
                lightcolor=COLORS['border_soft'],
                darkcolor=COLORS['border_soft'],
                selectbackground=COLORS['accent'],
                selectforeground='#ffffff',
                padding=6,
            )
            style.map(
                'Light.TCombobox',
                fieldbackground=[('readonly', COLORS['bg_card'])],
                foreground=[('readonly', COLORS['text'])],
            )
        except Exception:
            pass

    # ---------- i18n ----------

    def t(self, key, **kwargs):
        return tr(self.lang, key, **kwargs)

    def set_language(self, lang_code):
        if lang_code not in STRINGS:
            return
        self.lang = lang_code
        save_language(lang_code)
        self.retranslate_ui()

    def retranslate_ui(self):
        if not hasattr(self, 'header_title_label'):
            return
        self.header_title_label.config(text=self.t('app_header_title'))
        self.login_title_label.config(text=self.t('login_title'))
        self.login_subtitle_label.config(text=self.t('login_subtitle'))
        self.username_label.config(text=self.t('username_label'))
        self.language_label.config(text=self.t('language_label'))
        self.login_button.config(text=self.t('login_button'))
        self.system_login_button.config(text=self.t('login_with_system_account'))
        self.rooms_panel_label.config(text=self.t('rooms_panel_title'))
        self.join_button.config(text=self.t('join_button'))
        self.create_room_button.config(text=self.t('create_room_button'))
        self.leave_button.config(text=self.t('leave_button'))
        if hasattr(self, 'send_button'):
            self.send_button.config(text=self.t('send_button'))
        if not self.client:
            self.status_label.config(text=self.t('status_offline'))
        self.empty_title.config(text=self.t('empty_chat_title'))
        self.empty_subtitle.config(text=self.t('empty_chat_subtitle'))
        if not self.rooms:
            self._show_empty_rooms_hint()

    # ---------- LOGIN VIEW ----------

    def _build_login_view(self):
        self.login_frame = tk.Frame(self.root, bg=COLORS['bg_root'])

        center = tk.Frame(self.login_frame, bg=COLORS['bg_root'])
        center.place(relx=0.5, rely=0.5, anchor='center')

        card = tk.Frame(center, bg=COLORS['bg_card'], padx=36, pady=32,
                        highlightbackground=COLORS['border'],
                        highlightthickness=1)
        card.pack()

        tk.Label(card, text="KCHAT", font=fnt(22, 'bold'),
                 fg=COLORS['accent'], bg=COLORS['bg_card']).pack(pady=(0, 2))

        self.login_title_label = tk.Label(card, text="", font=fnt(11),
                                          fg=COLORS['text'], bg=COLORS['bg_card'])
        self.login_title_label.pack(pady=(6, 2))

        self.login_subtitle_label = tk.Label(card, text="", font=fnt(9),
                                             fg=COLORS['text_soft'], bg=COLORS['bg_card'])
        self.login_subtitle_label.pack(pady=(0, 20))

        tk.Frame(card, bg=COLORS['border'], height=1).pack(fill=tk.X, pady=(0, 20))

        self.language_label = tk.Label(card, text="", font=fnt(9),
                                       fg=COLORS['text_soft'],
                                       bg=COLORS['bg_card'], anchor='w')
        self.language_label.pack(fill=tk.X, pady=(0, 4))
        self.language_var = tk.StringVar(value=LANGUAGE_NAMES.get(self.lang, self.lang))
        lang_values = [LANGUAGE_NAMES[code] for code in STRINGS.keys()]
        self.language_combo = ttk.Combobox(
            card, textvariable=self.language_var, values=lang_values,
            state='readonly', style='Light.TCombobox', font=fnt(10), width=28,
        )
        self.language_combo.pack(fill=tk.X, pady=(0, 14))
        self.language_combo.bind('<<ComboboxSelected>>', self._on_language_selected)

        self.username_label = tk.Label(card, text="", font=fnt(9),
                                       fg=COLORS['text_soft'],
                                       bg=COLORS['bg_card'], anchor='w')
        self.username_label.pack(fill=tk.X, pady=(0, 4))

        self.name_var = tk.StringVar()
        self.name_entry = tk.Entry(
            card, textvariable=self.name_var,
            font=fnt(11), bg=COLORS['bg_card'], fg=COLORS['text'],
            insertbackground=COLORS['text'], relief='solid', bd=1,
            highlightthickness=0,
        )
        self.name_entry.pack(fill=tk.X, ipady=8)
        self.name_entry.bind('<Return>', lambda e: self.do_login())

        self.login_button = make_flat_button(
            card, text="", command=self.do_login, style='primary', font_size=11)
        self.login_button.pack(fill=tk.X, pady=(20, 8), ipady=4)

        self.system_login_button = make_flat_button(
            card, text="", command=self.show_system_login, style='ghost', font_size=10)
        self.system_login_button.pack(fill=tk.X, ipady=2)

    def _on_language_selected(self, event=None):
        selected_name = self.language_var.get()
        for code, name in LANGUAGE_NAMES.items():
            if name == selected_name:
                self.set_language(code)
                break

    def show_system_login(self):
        accounts = load_system_accounts()
        if not accounts:
            self.show_toast(self.t('err_system_account_missing'), is_error=True)
            return
        user_var = tk.StringVar()
        pw_var = tk.StringVar()

        def do_sys_login():
            u = user_var.get().strip()
            p = pw_var.get()
            if not u or not p:
                return
            acct = verify_system_account(u, p)
            if acct is None:
                self.show_toast(self.t('err_system_account_invalid'), is_error=True)
                return
            self.hide_overlay()
            self.system_account = acct
            self.name_var.set(u)
            self._start_login(u)

        self.show_overlay(
            self.t('dialog_system_login_title'),
            [(self.t('dialog_system_username_label'), user_var, False),
             (self.t('dialog_system_password_label'), pw_var, True)],
            self.t('dialog_system_login_confirm'),
            do_sys_login,
        )

    # ---------- CHAT VIEW ----------

    def _build_chat_view(self):
        self.chat_frame = tk.Frame(self.root, bg=COLORS['bg_main'])

        header = tk.Frame(self.chat_frame, bg=COLORS['bg_header'], height=56)
        header.pack(side=tk.TOP, fill=tk.X)
        header.pack_propagate(False)
        tk.Frame(header, bg=COLORS['border'], height=1).pack(side=tk.BOTTOM, fill=tk.X)

        left = tk.Frame(header, bg=COLORS['bg_header'])
        left.pack(side=tk.LEFT, fill=tk.Y, padx=18)

        self.header_title_label = tk.Label(left, text="KCHAT", font=fnt(14, 'bold'),
                                            fg=COLORS['accent'], bg=COLORS['bg_header'])
        self.header_title_label.pack(side=tk.LEFT, pady=14)

        right = tk.Frame(header, bg=COLORS['bg_header'])
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=18)

        self.status_dot = tk.Label(right, text="●", font=fnt(12),
                                    fg=COLORS['text_muted'], bg=COLORS['bg_header'])
        self.status_dot.pack(side=tk.LEFT, pady=16, padx=(0, 4))
        self.status_label = tk.Label(right, text="", font=fnt(9),
                                     fg=COLORS['text_soft'], bg=COLORS['bg_header'])
        self.status_label.pack(side=tk.LEFT, pady=16, padx=(0, 14))

        self.avatar_button = tk.Button(
            right, text="🖼", font=(FONT_FAMILY, 12),
            bg=COLORS['bg_input'], fg=COLORS['text_soft'],
            activebackground=COLORS['bg_hover'], activeforeground=COLORS['text'],
            relief='flat', bd=0, padx=10, pady=4, cursor='hand2',
            command=self.change_avatar)
        self.avatar_button.pack(side=tk.LEFT, pady=10)

        body = tk.Frame(self.chat_frame, bg=COLORS['bg_main'])
        body.pack(fill=tk.BOTH, expand=True)

        sidebar = tk.Frame(body, bg=COLORS['bg_sidebar'], width=260)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        tk.Frame(sidebar, bg=COLORS['border'], width=1).pack(side=tk.RIGHT, fill=tk.Y)

        side_inner = tk.Frame(sidebar, bg=COLORS['bg_sidebar'])
        side_inner.pack(fill=tk.BOTH, expand=True, padx=14, pady=14)

        self.rooms_panel_label = tk.Label(side_inner, text="", font=fnt(10, 'bold'),
                                          fg=COLORS['text'],
                                          bg=COLORS['bg_sidebar'], anchor='w')
        self.rooms_panel_label.pack(fill=tk.X, pady=(0, 8))

        list_wrap = tk.Frame(side_inner, bg=COLORS['bg_sidebar'])
        list_wrap.pack(fill=tk.BOTH, expand=True)

        self.room_listbox = tk.Listbox(
            list_wrap,
            bg=COLORS['bg_card'], fg=COLORS['text'],
            selectbackground=COLORS['bg_selected'], selectforeground=COLORS['text'],
            font=fnt(10), bd=0, highlightthickness=1,
            highlightbackground=COLORS['border'], highlightcolor=COLORS['border'],
            activestyle='none', relief='flat',
        )
        self.room_listbox.pack(fill=tk.BOTH, expand=True)
        self.room_listbox.bind('<Double-Button-1>', lambda e: self.join_selected_room())

        self.empty_rooms_label = tk.Label(
            list_wrap, text=self.t('empty_rooms'),
            font=fnt(9, 'italic'), fg=COLORS['text_muted'],
            bg=COLORS['bg_sidebar'], anchor='w',
        )

        actions = tk.Frame(side_inner, bg=COLORS['bg_sidebar'])
        actions.pack(fill=tk.X, pady=(12, 0))

        self.join_button = make_flat_button(actions, text="", command=self.join_selected_room,
                                            style='primary', font_size=10)
        self.join_button.pack(fill=tk.X, pady=(0, 6))

        row2 = tk.Frame(actions, bg=COLORS['bg_sidebar'])
        row2.pack(fill=tk.X)
        self.create_room_button = make_flat_button(row2, text="", command=self.create_room,
                                                   style='ghost', font_size=9)
        self.create_room_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.leave_button = make_flat_button(row2, text="", command=self.leave_room,
                                             style='ghost', font_size=9)
        self.leave_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))

        chat_area = tk.Frame(body, bg=COLORS['bg_main'])
        chat_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.empty_state = tk.Frame(chat_area, bg=COLORS['bg_main'])
        self.empty_state.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(self.empty_state, text="💬", font=(FONT_FAMILY, 40),
                 fg=COLORS['text_muted'], bg=COLORS['bg_main']).pack()
        self.empty_title = tk.Label(self.empty_state, text="", font=fnt(12, 'bold'),
                                    fg=COLORS['text_soft'], bg=COLORS['bg_main'])
        self.empty_title.pack(pady=(10, 4))
        self.empty_subtitle = tk.Label(self.empty_state, text="", font=fnt(9),
                                       fg=COLORS['text_muted'], bg=COLORS['bg_main'])
        self.empty_subtitle.pack()

        self.messages_wrap = tk.Frame(chat_area, bg=COLORS['bg_main'])
        self.message_canvas = MessageCanvas(self.messages_wrap,
                                             on_right_click=self._on_message_right_click)
        self.message_canvas.pack(fill=tk.BOTH, expand=True)

        self.input_wrap = tk.Frame(chat_area, bg=COLORS['bg_main'])
        tk.Frame(self.input_wrap, bg=COLORS['border'], height=1).pack(side=tk.TOP, fill=tk.X)
        input_inner = tk.Frame(self.input_wrap, bg=COLORS['bg_main'])
        input_inner.pack(fill=tk.X, padx=16, pady=12)

        self.msg_entry = tk.Entry(
            input_inner, font=fnt(11), bg=COLORS['bg_input'],
            fg=COLORS['text'], insertbackground=COLORS['text'],
            relief='flat', bd=0,
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=10, padx=(4, 8))
        self.msg_entry.bind('<Return>', self.send_message)

        self.send_button = make_flat_button(input_inner, text="", command=self.send_message,
                                            style='primary', font_size=10)
        self.send_button.pack(side=tk.RIGHT)

        self.messages_wrap.pack_forget()
        self.input_wrap.pack_forget()
        self.empty_state.place(relx=0.5, rely=0.5, anchor='center')

    def _show_empty_rooms_hint(self):
        try:
            self.room_listbox.pack_forget()
            self.empty_rooms_label.pack(fill=tk.X)
        except Exception:
            pass

    def _hide_empty_rooms_hint(self):
        try:
            self.empty_rooms_label.pack_forget()
            self.room_listbox.pack(fill=tk.BOTH, expand=True)
        except Exception:
            pass

    def _build_overlay(self):
        self.overlay = tk.Frame(self.root, bg=COLORS['bg_card'],
                                highlightbackground=COLORS['border_soft'],
                                highlightthickness=1)

    def show_overlay(self, title, fields, confirm_text, confirm_callback):
        for w in self.overlay.winfo_children():
            w.destroy()
        self.overlay.config(bg=COLORS['bg_card'], padx=26, pady=22)
        self.overlay.place(relx=0.5, rely=0.5, anchor='center')

        tk.Label(self.overlay, text=title, font=fnt(12, 'bold'),
                 fg=COLORS['text'], bg=COLORS['bg_card']).pack(pady=(0, 14))

        for label, var, is_password in fields:
            f = tk.Frame(self.overlay, bg=COLORS['bg_card'])
            f.pack(fill=tk.X, pady=(0, 10))
            tk.Label(f, text=label, font=fnt(9), fg=COLORS['text_soft'],
                     bg=COLORS['bg_card'], anchor='w').pack(fill=tk.X, pady=(0, 4))
            entry = tk.Entry(f, textvariable=var, font=fnt(10),
                             bg=COLORS['bg_input'], fg=COLORS['text'],
                             insertbackground=COLORS['text'], relief='solid', bd=1,
                             show="•" if is_password else "")
            entry.pack(fill=tk.X, ipady=6)
            entry.bind('<Return>', lambda e: confirm_callback())

        btn_frame = tk.Frame(self.overlay, bg=COLORS['bg_card'])
        btn_frame.pack(pady=(14, 0), fill=tk.X)
        make_flat_button(btn_frame, self.t('dialog_cancel'),
                         self.hide_overlay, style='ghost', font_size=10).pack(side=tk.LEFT)
        make_flat_button(btn_frame, confirm_text,
                         confirm_callback, style='primary', font_size=10).pack(side=tk.RIGHT)

    def hide_overlay(self):
        self.overlay.place_forget()

    def show_toast(self, message, duration=3000, is_error=False):
        if self._toast_ref is not None:
            try:
                if self._toast_ref.winfo_exists():
                    self._toast_ref.destroy()
            except Exception:
                pass
            self._toast_ref = None
        bg = COLORS['danger'] if is_error else '#323232'
        toast = tk.Frame(self.root, bg=bg)
        toast.place(relx=0.5, y=76, anchor='n')
        tk.Label(toast, text=message, fg='#ffffff', bg=bg,
                 font=fnt(10), padx=16, pady=10).pack()
        self._toast_ref = toast

        def dismiss(t=toast):
            try:
                if t.winfo_exists():
                    t.destroy()
            except Exception:
                pass
            if self._toast_ref is t:
                self._toast_ref = None
        self.root.after(duration, dismiss)

    def show_login(self):
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.chat_frame.pack_forget()

    def show_chat(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

    def set_status_key(self, key, online=True):
        self.status_label.config(text=self.t(key))
        if key == "status_offline":
            color = COLORS['text_muted']
        elif online:
            color = COLORS['success']
        else:
            color = COLORS['warning']
        try:
            self.status_dot.config(fg=color)
        except Exception:
            pass

    # ---------- ROOM LIST ----------

    def on_room_list(self, rooms):
        def update():
            self.rooms = {r['code']: r['name'] for r in rooms}
            self.room_codes = [r['code'] for r in rooms]
            self.room_listbox.delete(0, tk.END)
            if not rooms:
                self._show_empty_rooms_hint()
                return
            self._hide_empty_rooms_hint()
            for r in rooms:
                prefix = "🔒  " if r.get('is_protected') else "🌐  "
                self.room_listbox.insert(tk.END, f"{prefix}{r['name']}")
        self.queue_gui(update)

    def join_selected_room(self):
        if not self.room_listbox.curselection():
            return
        idx = self.room_listbox.curselection()[0]
        if idx >= len(self.room_codes):
            return
        code = self.room_codes[idx]
        is_protected = "🔒" in self.room_listbox.get(idx)
        if is_protected:
            pwd_var = tk.StringVar()
            self.show_overlay(
                self.t('dialog_protected_title'),
                [(self.t('dialog_enter_password_label'), pwd_var, True)],
                self.t('dialog_join_confirm'),
                lambda: self._send_join_req(code, pwd_var.get()),
            )
        else:
            self._send_join_req(code, "")

    def _send_join_req(self, code, password):
        self.hide_overlay()
        if self.client:
            self.client.send({'type': 'join_room', 'room_code': code, 'password': password})

    def on_join_success(self, room_code):
        self.queue_gui(lambda: self.switch_chat_room(room_code))

    def create_room(self):
        name_var = tk.StringVar()
        pass_var = tk.StringVar()
        self.show_overlay(
            self.t('dialog_create_room_title'),
            [(self.t('dialog_room_name_label'), name_var, False),
             (self.t('dialog_room_password_label'), pass_var, True)],
            self.t('dialog_create_confirm'),
            lambda: self._create_room_process(name_var.get(), pass_var.get()),
        )

    def _create_room_process(self, name, password):
        if not name:
            return
        self.hide_overlay()
        if self.client:
            self.client.send({'type': 'create_room', 'room_name': name, 'room_password': password})

    # ---------- CHAT AREA ----------

    def switch_chat_room(self, room_code):
        self.current_room = room_code
        try:
            self.empty_state.place_forget()
        except Exception:
            pass
        self.messages_wrap.pack(fill=tk.BOTH, expand=True)
        self.input_wrap.pack(fill=tk.X, side=tk.BOTTOM)
        history = self.room_messages.get(room_code, [])
        self.message_canvas.clear()
        self.message_canvas.set_messages(history)
        try:
            self.msg_entry.focus_set()
        except Exception:
            pass

    def _insert_message(self, entry):
        self.message_canvas.add_message(entry)

    def send_message(self, event=None):
        if not self.client or not self.current_room:
            return
        text = self.msg_entry.get().strip()
        if not text:
            return
        self.client.send({'type': 'send_message', 'room_code': self.current_room, 'message': text})
        self.msg_entry.delete(0, tk.END)

    def on_message(self, room_code, sender, text, avatar, msg_id=None,
                   tag='', color='', is_privileged=False):
        if room_code not in self.room_messages:
            self.room_messages[room_code] = []
        own = (sender == self.username)
        history = self.room_messages[room_code]
        entry = {
            'sender': sender, 'text': text, 'own': own, 'avatar': avatar,
            'msg_id': msg_id, 'tag': tag, 'color': color,
            'is_privileged': is_privileged,
        }
        if not history or history[-1] != entry:
            history.append(entry)
        if room_code == self.current_room:
            self.queue_gui(lambda e=entry: self._insert_message(e))

    def on_message_deleted(self, room_code, msg_id):
        history = self.room_messages.get(room_code, [])
        new_history = [m for m in history if str(m.get('msg_id')) != str(msg_id)]
        self.room_messages[room_code] = new_history
        if room_code == self.current_room:
            self.queue_gui(lambda h=new_history: self.message_canvas.set_messages(h))

    def on_user_banned(self, username):
        text = self.t('sys_user_banned', user=username)

        def update():
            if self.current_room:
                self.message_canvas.add_system(text)
            else:
                self.show_toast(text, 2500, is_error=True)
        self.queue_gui(update)

    def on_kicked(self, reason):
        self.queue_gui(lambda: self._handle_kicked())

    def _handle_kicked(self):
        self.show_toast(self.t('sys_you_were_banned'), 5000, is_error=True)
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
        self.system_account = None
        self.username = None
        self.current_room = None
        self.room_messages = {}
        self.message_canvas.clear()
        self.messages_wrap.pack_forget()
        self.input_wrap.pack_forget()
        self.empty_state.place(relx=0.5, rely=0.5, anchor='center')
        self.show_login()

    def on_system(self, code, params):
        text = self.t(code, **(params or {})) if code else ''

        def update():
            if self.current_room:
                self.message_canvas.add_system(text)
            else:
                self.show_toast(text, 2200, is_error=False)
        self.queue_gui(update)

    def leave_room(self):
        if not self.client or not self.current_room:
            return
        self.client.send({'type': 'leave_room'})
        self.current_room = None
        self.message_canvas.clear()
        self.messages_wrap.pack_forget()
        self.input_wrap.pack_forget()
        self.empty_state.place(relx=0.5, rely=0.5, anchor='center')

    def on_state_update(self, version, state):
        if self.discovery:
            self.discovery.receive_state_update(version, state)

    def on_state_sync(self, version, state):
        if self.discovery:
            self.discovery.receive_state_update(version, state)

    def on_error(self, code, params=None):
        text = self.t(code, **(params or {})) if code else self.t('err_unknown')
        self.queue_gui(lambda: self.show_toast(text, 3000, is_error=True))

    # ---------- CONTEXT MENU ----------

    def _on_message_right_click(self, msg, x_root, y_root):
        if not self.system_account or not self.client:
            return
        perms = self.system_account.get('permissions', [])
        if user_level(perms) < 2:
            return
        if msg.get('own'):
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=self.t('ctx_delete_message'),
                         command=lambda m=msg: self._do_delete_message(m))
        menu.add_command(label=self.t('ctx_ban_user'),
                         command=lambda m=msg: self._do_ban_user(m))
        try:
            menu.tk_popup(x_root, y_root)
        except Exception:
            pass
        finally:
            try:
                menu.grab_release()
            except Exception:
                pass

    def _do_delete_message(self, msg):
        if not self.client or not self.current_room:
            return
        msg_id = msg.get('msg_id')
        if not msg_id:
            return
        self.client.send({
            'type': 'delete_message',
            'room_code': self.current_room,
            'msg_id': msg_id,
        })

    def _do_ban_user(self, msg):
        if not self.client:
            return
        target = msg.get('sender')
        if not target:
            return
        self.client.send({
            'type': 'ban_user',
            'target': target,
        })

    # ---------- NETWORK HOOKS ----------

    def do_login(self):
        name = self.name_var.get().strip()
        if not name:
            self.show_toast(self.t('err_username_required'), is_error=True)
            return
        self._start_login(name)

    def _start_login(self, name):
        self.username = name
        self.show_chat()
        self.discovery = DiscoveryManager(
            on_host_elected=self.become_host,
            on_client_connect=self.connect_to_host,
            on_status_update=lambda key: self.queue_gui(lambda: self.set_status_key(key, online=False)),
        )
        threading.Thread(target=self.discovery.start, daemon=True).start()

    def become_host(self):
        self.queue_gui(lambda: self.set_status_key("status_host", online=True))
        rooms = self.discovery.get_state()
        server_ready = threading.Event()

        def run_server():
            self.server = ChatServer(initial_state=rooms,
                                     state_change_callback=self.discovery.on_state_changed)
            self.discovery.server = self.server
            server_ready.set()
            self.server.start()

        threading.Thread(target=run_server, daemon=True).start()

        def connect_when_ready():
            server_ready.wait(timeout=2.0)
            for _ in range(20):
                if self.connect_to_host('127.0.0.1', 5000):
                    return
                time.sleep(0.1)
        threading.Thread(target=connect_when_ready, daemon=True).start()

    def connect_to_host(self, host_ip, port):
        if self.client:
            self.client.close()
        client = ChatClient(
            host_ip, port, self.username, self.avatar_data, self.system_account,
            self.on_message, self.on_room_list, self.on_error,
            self.on_system, self.on_state_update, self.on_state_sync,
            self.on_join_success, self.on_message_deleted,
            self.on_user_banned, self.on_kicked,
        )
        if client.connect():
            self.client = client
            self.queue_gui(lambda: self.set_status_key("status_connected", online=True))
            return True
        return False

    def change_avatar(self):
        if not self.client:
            return
        filename = filedialog.askopenfilename(
            title=self.t('username_label'),
            filetypes=(("Image files", "*.png *.jpg *.jpeg"),),
        )
        if not filename or not HAS_PIL:
            return
        try:
            img = Image.open(filename)
            img.thumbnail((100, 100))
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            self.avatar_data = base64.b64encode(buf.getvalue()).decode('utf-8')
            self.client.set_avatar(self.avatar_data)
            self.show_toast(self.t('toast_avatar_updated'))
        except Exception:
            pass

    # ---------- GUI QUEUE ----------

    def queue_gui(self, func):
        self.gui_queue.put(func)

    def process_gui_queue(self):
        if self._closing:
            return
        try:
            while True:
                func = self.gui_queue.get_nowait()
                try:
                    func()
                except Exception:
                    pass
        except Empty:
            pass
        if self.running and not self._closing:
            self.root.after(80, self.process_gui_queue)

    def on_closing(self):
        if self._closing:
            return
        self._closing = True
        self.running = False
        try:
            if self.discovery:
                self.discovery.shutdown()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        try:
            if self.server:
                self.server.shutdown()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass


def main():
    args = sys.argv[1:]
    if args:
        cmd = args[0].lower()
        if cmd == "create":
            cli_create_account()
            return
        if cmd == "list":
            cli_list_accounts()
            return
        if cmd == "delete":
            cli_delete_account()
            return
        if cmd in ("help", "-h", "--help"):
            print("KCHAT")
            print("Usage:")
            print("  python kchat.py                    Launch the GUI")
            print("  python kchat.py create             Create a system account")
            print("  python kchat.py list               List system accounts")
            print("  python kchat.py delete             Delete a system account")
            print()
            print(f"  Encrypted account store: {ACCOUNTS_PATH}")
            return

    root = tk.Tk()
    detect_font(root)
    app = KCHATApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
