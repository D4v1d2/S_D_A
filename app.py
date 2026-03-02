from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import jwt
import datetime
from functools import wraps
from config import config as Config

app = Flask(__name__)



def get_db_connection():
    conn = sqlite3.connect("usuarios.db")
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# DECORADOR PARA PROTEGER RUTAS
# =========================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "Authorization" in request.headers:
            parts = request.headers["Authorization"].split(" ")
            if len(parts) == 2 and parts[0] == "Bearer":
                token = parts[1]

        if not token:
            return jsonify({"error": "Token requerido"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401

        return f(*args, **kwargs)

    return decorated


@app.route("/registro", methods=["POST"])
def registro():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")

    # Validación básica corregida
    if not email or not password:
        return jsonify({"error": "Credenciales Invalidas"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password debe tener mínimo 8 caracteres"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario_existente = cursor.fetchone()

    if usuario_existente:
        conn.close()
        return jsonify({"error": "El usuario ya existe"}), 409

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute(
        "INSERT INTO usuarios (email, password, role) VALUES (?, ?, ?)",
        (email, password_hash, "user")
    )

    conn.commit()
    conn.close()

    return jsonify({"mensaje": "Usuario Registrado"}), 201


@app.route("/recuperacion", methods=["POST"])
def recuperacion():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    new_password = data.get("password")

    if not email or not new_password:
        return jsonify({"error": "Email y password son obligatorios"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "Password invalido"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if not usuario:
            return jsonify({"error": "Usuario no encontrado"}), 404

        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        cursor.execute(
            "UPDATE usuarios SET password = ? WHERE email = ?",
            (hashed, email)
        )

        conn.commit()

        return jsonify({"message": "Contraseña actualizada correctamente"}), 200

    except sqlite3.Error:
        conn.rollback()
        return jsonify({"error": "Error del servidor"}), 500

    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email y password son obligatorios"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario = cursor.fetchone()
    conn.close()

    if not usuario:
        return jsonify({"error": "Credenciales Invalidas"}), 401

    stored_password = usuario["password"]

    if isinstance(stored_password, str):
        stored_password = stored_password.encode("utf-8")

    if bcrypt.checkpw(password.encode("utf-8"), stored_password):

        payload = {
            "sub": usuario["id"],
            "email": usuario["email"],
            "role": usuario["role"],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=0.5),
            "iat": datetime.datetime.now(datetime.timezone.utc),
        }

        encoded_jwt = jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALGORITHM)

        return jsonify({
            "message": "Login exitoso",
            "role": usuario["role"],
            "token": encoded_jwt
        }), 200

    return jsonify({"error": "Credenciales Invalidas"}), 401


# =========================
# RUTA PROTEGIDA 
# =========================
@app.route("/perfil", methods=["GET"])
@token_required
def perfil():
    return jsonify({
        "message": "Acceso concedido",
        "usuario": request.user
    }), 200


if __name__ == "__main__":
    app.run(debug=True)