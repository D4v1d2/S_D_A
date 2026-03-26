from flask import Flask, request, jsonify, g
import sqlite3
import bcrypt
import jwt
import datetime
import logging
import logging.config
import os
from functools import wraps
from config import config as Config

app = Flask(__name__)


def configure_logging():
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_file = os.getenv("LOG_FILE", os.path.join("logs", "api_registro.log"))
    log_directory = os.path.dirname(log_file)

    if log_directory:
        os.makedirs(log_directory, exist_ok=True)

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "standard",
                    "level": level,
                },
                "file": {
                    "class": "logging.FileHandler",
                    "formatter": "standard",
                    "level": level,
                    "filename": log_file,
                    "encoding": "utf-8",
                }
            },
            "loggers": {
                "api_registro": {
                    "handlers": ["console", "file"],
                    "level": level,
                    "propagate": False,
                },
                "api_registro.auth": {"level": level, "propagate": True},
                "api_registro.db": {"level": level, "propagate": True},
                "api_registro.routes": {"level": level, "propagate": True},
            },
        }
    )


configure_logging()
logger = logging.getLogger("api_registro")
auth_logger = logging.getLogger("api_registro.auth")
db_logger = logging.getLogger("api_registro.db")
routes_logger = logging.getLogger("api_registro.routes")

def get_db_connection():
    db_logger.debug("Abriendo conexión a SQLite")
    conn = sqlite3.connect("usuarios.db")
    conn.row_factory = sqlite3.Row
    return conn

# =========================
# DECORADOR PARA PROTEGER RUTAS (ACTUALIZADO)
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
            data = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])
            g.user = data
        except jwt.ExpiredSignatureError:
            auth_logger.warning("Token expirado")
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError as e:
            auth_logger.warning("Token inválido: %s", e)
            return jsonify({"error": "Token inválido"}), 401

        return f(*args, **kwargs)

    return decorated


@app.route("/registro", methods=["POST"])
def registro():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")

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
        routes_logger.info("Intento de registro con email existente: %s", email)
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
        db_logger.exception("Error SQLite durante recuperación de contraseña")
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
            "sub": str(usuario["id"]),
            "email": usuario["email"],
            "role": usuario["role"],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
            "iat": datetime.datetime.now(datetime.timezone.utc),
        }

        encoded_jwt = jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
        auth_logger.info("Login exitoso para usuario: %s", email)

        return jsonify({
            "message": "Login exitoso",
            "role": usuario["role"],
            "token": encoded_jwt
        }), 200

    return jsonify({"error": "Credenciales Invalidas"}), 401


# =========================
# RUTA: CREAR RESERVA (CORREGIDA)
# =========================
@app.route("/crear_reserva", methods=["POST"])
@token_required
def crear_reserva():
    data = request.get_json(silent=True) or {}
    
    fecha = data.get("fecha")
    detalle = data.get("detalle")
    
    if not fecha or not detalle:
        return jsonify({"error": "Fecha y detalle son obligatorios"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Los nombres de columnas deben ser idénticos a los de tu imagen
        cursor.execute(
            "INSERT INTO reservas (usuario_id, fecha, detalle) VALUES (?, ?, ?)",
            (g.user["sub"], fecha, detalle)
        )
        conn.commit()
        return jsonify({"message": "Reserva creada", "id": cursor.lastrowid}), 201
    except sqlite3.Error as e:
        conn.rollback()
        db_logger.exception("Error SQLite al crear reserva: %s", e)
        return jsonify({"error": "Error interno en la base de datos"}), 500
    finally:
        conn.close()

# =========================
# RUTA: PUBLICAR ARTÍCULO (CORREGIDA)
# =========================
@app.route("/publicar_articulo", methods=["POST"])
@token_required
def publicar_articulo():
    data = request.get_json(silent=True) or {}
    
    titulo = data.get("titulo", "").strip()
    contenido = data.get("contenido", "").strip() # Cambiado de 'descripcion' a 'contenido'
    
    if not titulo or not contenido:
        return jsonify({"error": "Título y contenido son obligatorios"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO articulos (autor_id, titulo, contenido) VALUES (?, ?, ?)",
            (g.user["sub"], titulo, contenido)
        )
        conn.commit()
        return jsonify({"message": "Artículo publicado", "id": cursor.lastrowid}), 201
    except sqlite3.Error as e:
        conn.rollback()
        db_logger.exception("Error SQLite al publicar artículo: %s", e)
        return jsonify({"error": "Error al publicar artículo"}), 500
    finally:
        conn.close()


@app.route("/comprar", methods=["POST"])
@token_required
def comprar():
    data = request.get_json(silent=True) or {}
    
    articulo_id = data.get("articulo_id")
    cantidad = data.get("cantidad")
    
    # Validación de datos
    if not articulo_id or not cantidad:
        return jsonify({"error": "ID de artículo y cantidad son obligatorios"}), 400
    
    # Asegurarnos de que la cantidad sea un número
    try:
        cantidad = float(cantidad)
        if cantidad <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "La cantidad debe ser un número positivo"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Insertamos usando g.user["sub"] que ya es un string (corregido antes)
        cursor.execute(
            "INSERT INTO compras (usuario_id, articulo_id, cantidad) VALUES (?, ?, ?)",
            (g.user["sub"], articulo_id, cantidad)
        )
        conn.commit()
        return jsonify({
            "message": "Compra realizada con éxito", 
            "id": cursor.lastrowid
        }), 201
    except sqlite3.Error as e:
        conn.rollback()
        db_logger.exception("Error SQLite en compra: %s", e)
        return jsonify({"error": "No se pudo procesar la compra en la base de datos"}), 500
    finally:
        conn.close()



# =========================
# RUTA PROTEGIDA 
# =========================
@app.route("/perfil", methods=["GET"])
@token_required
def perfil():
    # Actualizado a g.user
    return jsonify({
        "message": "Acceso concedido",
        "usuario": g.user
    }), 200


if __name__ == "__main__":
    logger.info("Iniciando API en modo debug")
    app.run(debug=True)
