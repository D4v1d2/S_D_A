from flask import Flask, request, jsonify
import sqlite3
import bcrypt

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect("usuarios.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/registro", methods=["POST"])
def registro():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    # Validación básica
    if not email or not password or len(password) <= 8 or len(password) >= 10:
        return jsonify({"error": "Credenciales Invalidas"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verificar duplicados
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario_existente = cursor.fetchone()

    if usuario_existente:
        conn.close()
        return jsonify({"error": "El usuario ya existe"}), 409

    # Hash de contraseña
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Guardar usuario
    cursor.execute(
        "INSERT INTO usuarios (email, password) VALUES (?, ?)",
        (email, password_hash)
    )

    conn.commit()
    conn.close()

    return jsonify({"mensaje": "Usuario Registrado"}), 201


if __name__ == "__main__":
    app.run(debug=True)
