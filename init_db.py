import sqlite3

def init_db():
    conexion = sqlite3.connect("usuarios.db")
    cursor = conexion.cursor()

    # 1. Habilitar soporte de llaves foráneas en SQLite
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute("DROP TABLE IF EXISTS compras")
    cursor.execute("DROP TABLE IF EXISTS reservas")
    cursor.execute("DROP TABLE IF EXISTS articulos")

    # 2. Tabla de Usuarios (ya la tenías, agregué un campo nombre opcional)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'cliente'
    )
    """)

    # 3. Tabla de Reservas (Relacionada con usuarios)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reservas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fecha TEXT NOT NULL,
        detalle TEXT,
        usuario_id INTEGER NOT NULL,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE
    )
    """)

    # 4. Tabla de Artículos (Relacionada con usuarios)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS articulos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        contenido TEXT NOT NULL,
        autor_id INTEGER NOT NULL,
        fecha_publicacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (autor_id) REFERENCES usuarios (id) ON DELETE CASCADE
    )
    """)

        # 5. Tabla de Compras (Relacionada con usuarios y articulos)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS compras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL,
        articulo_id INTEGER NOT NULL,
        cantidad REAL NOT NULL,
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE,
        FOREIGN KEY (articulo_id) REFERENCES articulos (id) ON DELETE CASCADE
    )
    """)

    conexion.commit()
    conexion.close()
    print("Base de datos optimizada y tablas creadas correctamente.")

if __name__ == "__main__":
    init_db()
