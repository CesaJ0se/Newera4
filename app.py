from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os

app = Flask(__name__)

# ==========================
# MONGODB
# ==========================

MONGO_URI = os.environ.get("MONGO_URI")

if not MONGO_URI:
    raise Exception("MONGO_URI no configurada")

client = MongoClient(MONGO_URI)

db = client["newera"]
usuarios = db["usuarios"]

# ==========================
# RUTAS HTML
# ==========================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/registro")
def registro():
    return render_template("registro.html")


@app.route("/login")
def login():
    return render_template("login.html")


# ==========================
# API REGISTRO
# ==========================

@app.route("/api/registro", methods=["POST"])
def api_registro():

    data = request.get_json()

    print("DATOS RECIBIDOS:")
    print(data)

    nombre = data.get("nombre", "").strip()
    apellido = data.get("apellido", "").strip()
    email = data.get("email", "").strip().lower()
    telefono = data.get("telefono", "").strip()
    password = data.get("password", "")

    if not nombre:
        return jsonify({
            "ok": False,
            "mensaje": "Nombre requerido"
        }), 400

    if not apellido:
        return jsonify({
            "ok": False,
            "mensaje": "Apellido requerido"
        }), 400

    if not email:
        return jsonify({
            "ok": False,
            "mensaje": "Correo requerido"
        }), 400

    if len(password) < 8:
        return jsonify({
            "ok": False,
            "mensaje": "La contraseña debe tener al menos 8 caracteres"
        }), 400

    usuario_existente = usuarios.find_one({
        "email": email
    })

    if usuario_existente:
        return jsonify({
            "ok": False,
            "mensaje": "Este correo ya está registrado",
            "campo": "email"
        }), 409

    password_hash = generate_password_hash(password)

    usuarios.insert_one({
        "nombre": nombre,
        "apellido": apellido,
        "email": email,
        "telefono": telefono,
        "password": password_hash
    })

    token = secrets.token_hex(32)

    return jsonify({
        "ok": True,
        "token": token,
        "usuario": {
            "nombre": nombre,
            "apellido": apellido,
            "email": email
        }
    })


# ==========================
# API LOGIN
# ==========================

@app.route("/api/login", methods=["POST"])
def api_login():

    data = request.get_json()

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    usuario = usuarios.find_one({
        "email": email
    })

    if not usuario:
        return jsonify({
            "ok": False,
            "mensaje": "Correo o contraseña incorrectos",
            "campo": "email"
        }), 401

    if not check_password_hash(
        usuario["password"],
        password
    ):
        return jsonify({
            "ok": False,
            "mensaje": "Correo o contraseña incorrectos",
            "campo": "password"
        }), 401

    token = secrets.token_hex(32)

    return jsonify({
        "ok": True,
        "token": token,
        "usuario": {
            "nombre": usuario["nombre"],
            "apellido": usuario["apellido"],
            "email": usuario["email"]
        }
    })


# ==========================
# INICIO
# ==========================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )