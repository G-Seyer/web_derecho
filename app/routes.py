
from flask import Blueprint, request, redirect, render_template
import os
import psycopg2
import smtplib
from email.mime.text import MIMEText
from app.models import Contacto
from app import db

main = Blueprint('main', __name__)

# Página principal
@main.route("/")
def inicio():
    return render_template("index.html")

# Página de contacto
@main.route("/contacto")
def contacto():
    return render_template("contacto.html")

# Página de privacidad
@main.route("/privacidad")
def privacidad():
    return render_template("privacidad.html")

# Función para enviar correo
def enviar_correo(nombre, correo, telefono, mensaje):
    cuerpo = f"""
    Nuevo mensaje desde el formulario de contacto:

    Nombre: {nombre}
    Correo: {correo}
    Teléfono: {telefono}
    Mensaje:
    {mensaje}
    """
    msg = MIMEText(cuerpo)
    msg['Subject'] = "Nuevo mensaje desde la página web"
    msg['From'] = os.getenv("EMAIL_USER")
    msg['To'] = "EMAIL_USER"

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
        smtp.send_message(msg)

# Conexión a la base de datos PostgreSQL (solo cuando se usa)
def obtener_conexion():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT")
    )

# Procesamiento del formulario

@main.route("/guardar_contacto", methods=["POST"])
def guardar_contacto():
    nombre = request.form.get("nombre")
    correo = request.form.get("correo")
    telefono = request.form.get("telefono")
    mensaje = request.form.get("mensaje")

    nuevo = Contacto(nombre=nombre, correo=correo, telefono=telefono, mensaje=mensaje)
    db.session.add(nuevo)
    db.session.commit()

    enviar_correo(nombre, correo, telefono, mensaje)

    return redirect("/gracias")


# Página de agradecimiento
@main.route('/gracias')
def gracias():
    return """
    <html>
        <head>
            <meta http-equiv="refresh" content="4; url=/" />
        </head>
        <body>
            <h2>Gracias por contactarnos. Te responderemos pronto.</h2>
            <p>Serás redirigido al inicio automáticamente...</p>
        </body>
    </html>
    """
