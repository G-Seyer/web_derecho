# routes.py
import os
import time
import smtplib
from email.mime.text import MIMEText

import boto3
from botocore.client import Config

from flask import Blueprint, request, redirect, render_template, current_app
from sqlalchemy import text
from werkzeug.utils import secure_filename

from app import db
from app.models import Contacto

main = Blueprint('main', __name__)

# =========================
# S3 (documentos)
# =========================
s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_S3_REGION_NAME"),
    config=Config(signature_version="s3v4"),
)
BUCKET = os.getenv("S3_BUCKET_NAME") or os.getenv("S3_BUCKET")
PREFIX = os.getenv("S3_PREFIX", "")  # opcional, ej. "aepra/"

# =========================
# Helpers (documentos)
# =========================
def _valida_gmail(correo: str) -> bool:
    return correo.strip().lower().endswith("@gmail.com")

def _allowed(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config.get("ALLOWED_EXTENSIONS", {"pdf","jpg","jpeg","png","webp"})

def _save_file(file_storage, carpeta: str, user_id: int, clave: str):
    """
    Sube a s3://<BUCKET>/<PREFIX><carpeta>/<user_id>/<nombre>_<clave>_<ts>.<ext>
    Retorna (s3_key, tamano_bytes, mimetype)
    """
    if not BUCKET:
        raise RuntimeError("S3_BUCKET_NAME (o S3_BUCKET) no está configurado")

    ts = time.strftime("%Y%m%d-%H%M%S")
    name, ext = os.path.splitext(file_storage.filename)
    safe = (secure_filename(name) or "archivo")[:50]
    filename = f"{safe}_{clave}_{ts}{ext.lower()}"

    key = f"{PREFIX}{carpeta}/{user_id}/{filename}"

    file_storage.stream.seek(0)
    s3.upload_fileobj(
        Fileobj=file_storage.stream,
        Bucket=BUCKET,
        Key=key,
        ExtraArgs={"ContentType": file_storage.mimetype or "application/octet-stream"},
    )

    size = getattr(file_storage, "content_length", None) or 0
    mime = (file_storage.mimetype or None)
    return key, size, mime


# =========================
# Páginas públicas
# =========================
@main.route("/")
def inicio():
    return render_template("index.html")

@main.route("/contacto")
def contacto():
    return render_template("contacto.html")

@main.route("/privacidad")
def privacidad():
    return render_template("privacidad.html")

# =========================
# Formularios separados (GET)
# =========================
@main.route("/documentos/propietario", methods=["GET"])
def documentos_propietario():
    return render_template("documentos_propietario.html")

@main.route("/documentos/inquilino", methods=["GET"])
def documentos_inquilino():
    return render_template("documentos_inquilino.html")

# =========================
# Recepción (POST) – guardar en S3 + DB
# =========================
@main.route("/documentos/propietario", methods=["POST"])
def subir_propietario():
    f = request.form
    files = request.files

    nombre = f.get("nombre", "").strip()
    correo = f.get("correo", "").strip()
    direccion = f.get("direccion", "").strip()

    if not (nombre and correo and direccion):
        return "Faltan campos obligatorios.", 400
    if not _valida_gmail(correo):
        return "El correo debe terminar en @gmail.com", 400

    req = {
        "identificacion":        files.get("identificacion"),
        "comprobante_domicilio": files.get("comprobante_domicilio"),
        "escritura":             files.get("escritura"),
        "contrato_poder":        files.get("contrato_poder"),
        "folio_real":            files.get("folio_real"),
    }
    for k, fs in req.items():
        if not fs or fs.filename == "":
            return f"Falta archivo: {k}", 400
        if not _allowed(fs.filename):
            return f"Extensión no permitida en: {k}", 400

    try:
        # 1) Inserta arrendador
        arr_id = db.session.execute(text("""
            INSERT INTO arrendadores (nombre, correo, direccion)
            VALUES (:n, :c, :d)
            RETURNING id
        """), dict(n=nombre, c=correo, d=direccion)).scalar()

        # 2) Sube archivos a S3 y registra en documentos
        for clave, fs in req.items():
            ruta, size, mime = _save_file(fs, "arrendador", arr_id, clave)
            db.session.execute(text("""
                INSERT INTO documentos (tipo_usuario, usuario_id, tipo_documento, ruta, nombre_archivo, mime, tamano_bytes)
                VALUES ('arrendador', :uid, :tipo, :ruta, :nombre, :mime, :size)
                ON CONFLICT (tipo_usuario, usuario_id, tipo_documento) DO UPDATE
                SET ruta=EXCLUDED.ruta,
                    nombre_archivo=EXCLUDED.nombre_archivo,
                    mime=EXCLUDED.mime,
                    tamano_bytes=EXCLUDED.tamano_bytes,
                    fecha_subida=now();
            """), dict(uid=arr_id, tipo=clave, ruta=ruta, nombre=fs.filename, mime=mime, size=size))

        db.session.commit()
        return f"✅ Documentos del PROPIETARIO guardados. ID={arr_id}", 200

    except Exception as e:
        db.session.rollback()
        return f"Error guardando propietario: {e}", 500

@main.route("/documentos/inquilino", methods=["POST"])
def subir_inquilino():
    f = request.form
    files = request.files

    nombre = f.get("nombre", "").strip()
    correo = f.get("correo", "").strip()
    direccion = f.get("direccion", "").strip()

    if not (nombre and correo and direccion):
        return "Faltan campos obligatorios.", 400
    if not _valida_gmail(correo):
        return "El correo debe terminar en @gmail.com", 400

    req = {
        "identificacion":          files.get("identificacion"),
        "comprobante_domicilio":   files.get("comprobante_domicilio"),
        "comprobante_ingresos":    files.get("comprobante_ingresos"),
        "solicitud_arrendamiento": files.get("solicitud_arrendamiento"),
        "aval":                    files.get("aval"),
    }
    for k, fs in req.items():
        if not fs or fs.filename == "":
            return f"Falta archivo: {k}", 400
        if not _allowed(fs.filename):
            return f"Extensión no permitida en: {k}", 400

    try:
        # 1) Inserta arrendatario
        inq_id = db.session.execute(text("""
            INSERT INTO arrendatarios (nombre, correo, direccion)
            VALUES (:n, :c, :d)
            RETURNING id
        """), dict(n=nombre, c=correo, d=direccion)).scalar()

        # 2) Sube archivos a S3 y registra en documentos
        for clave, fs in req.items():
            ruta, size, mime = _save_file(fs, "arrendatario", inq_id, clave)
            db.session.execute(text("""
                INSERT INTO documentos (tipo_usuario, usuario_id, tipo_documento, ruta, nombre_archivo, mime, tamano_bytes)
                VALUES ('arrendatario', :uid, :tipo, :ruta, :nombre, :mime, :size)
                ON CONFLICT (tipo_usuario, usuario_id, tipo_documento) DO UPDATE
                SET ruta=EXCLUDED.ruta,
                    nombre_archivo=EXCLUDED.nombre_archivo,
                    mime=EXCLUDED.mime,
                    tamano_bytes=EXCLUDED.tamano_bytes,
                    fecha_subida=now();
            """), dict(uid=inq_id, tipo=clave, ruta=ruta, nombre=fs.filename, mime=mime, size=size))

        db.session.commit()
        return f"✅ Documentos del INQUILINO guardados. ID={inq_id}", 200

    except Exception as e:
        db.session.rollback()
        return f"Error guardando inquilino: {e}", 500

# =========================
# Formulario de contacto
# =========================
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
    msg['From'] = os.getenv("EMAIL_USER"); msg['To'] = os.getenv("EMAIL_USER")
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
        smtp.send_message(msg)

@main.route("/guardar_contacto", methods=["POST"])
def guardar_contacto():
    try:
        nombre = request.form.get("nombre")
        correo = request.form.get("correo")
        telefono = request.form.get("telefono")
        mensaje = request.form.get("mensaje")
        nuevo = Contacto(nombre=nombre, correo=correo, telefono=telefono, mensaje=mensaje)
        db.session.add(nuevo); db.session.commit()
        enviar_correo(nombre, correo, telefono, mensaje)
        return redirect("/gracias")
    except Exception as e:
        print("❌ ERROR al guardar o enviar correo:", e)
        return "Error interno del servidor", 500

@main.route('/gracias')
def gracias():
    return """
    <html>
      <head><meta http-equiv="refresh" content="4; url=/" /></head>
      <body>
        <h2>Gracias por contactarnos. Te responderemos pronto.</h2>
        <p>Serás redirigido al inicio automáticamente...</p>
      </body>
    </html>
    """

# =========================
# Healthcheck simple DB
# =========================
@main.route("/dbcheck")
def dbcheck():
    try:
        now = db.session.execute(text("SELECT now()")).scalar()
        return f"OK DB {now}"
    except Exception as e:
        return f"DB error: {e}", 500
