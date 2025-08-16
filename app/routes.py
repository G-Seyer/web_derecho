# app/routes.py
import os
import re
import mimetypes
from flask import render_template, request, redirect, url_for, flash
from app.models import MensajeContacto
from datetime import date, datetime
from functools import wraps

FORCE_S3 = os.getenv("FORCE_S3", "0") == "1"

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, current_app as app, Response
)
from sqlalchemy import text
from werkzeug.utils import secure_filename

from app import db

bp = Blueprint("routes", __name__)

# ---------- Health ----------
@bp.route("/health")
def healthcheck():
    return jsonify({"status": "ok"}), 200

# ---------- Home ----------
@bp.route("/")
def home():
    return render_template("index.html")


# =====================================================
# ===============  STORAGE: S3 / LOCAL  ===============
# =====================================================
ALLOWED_EXTS = {"pdf", "png", "jpg", "jpeg", "webp", "heic", "heif"}

def _ext_ok(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[-1].lower() in ALLOWED_EXTS

def _get_s3_client():
    """Crea cliente S3 solo si hay credenciales; si boto3 no está, se usa local."""
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_sec = os.getenv("AWS_SECRET_ACCESS_KEY")
    region  = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    if not aws_key or not aws_sec:
        raise RuntimeError("AWS credentials missing")
    import boto3  # import perezoso
    return boto3.client(
        "s3",
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_sec,
        region_name=region,
    )

def _save_file_to_s3(*, file_storage, folder: str, public: bool = True):
    bucket = os.getenv("S3_BUCKET_NAME") or os.getenv("S3_BUCKET")
    if not bucket:
        raise RuntimeError("S3_BUCKET_NAME (o S3_BUCKET) no está configurado")
    s3 = _get_s3_client()

    filename = secure_filename(file_storage.filename or "archivo.bin")
    raw = file_storage.read()
    size = len(raw)
    mime = mimetypes.guess_type(filename)[0] or file_storage.mimetype or "application/octet-stream"
    key  = f"{folder.strip('/')}/{datetime.now().strftime('%Y%m%dT%H%M%S')}_{filename}"

    # Intento 1: con ACL sólo si se pidió público explícitamente
    want_public = os.getenv("S3_PUBLIC_READ", "0") == "1"
    put_kwargs = {"Bucket": bucket, "Key": key, "Body": raw, "ContentType": mime}
    if want_public:
        put_kwargs["ACL"] = "public-read"

    try:
        s3.put_object(**put_kwargs)
    except Exception as e:
        # Si falló por ACL, reintentamos SIN ACL (privado) antes de rendirnos
        try:
            if "AccessDenied" in str(e) or "InvalidArgument" in str(e):
                s3.put_object(Bucket=bucket, Key=key, Body=raw, ContentType=mime)
            else:
                raise
        except Exception:
            app.logger.exception("Fallo guardando en S3 (reintento sin ACL)")
            raise

    # URL pública por región (si es privado, la URL existe pero requerirá permisos para leer)
    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    base = f"https://{bucket}.s3.amazonaws.com" if region == "us-east-1" else f"https://{bucket}.s3.{region}.amazonaws.com"
    ruta = f"{base}/{key}"
    app.logger.info(f"[S3] PUT s3://{bucket}/{key} ({size} bytes, {mime})")
    return ruta, mime, size


def _save_file_to_local(*, file_storage, folder: str):
    root = app.config.get("UPLOAD_FOLDER", os.path.join(app.root_path, "uploads"))
    folder_abs = os.path.join(root, folder.strip("/"))
    os.makedirs(folder_abs, exist_ok=True)

    filename = secure_filename(file_storage.filename or "archivo.bin")
    filename = f"{datetime.now().strftime('%Y%m%dT%H%M%S')}_{filename}"
    path = os.path.join(folder_abs, filename)

    file_storage.save(path)
    size = os.path.getsize(path)
    mime = mimetypes.guess_type(filename)[0] or file_storage.mimetype or "application/octet-stream"
    ruta = os.path.relpath(path, root).replace("\\", "/")  # ruta relativa
    return ruta, mime, size

def _save_file(*, file_storage, folder: str, public: bool = True):
    """
    Intenta S3 si hay configuración; si falla:
      - si FORCE_S3=1 -> lanza error (así ves el problema),
      - si FORCE_S3=0 -> cae a almacenamiento local.
    """
    try:
        if os.getenv("S3_BUCKET_NAME") or os.getenv("S3_BUCKET"):
            return _save_file_to_s3(file_storage=file_storage, folder=folder, public=public)
    except Exception:
        app.logger.exception("Fallo guardando en S3")
        if FORCE_S3:
            raise
    return _save_file_to_local(file_storage=file_storage, folder=folder)



# =====================================================
# ===============  HELPERS BASE DE DATOS  =============
# =====================================================
def _insert_document_with_folio(*, folio, tipo_usuario, usuario_id, tipo_documento, ruta, nombre_archivo, mime, size):
    """
    Inserta/actualiza un documento en public.documentos.
    La llave de conflicto usa (tipo_usuario, usuario_id, tipo_documento).
    """
    sql = text("""
        INSERT INTO public.documentos
          (folio, tipo_usuario, usuario_id, tipo_documento, ruta, nombre_archivo, mime, tamano_bytes, fecha_subida)
        VALUES
          (:folio, :tipo_usuario, :usuario_id, :tipo_documento, :ruta, :nombre_archivo, :mime, :size, now())
        ON CONFLICT (tipo_usuario, usuario_id, tipo_documento) DO UPDATE
        SET ruta           = EXCLUDED.ruta,
            nombre_archivo = EXCLUDED.nombre_archivo,
            mime           = EXCLUDED.mime,
            tamano_bytes   = EXCLUDED.tamano_bytes,
            fecha_subida   = now(),
            folio          = EXCLUDED.folio;
    """)
    db.session.execute(sql, dict(
        folio=folio, tipo_usuario=tipo_usuario, usuario_id=usuario_id,
        tipo_documento=tipo_documento, ruta=ruta, nombre_archivo=nombre_archivo,
        mime=mime, size=size
    ))

def _get_or_create_usuario_id_por_folio(*, tabla: str, folio: str):
    """
    Crea un registro con folio (si no existe) y devuelve el id.
    'tabla' debe ser un nombre controlado: 'arrendadores' o 'arrendatarios'.
    """
    sql = text(f"""
        INSERT INTO public.{tabla} (folio)
        VALUES (:folio)
        ON CONFLICT (folio) DO UPDATE SET folio = EXCLUDED.folio
        RETURNING id;
    """)
    row = db.session.execute(sql, {"folio": folio}).first()
    return row[0]

def _upsert_arrendador_datos(datos: dict):
    """
    Inserta/actualiza datos del arrendador.
    Requiere que public.arrendadores tenga UNIQUE(folio).
    Ajusta a tu esquema si algún campo no existe.
    """
    sql = text("""
        INSERT INTO public.arrendadores(
            folio, nombre, correo, direccion_actual, rfc, curp, telefono,
            banco, titular_cuenta, cuenta_bancaria, clabe_interbancaria,
            direccion, tipo_inmueble, superficie_terreno, metros_construidos,
            habitaciones, banos, estacionamientos, uso_suelo, cuenta_predial,
            cuenta_agua, servicios_pagan, caracteristicas, inventario,
            precio_renta, fecha_inicio_renta, fecha_firma_contrato, lugar_nacimiento, fecha_nacimiento, updated_at
        ) VALUES (
            :folio, :nombre, :correo, :direccion_actual, :rfc, :curp, :telefono,
            :banco, :titular_cuenta, :cuenta_bancaria, :clabe_interbancaria,
            :direccion, :tipo_inmueble, :superficie_terreno, :metros_construidos,
            :habitaciones, :banos, :estacionamientos, :uso_suelo, :cuenta_predial,
            :cuenta_agua, :servicios_pagan, :caracteristicas, :inventario,
            :precio_renta, :fecha_inicio_renta, :fecha_firma_contrato, :lugar_nacimiento, :fecha_nacimiento, now()
        )
        ON CONFLICT (folio) DO UPDATE SET
            nombre               = EXCLUDED.nombre,
            correo               = EXCLUDED.correo,
            direccion_actual     = EXCLUDED.direccion_actual,
            rfc                  = EXCLUDED.rfc,
            curp                 = EXCLUDED.curp,
            telefono             = EXCLUDED.telefono,
            banco                = EXCLUDED.banco,
            titular_cuenta       = EXCLUDED.titular_cuenta,
            cuenta_bancaria      = EXCLUDED.cuenta_bancaria,
            clabe_interbancaria  = EXCLUDED.clabe_interbancaria,
            direccion            = EXCLUDED.direccion,
            tipo_inmueble        = EXCLUDED.tipo_inmueble,
            superficie_terreno   = EXCLUDED.superficie_terreno,
            metros_construidos   = EXCLUDED.metros_construidos,
            habitaciones         = EXCLUDED.habitaciones,
            banos                = EXCLUDED.banos,
            estacionamientos     = EXCLUDED.estacionamientos,
            uso_suelo            = EXCLUDED.uso_suelo,
            cuenta_predial       = EXCLUDED.cuenta_predial,
            cuenta_agua          = EXCLUDED.cuenta_agua,
            servicios_pagan      = EXCLUDED.servicios_pagan,
            caracteristicas      = EXCLUDED.caracteristicas,
            inventario           = EXCLUDED.inventario,
            precio_renta         = EXCLUDED.precio_renta,
            fecha_inicio_renta   = EXCLUDED.fecha_inicio_renta,
            fecha_firma_contrato = EXCLUDED.fecha_firma_contrato,
            lugar_nacimiento     = EXCLUDED.lugar_nacimiento,
            fecha_nacimiento     = EXCLUDED.fecha_nacimiento,
            updated_at           = now();
    """)
    db.session.execute(sql, datos)


def _upsert_arrendatario_datos(datos: dict):
    """
    Inserta/actualiza datos mínimos del arrendatario.
    Requiere que public.arrendatarios tenga UNIQUE(folio).
    """
    sql = text("""
        INSERT INTO public.arrendatarios(
            folio, lugar_nacimiento, fecha_nacimiento, updated_at
        ) VALUES (
            :folio, :lugar_nacimiento, :fecha_nacimiento, now()
        )
        ON CONFLICT (folio) DO UPDATE SET
            lugar_nacimiento = EXCLUDED.lugar_nacimiento,
            fecha_nacimiento = EXCLUDED.fecha_nacimiento,
            updated_at       = now();
    """)
    db.session.execute(sql, datos)
# Mensaje flash + redirección a Inicio
def _to_home(message: str, category: str = "success"):
    flash(message, category)
    return redirect(url_for("routes.home"))


# =====================================================
# ===============  CONTROL DE FOLIOS  =================
# =====================================================
def _folio_activo(folio: str) -> bool:
    row = db.session.execute(text("SELECT activo FROM public.folios WHERE folio = :f"), {"f": folio}).first()
    return bool(row and row[0])

def _marcar_uso_folio(folio: str, quien: str):
    campo = "usos_arrendador" if quien == "arrendador" else "usos_arrendatario"
    db.session.execute(text(f"""
        UPDATE public.folios
           SET {campo} = {campo} + 1,
               ultima_actividad_at = now()
         WHERE folio = :f
    """), {"f": folio})

def _generar_folio_unico() -> str:
    import random, string
    for _ in range(24):
        suf = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        ym = datetime.now().strftime("%Y%m")
        folio = f"AEPRA-{ym}-{suf}"
        ex = db.session.execute(text("SELECT 1 FROM public.folios WHERE folio = :f"), {"f": folio}).first()
        if not ex:
            db.session.execute(text("INSERT INTO public.folios(folio) VALUES (:f)"), {"f": folio})
            db.session.commit()
            return folio
    raise RuntimeError("No se pudo generar un folio único")


# =====================================================
# ===============  API: FOLIOS / COMPAT  ==============
# =====================================================
@bp.get("/api/verificar-folio/<folio>")
def api_verificar_folio(folio):
    ok = _folio_activo((folio or "").upper())
    return jsonify({"ok": ok})

@bp.get("/validar_folio")  # compat para plantillas viejas
def validar_folio():
    folio = (request.args.get("folio") or "").strip().upper()
    return jsonify({"valido": _folio_activo(folio)})

@bp.get("/api/admin/folio-nuevo")
def api_admin_folio_nuevo():
    folio = _generar_folio_unico()
    return jsonify({"ok": True, "folio": folio})


# =====================================================
# ===============  VISTAS: DOCUMENTOS  ================
# =====================================================
@bp.route("/documentos/propietario", methods=["GET", "POST"])
def subir_propietario():
    if request.method == "GET":
        return render_template("documentos_propietario.html")

    form = request.form
    folio = (form.get("folio") or "").strip().upper()

    # Validación de folio (formato + existencia en tabla folios)
    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return _to_home("Folio inválido. Verifica el formato AEPRA-YYYYMM-XXXX.", "danger")
    if not _folio_activo(folio):
        return _to_home("El folio no existe o está desactivado. Solicítalo a administración.", "danger")

    # Datos
    datos = {
        "folio": folio,
        "nombre": form.get("nombre"),
        "correo": form.get("correo"),
        "direccion_actual": form.get("direccion_actual"),
        "rfc": form.get("rfc"),
        "curp": form.get("curp"),
        "telefono": form.get("telefono"),
        "banco": form.get("banco"),
        "titular_cuenta": form.get("titular_cuenta"),
        "cuenta_bancaria": form.get("cuenta_bancaria"),
        "clabe_interbancaria": form.get("clabe_interbancaria"),
        "direccion": form.get("direccion"),
        "tipo_inmueble": form.get("tipo_inmueble"),
        "superficie_terreno": form.get("superficie_terreno"),
        "metros_construidos": form.get("metros_construidos"),
        "habitaciones": form.get("habitaciones"),
        "banos": form.get("banos"),
        "estacionamientos": form.get("estacionamientos"),
        "uso_suelo": form.get("uso_suelo"),
        "cuenta_predial": form.get("cuenta_predial"),
        "cuenta_agua": form.get("cuenta_agua"),
        "servicios_pagan": form.get("servicios_pagan"),
        "caracteristicas": form.get("caracteristicas"),
        "inventario": form.get("inventario"),
        "precio_renta": form.get("precio_renta"),
        "fecha_inicio_renta": form.get("fecha_inicio_renta"),
        "fecha_firma_contrato": form.get("fecha_firma_contrato"),
        "lugar_nacimiento": form.get("lugar_nacimiento"),
        "fecha_nacimiento": (form.get("fecha_nacimiento") or None),
    }
    requeridos = [
        "nombre","correo","direccion_actual","rfc","curp","telefono",
        "banco","titular_cuenta","cuenta_bancaria","clabe_interbancaria",
        "direccion","precio_renta","fecha_inicio_renta","fecha_firma_contrato"
    ]
    faltantes = [k for k in requeridos if not (datos.get(k) or "").strip()]
    if faltantes:
        return _to_home(f"Campos obligatorios faltantes: {', '.join(faltantes)}", "danger")

    try:
        # 1) Datos del arrendador (upsert)
        _upsert_arrendador_datos(datos)
        arr_id = _get_or_create_usuario_id_por_folio(tabla="arrendadores", folio=folio)

        # 2) Archivos
        alias = {
            "boleta_predial": ["boleta_predial", "solicitud_propietario", "solicitud"],
            "identificacion": ["identificacion", "id_oficial"],
            "comprobante_domicilio": ["comprobante_domicilio", "comp_domicilio"],
            "escritura": ["escritura"],
            "contrato_poder": ["contrato_poder", "poder_notarial"],  # opcional
            "folio_real": ["folio_real", "constancia_folio_real"],
        }
        requeridos_doc = {"boleta_predial", "identificacion", "comprobante_domicilio", "escritura", "folio_real"}
        guardados = []

        for logical, keys in alias.items():
            fs = next(
                (request.files[k] for k in keys if k in request.files and request.files[k] and request.files[k].filename),
                None
            )
            if not fs:
                if logical in requeridos_doc:
                    raise ValueError(f"Falta archivo requerido: {logical.replace('_',' ')}")
                continue
            if not _ext_ok(fs.filename):
                raise ValueError(f"Extensión no permitida: {fs.filename}")

            ruta, mime, size = _save_file(
                file_storage=fs,
                folder=f"arrendador/{folio}/{arr_id}",
                public=True
            )
            _insert_document_with_folio(
                folio=folio, tipo_usuario="arrendador", usuario_id=arr_id,
                tipo_documento=logical, ruta=ruta, nombre_archivo=fs.filename, mime=mime, size=size
            )
            guardados.append(logical)

        # 3) Marcar uso de folio y commit
        _marcar_uso_folio(folio, "arrendador")
        db.session.commit()

        # 4) Mensaje + redirección a inicio
        lista = ", ".join(guardados) if guardados else "ninguno"
        return _to_home(
            f"✅ Propietario guardado para <b>{folio}</b>. Documentos almacenados: <b>{len(guardados)}</b> ({lista}).",
            "success"
        )

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Error guardando propietario")
        return _to_home(f"❌ No se pudieron guardar los datos del propietario ({folio}). Detalle: {e}", "danger")


@bp.route("/documentos/inquilino", methods=["GET", "POST"])
def subir_inquilino():
    if request.method == "GET":
        return render_template("documentos_inquilino.html")

    form = request.form
    folio = (form.get("folio") or "").strip().upper()

    # Validación de folio (formato + existencia en tabla folios)
    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return _to_home("Folio inválido. Verifica el formato AEPRA-YYYYMM-XXXX.", "danger")
    if not _folio_activo(folio):
        return _to_home("El folio no existe o está desactivado. Solicítalo a administración.", "danger")

    try:
        # 1) Asegura registro y obtiene id del inquilino para ese folio
        inq_id = _get_or_create_usuario_id_por_folio(tabla="arrendatarios", folio=folio)
        # Datos nuevos del inquilino (mínimo para nacimiento)
        datos_inq = {
            "folio": folio,
            "lugar_nacimiento": (form.get("lugar_nacimiento") or None),
            "fecha_nacimiento": (form.get("fecha_nacimiento") or None)
        }
        _upsert_arrendatario_datos(datos_inq)

        # 2) Guardar todos los archivos enviados (cualesquiera que vengan del form)
        guardados = []
        for clave, fs in request.files.items():
            if not fs or fs.filename == "":
                continue
            if not _ext_ok(fs.filename):
                raise ValueError(f"Extensión no permitida: {fs.filename}")

            ruta, mime, size = _save_file(
                file_storage=fs,
                folder=f"arrendatario/{folio}/{inq_id}",
                public=True
            )
            _insert_document_with_folio(
                folio=folio, tipo_usuario="arrendatario", usuario_id=inq_id,
                tipo_documento=clave, ruta=ruta, nombre_archivo=fs.filename, mime=mime, size=size
            )
            guardados.append(clave)

        # 3) Marcar uso de folio y confirmar transacción
        _marcar_uso_folio(folio, "arrendatario")
        db.session.commit()

        # 4) Mensaje + redirección a Inicio
        lista = ", ".join(guardados) if guardados else "ninguno"
        return _to_home(
            f"✅ Inquilino guardado para <b>{folio}</b>. Documentos almacenados: <b>{len(guardados)}</b> ({lista}).",
            "success"
        )

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Error guardando inquilino")
        return _to_home(f"❌ No se pudieron guardar documentos de inquilino ({folio}). Detalle: {e}", "danger")



# =====================================================
# =====================  ADMIN  =======================
# =====================================================
# --- Basic Auth para /admin ---
# --------- Login por sesión (Flask-Login) ---------
import os, logging
from flask import render_template, request, redirect, url_for, flash, current_app as app
from flask_login import (
    login_user, logout_user, login_required, UserMixin, current_user
)
from app import login_manager

# 1) Credenciales desde .env (cargado en __init__.py)
ADMIN_USER = (os.getenv("ADMIN_USER") or "").strip()
ADMIN_PASS = (os.getenv("ADMIN_PASS") or "").strip()

# 2) Fallback de desarrollo si .env no cargó
USE_FALLBACK = False
if not ADMIN_USER or not ADMIN_PASS:
    ADMIN_USER = "admin"
    ADMIN_PASS = "admin123"
    USE_FALLBACK = True

_auth_logger = logging.getLogger("auth")
_auth_logger.warning(
    "ADMIN CREDS -> user_set=%s pass_len=%d%s",
    bool(ADMIN_USER), len(ADMIN_PASS or ""),
    " [FALLBACK DEV ENABLED]" if USE_FALLBACK else ""
)

class AdminUser(UserMixin):
    def __init__(self, user_id="admin"):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id: str):
    return AdminUser("admin") if user_id == "admin" else None

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("routes.admin"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        # Log del intento (no imprimimos la contraseña)
        try:
            app.logger.warning(
                "LOGIN TRY -> user=%r match_user=%s match_pass=%s",
                username, (username == ADMIN_USER), (password == ADMIN_PASS)
            )
        except Exception:
            pass

        if username == ADMIN_USER and password == ADMIN_PASS:
            login_user(AdminUser("admin"))
            flash("Bienvenido, acceso concedido.", "success")
            return redirect(url_for("routes.admin"))
        else:
            flash("Usuario o contraseña incorrectos.", "warning")

    return render_template("login.html")

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("routes.login"))

@bp.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    return render_template("admin.html")


# =====================================================
# ======================  API ADMIN  ==================
# =====================================================
@bp.get("/api/admin/folio/<folio>")
def api_admin_folio(folio):
    conn = db.session.connection()

    cur  = conn.execute(text("""
        SELECT folio, docs_arrendador, docs_arrendatario, total_docs,
               primera_subida, ultima_subida
        FROM public.v_documentos_resumen
        WHERE folio = :folio
    """), {"folio": folio})
    row = cur.fetchone()
    resumen = None
    if row:
        resumen = {
            "folio": row[0],
            "docs_arrendador": row[1],
            "docs_arrendatario": row[2],
            "total_docs": row[3],
            "primera_subida": row[4].isoformat() if row[4] else None,
            "ultima_subida":  row[5].isoformat() if row[5] else None,
        }

    cur = conn.execute(text("""
        SELECT tipo_usuario, tipo_documento, nombre_archivo,
               COALESCE(mime, content_type) AS mime,
               tamano_bytes, ruta, fecha_subida
        FROM public.v_documentos_por_folio
        WHERE folio = :folio
        ORDER BY fecha_subida DESC, tipo_usuario, tipo_documento
    """), {"folio": folio})
    documentos = []
    for r in cur.fetchall():
        documentos.append({
            "tipo_usuario": r[0],
            "tipo_documento": r[1],
            "nombre_archivo": r[2],
            "mime": r[3],
            "tamano_bytes": int(r[4]) if r[4] is not None else None,
            "ruta": r[5],
            "fecha_subida": r[6].isoformat() if r[6] else None,
        })

    cur = conn.execute(text("""
        SELECT fecha_inicio, fecha_fin
        FROM public.polizas
        WHERE folio = :folio
    """), {"folio": folio})
    poliza = None
    row = cur.fetchone()
    if row:
        poliza = {"fecha_inicio": row[0].isoformat(), "fecha_fin": row[1].isoformat()}

    return jsonify({"resumen": resumen, "documentos": documentos, "poliza": poliza})

@bp.post("/api/admin/poliza")
def api_admin_set_poliza():
    data = request.get_json(silent=True) or request.form
    folio = (data.get("folio") or "").strip()
    finicio = (data.get("fecha_inicio") or "").strip()
    if not folio or not finicio:
        return jsonify({"ok": False, "error": "Folio y fecha_inicio son requeridos"}), 400

    try:
        y, m, d = map(int, finicio.split("-"))
        fi = date(y, m, d)
        ff = date(y + 1, m, d)
    except Exception:
        return jsonify({"ok": False, "error": "fecha_inicio inválida (YYYY-MM-DD)"}), 400

    db.session.execute(text("""
        INSERT INTO public.polizas (folio, fecha_inicio, fecha_fin)
        VALUES (:folio, :fi, :ff)
        ON CONFLICT (folio) DO UPDATE
        SET fecha_inicio = EXCLUDED.fecha_inicio,
            fecha_fin    = EXCLUDED.fecha_fin
    """), {"folio": folio, "fi": fi, "ff": ff})
    db.session.commit()

    return jsonify({"ok": True, "folio": folio, "fecha_inicio": fi.isoformat(), "fecha_fin": ff.isoformat()})

@bp.get("/api/admin/polizas")
def api_admin_polizas():
    """
    Devuelve pólizas que vencen en <= max_meses meses a partir de hoy.
    ?max_meses=3  (default 3)
    ?incluir_vencidas=0|1  (default 0, no incluye ya vencidas)
    """
    try:
        max_meses = int(request.args.get("max_meses", 3))
    except ValueError:
        max_meses = 3
    incluir_vencidas = request.args.get("incluir_vencidas", "0") == "1"

    sql = text(f"""
        with pol as (
          select
            folio,
            fecha_inicio,
            fecha_fin,
            (extract(year  from age(fecha_fin, current_date))::int * 12)
          + (extract(month from age(fecha_fin, current_date))::int)          as meses_restantes,
            (fecha_fin - current_date)                                        as dias_restantes
          from polizas
        )
        select folio,
               to_char(fecha_inicio, 'YYYY-MM-DD') as fecha_inicio,
               to_char(fecha_fin,    'YYYY-MM-DD') as fecha_fin,
               meses_restantes,
               dias_restantes
        from pol
        where meses_restantes <= :max_meses
          and (:incl = true or dias_restantes >= 0)
        order by dias_restantes asc, folio asc
        limit 500
    """)
    rows = db.session.execute(sql, {"max_meses": max_meses, "incl": incluir_vencidas}).mappings().all()

    items = []
    for r in rows:
        items.append({
            "folio": r["folio"],
            "fecha_inicio": r["fecha_inicio"],
            "fecha_fin": r["fecha_fin"],
            "meses_restantes": int(r["meses_restantes"]),
            "dias_restantes": int(r["dias_restantes"]),
        })
    return jsonify({"items": items, "max_meses": max_meses, "incluir_vencidas": incluir_vencidas})


# =====================================================
# ==================  OTRAS PÁGINAS  ==================
# =====================================================
@bp.route("/terminos-mascotas")
def terminos_mascotas():
    return render_template("terminos_mascotas.html")


@bp.route("/politicas")
def politicas():
    return render_template("privacidad.html")

@bp.route("/privacidad")
def privacidad_alias():
    return redirect(url_for("routes.politicas"), code=301)


# =====================================================
# ====================  DEBUG API  ====================
# =====================================================
@bp.get("/api/debug/consistencia/<folio>")
def api_debug_consistencia(folio):
    f = (folio or "").strip().upper()
    out = {}

    r = db.session.execute(text("""
        SELECT folio, activo, usos_arrendador, usos_arrendatario, ultima_actividad_at
        FROM public.folios WHERE folio = :f
    """), {"f": f}).mappings().first()
    out["folios"] = dict(r) if r else None

    r = db.session.execute(text("""
        SELECT id, folio, nombre, correo, direccion_actual, created_at, updated_at
        FROM public.arrendadores WHERE folio = :f
        ORDER BY id DESC LIMIT 1
    """), {"f": f}).mappings().first()
    out["arrendadores"] = dict(r) if r else None

    docs = db.session.execute(text("""
        SELECT tipo_usuario, tipo_documento, nombre_archivo, ruta, fecha_subida
        FROM public.documentos WHERE folio = :f
        ORDER BY fecha_subida DESC, tipo_usuario, tipo_documento
        LIMIT 50
    """), {"f": f}).mappings().all()
    out["documentos"] = [dict(x) for x in docs]

    return jsonify(out)

@bp.get("/api/debug/s3")
def dbg_s3():
    try:
        bucket = os.getenv("S3_BUCKET_NAME") or os.getenv("S3_BUCKET")
        s3 = _get_s3_client()
        s3.head_bucket(Bucket=bucket)
        return jsonify({"ok": True, "bucket": bucket, "checked_at": datetime.utcnow().isoformat()+"Z"}), 200
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
            "env": {
                "AWS_ACCESS_KEY_ID": bool(os.getenv("AWS_ACCESS_KEY_ID")),
                "AWS_SECRET_ACCESS_KEY": bool(os.getenv("AWS_SECRET_ACCESS_KEY")),  
                "AWS_DEFAULT_REGION": os.getenv("AWS_DEFAULT_REGION"),
                "S3_BUCKET_NAME": os.getenv("S3_BUCKET_NAME") or os.getenv("S3_BUCKET"),
            }
        }), 500
    
# =====================================================
# ==================== Contactanos ====================
# =====================================================


# app/routes.py (fragmento)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@bp.route("/contacto", methods=["GET", "POST"])
def contacto():
    if request.method == "POST":
        nombre   = (request.form.get("nombre") or "").strip()
        correo   = (request.form.get("correo") or "").strip()
        telefono = (request.form.get("telefono") or "").strip()
        mensaje  = (request.form.get("mensaje") or "").strip()

        # Validación mínima
        if not nombre or not correo or not mensaje:
            flash("Nombre, correo y mensaje son obligatorios.", "warning")
            return render_template("contacto.html", form=request.form), 400

        if not EMAIL_RE.match(correo):
            flash("Correo no válido.", "warning")
            return render_template("contacto.html", form=request.form), 400

        try:
            m = MensajeContacto(
                nombre=nombre,
                correo=correo,
                telefono=telefono or None,
                mensaje=mensaje
            )
            db.session.add(m)
            db.session.commit()
            flash("¡Gracias! Tu mensaje fue enviado.", "success")
            return redirect(url_for("routes.contacto"))
        except Exception as e:
            db.session.rollback()
            app.logger.exception("Error guardando contacto: %s", e)  # <-- usa app.logger
            flash("Ocurrió un error al guardar tu mensaje. Intenta de nuevo.", "danger")
            return render_template("contacto.html", form=request.form), 500

    # GET
    return render_template("contacto.html")
