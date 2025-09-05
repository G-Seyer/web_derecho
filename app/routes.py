# app/routes.py
import os
import re
import mimetypes
from datetime import date, datetime
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, current_app as app, Response, session
)
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from sqlalchemy import text
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# Importamos desde app para no duplicar login_manager/user
from app import db, login_manager, SimpleUser
from app.models import MensajeContacto

bp = Blueprint("routes", __name__)

# ===== Config / flags
FORCE_S3 = os.getenv("FORCE_S3", "0") == "1"
ALLOWED_EXTS = {"pdf", "png", "jpg", "jpeg", "webp", "heic", "heif"}
FOLIO_RE = re.compile(r"^AEPRA-\d{6}-[A-Z0-9]{4}$")
ALLOWED_TIPOS_POLIZA = {"Tradicional", "Intermedia", "Plus", "Mascota"}

@bp.record_once
def _apply_proxy_and_cookies(state):
    app = state.app
    try:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    except Exception:
        pass
    is_prod = os.getenv("RENDER", "false").lower() in {"1", "true"} or os.getenv("FORCE_HTTPS", "1") == "1"
    if is_prod:
        app.config.setdefault("PREFERRED_URL_SCHEME", "https")
        app.config.setdefault("SESSION_COOKIE_SECURE", True)
        app.config.setdefault("REMEMBER_COOKIE_SECURE", True)

# ===== S3 helpers
def _current_bucket() -> str:
    bucket = os.getenv("S3_BUCKET") or os.getenv("S3_BUCKET_NAME")
    if not bucket:
        raise RuntimeError("S3_BUCKET no está configurado (ni S3_BUCKET_NAME)")
    return bucket

def _get_s3_client():
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_sec = os.getenv("AWS_SECRET_ACCESS_KEY")
    region  = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    if not aws_key or not aws_sec:
        raise RuntimeError("AWS credentials missing")
    import boto3
    return boto3.client("s3", aws_access_key_id=aws_key, aws_secret_access_key=aws_sec, region_name=region)

def _ext_ok(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[-1].lower() in ALLOWED_EXTS

def _save_file_to_s3(*, file_storage, folder: str, public: bool = True):
    bucket = _current_bucket()
    s3 = _get_s3_client()
    filename = secure_filename(file_storage.filename or "archivo.bin")
    raw = file_storage.read()
    size = len(raw)
    mime = mimetypes.guess_type(filename)[0] or file_storage.mimetype or "application/octet-stream"
    key  = f"{folder.strip('/')}/{datetime.now().strftime('%Y%m%dT%H%M%S')}_{filename}"
    want_public = (os.getenv("S3_PUBLIC_READ", "0") == "1") and public
    put_kwargs = {"Bucket": bucket, "Key": key, "Body": raw, "ContentType": mime}
    if want_public:
        put_kwargs["ACL"] = "public-read"
    try:
        s3.put_object(**put_kwargs)
    except Exception as e:
        try:
            if "AccessDenied" in str(e) or "InvalidArgument" in str(e):
                s3.put_object(Bucket=bucket, Key=key, Body=raw, ContentType=mime)
            else:
                raise
        except Exception:
            app.logger.exception("Fallo guardando en S3 (reintento sin ACL)")
            raise
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
    ruta = os.path.relpath(path, root).replace("\\", "/")
    return ruta, mime, size

def _save_file(*, file_storage, folder: str, public: bool = True):
    try:
        if (os.getenv("S3_BUCKET") or os.getenv("S3_BUCKET_NAME")):
            return _save_file_to_s3(file_storage=file_storage, folder=folder, public=public)
    except Exception:
        app.logger.exception("Fallo guardando en S3")
        if FORCE_S3:
            raise
    return _save_file_to_local(file_storage=file_storage, folder=folder)

def _upload_bytes_to_s3(bucket: str, key: str, raw: bytes, mime: str = "text/plain", want_public: bool = False):
    s3 = _get_s3_client()
    put_kwargs = {"Bucket": bucket, "Key": key, "Body": raw, "ContentType": mime}
    if want_public:
        put_kwargs["ACL"] = "public-read"
    try:
        s3.put_object(**put_kwargs)
    except Exception as e:
        if "AccessDenied" in str(e) or "InvalidArgument" in str(e):
            put_kwargs.pop("ACL", None)
            s3.put_object(**put_kwargs)
        else:
            raise

def _s3_key_for_submission(form_slug: str, folio, email, ext: str) -> str:
    prefix = os.getenv("S3_DOC_PREFIX", "").lstrip("/")
    if folio:
        base = str(folio).upper().replace(" ", "_")
    elif email:
        base = str(email).lower().replace("@", "_at_").replace(".", "_")
    else:
        base = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}{form_slug}/{base}.{ext}".lstrip("/")

def _serialize_submission_to_txt(title: str, data: dict, files_meta: list) -> bytes:
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(f"{title}")
    lines.append(f"Fecha local: {now}")
    lines.append("-" * 60)
    lines.append("CAMPOS DEL FORMULARIO:")
    for k, v in data.items():
        if isinstance(v, (list, tuple)):
            v = ", ".join([str(x) for x in v])
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("ADJUNTOS:")
    if files_meta:
        for f in files_meta:
            lines.append(f"- nombre: {f.get('filename')}  mime: {f.get('content_type')}  bytes: {f.get('size','?')}")
    else:
        lines.append("- (sin adjuntos)")
    lines.append("-" * 60)
    return ("\n".join(lines) + "\n").encode("utf-8")

def _collect_request_data():
    data = request.get_json(silent=True) or {}
    for k in request.form:
        if k not in data:
            vals = request.form.getlist(k)
            data[k] = vals if len(vals) > 1 else request.form.get(k)
    files_meta = []
    for k in request.files:
        fs = request.files.get(k)
        if not fs or fs.filename == "":
            continue
        filename = secure_filename(fs.filename)
        files_meta.append({
            "key": k, "file_storage": fs, "filename": filename,
            "content_type": fs.mimetype or "application/octet-stream"
        })
    return data, files_meta

def _upload_attachments_to_s3(bucket: str, prefix_key: str, files_meta: list):
    if not files_meta:
        return []
    s3 = _get_s3_client()
    uploaded = []
    for meta in files_meta:
        fs = meta["file_storage"]; filename = meta["filename"]; content_type = meta["content_type"]
        key = f"{os.path.splitext(prefix_key)[0]}/adjuntos/{filename}"
        fs.stream.seek(0); raw = fs.read()
        s3.put_object(Bucket=bucket, Key=key, Body=raw, ContentType=content_type)
        uploaded.append({"key": key, "filename": filename, "content_type": content_type, "size": len(raw)})
    return uploaded

def save_submission_bundle(form_slug: str, title: str, folio=None, email=None, upload_attachments: bool = True):
    bucket = _current_bucket()
    want_public = (os.getenv("DOC_DEFAULT_PUBLIC", "false").lower() == "true")
    data, files_meta = _collect_request_data()
    txt = _serialize_submission_to_txt(title, data, files_meta)
    key_txt = _s3_key_for_submission(form_slug=form_slug, folio=folio, email=email, ext="txt")
    _upload_bytes_to_s3(bucket=bucket, key=key_txt, raw=txt, mime="text/plain", want_public=want_public)
    uploaded_files = _upload_attachments_to_s3(bucket=bucket, prefix_key=key_txt, files_meta=files_meta) if upload_attachments else []
    return {"doc_key": key_txt, "uploaded_files": uploaded_files, "data": data}

# ===== Health & home
@bp.route("/health")
def healthcheck():
    return jsonify({"status": "ok"}), 200

@bp.route("/")
def home():
    return render_template("index.html")

# ===== BD helpers
def _insert_document_with_folio(*, folio, tipo_usuario, usuario_id, tipo_documento, ruta, nombre_archivo, mime, size):
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
    sql = text(f"""
        INSERT INTO public.{tabla} (folio)
        VALUES (:folio)
        ON CONFLICT (folio) DO UPDATE SET folio = EXCLUDED.folio
        RETURNING id;
    """)
    row = db.session.execute(sql, {"folio": folio}).first()
    return row[0]

def _upsert_arrendador_datos(datos: dict):
    sql = text("""
        INSERT INTO public.arrendadores(
            folio, nombre, correo, direccion_actual, rfc, curp, telefono,
            banco, titular_cuenta, cuenta_bancaria, clabe_interbancaria,
            direccion, tipo_inmueble, superficie_terreno, metros_construidos,
            habitaciones, banos, estacionamientos, uso_suelo, cuenta_predial,
            cuenta_agua, servicios_pagan, caracteristicas, inventario,
            precio_renta, fecha_inicio_renta, fecha_firma_contrato, updated_at
        ) VALUES (
            :folio, :nombre, :correo, :direccion_actual, :rfc, :curp, :telefono,
            :banco, :titular_cuenta, :cuenta_bancaria, :clabe_interbancaria,
            :direccion, :tipo_inmueble, :superficie_terreno, :metros_construidos,
            :habitaciones, :banos, :estacionamientos, :uso_suelo, :cuenta_predial,
            :cuenta_agua, :servicios_pagan, :caracteristicas, :inventario,
            :precio_renta, :fecha_inicio_renta, :fecha_firma_contrato, now()
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
            updated_at           = now();
    """)
    db.session.execute(sql, datos)

def _upsert_arrendatario_datos(datos: dict):
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

def _to_home(message: str, category: str = "success"):
    flash(message, category)
    return redirect(url_for("routes.home"))

# ===== Folios
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

@bp.get("/api/verificar-folio/<folio>")
def api_verificar_folio(folio):
    ok = _folio_activo((folio or "").upper())
    return jsonify({"ok": ok})

@bp.get("/validar_folio")
def validar_folio():
    folio = (request.args.get("folio") or "").strip().upper()
    return jsonify({"valido": _folio_activo(folio)})

@bp.get("/api/admin/folio-nuevo")
def api_admin_folio_nuevo():
    folio = _generar_folio_unico()
    return jsonify({"ok": True, "folio": folio})

# ===== Vistas: documentos propietario/inquilino
@bp.route("/documentos/propietario", methods=["GET", "POST"])
def subir_propietario():
    if request.method == "GET":
        return render_template("documentos_propietario.html")

    form = request.form
    folio = (form.get("folio") or "").strip().upper()
    if not FOLIO_RE.match(folio):
        return _to_home("Folio inválido. Verifica el formato AEPRA-YYYYMM-XXXX.", "danger")
    if not _folio_activo(folio):
        return _to_home("El folio no existe o está desactivado. Solicítalo a administración.", "danger")

    datos = {
        "folio": folio, "nombre": form.get("nombre"), "correo": form.get("correo"),
        "direccion_actual": form.get("direccion_actual"), "rfc": form.get("rfc"),
        "curp": form.get("curp"), "telefono": form.get("telefono"), "banco": form.get("banco"),
        "titular_cuenta": form.get("titular_cuenta"), "cuenta_bancaria": form.get("cuenta_bancaria"),
        "clabe_interbancaria": form.get("clabe_interbancaria"), "direccion": form.get("direccion"),
        "tipo_inmueble": form.get("tipo_inmueble"), "superficie_terreno": form.get("superficie_terreno"),
        "metros_construidos": form.get("metros_construidos"), "habitaciones": form.get("habitaciones"),
        "banos": form.get("banos"), "estacionamientos": form.get("estacionamientos"),
        "uso_suelo": form.get("uso_suelo"), "cuenta_predial": form.get("cuenta_predial"),
        "cuenta_agua": form.get("cuenta_agua"), "servicios_pagan": form.get("servicios_pagan"),
        "caracteristicas": form.get("caracteristicas"), "inventario": form.get("inventario"),
        "precio_renta": form.get("precio_renta"), "fecha_inicio_renta": form.get("fecha_inicio_renta"),
        "fecha_firma_contrato": form.get("fecha_firma_contrato"),
    }
    requeridos = ["nombre","correo","direccion_actual","rfc","curp","telefono",
                  "banco","titular_cuenta","cuenta_bancaria","clabe_interbancaria",
                  "direccion","precio_renta","fecha_inicio_renta","fecha_firma_contrato"]
    faltantes = [k for k in requeridos if not (datos.get(k) or "").strip()]
    if faltantes:
        return _to_home(f"Campos obligatorios faltantes: {', '.join(faltantes)}", "danger")

    try:
        _upsert_arrendador_datos(datos)
        arr_id = _get_or_create_usuario_id_por_folio(tabla="arrendadores", folio=folio)

        alias = {
            "boleta_predial": ["boleta_predial", "solicitud_propietario", "solicitud"],
            "identificacion": ["identificacion", "id_oficial"],
            "comprobante_domicilio": ["comprobante_domicilio", "comp_domicilio"],
            "escritura": ["escritura"],
            "contrato_poder": ["contrato_poder", "poder_notarial"],
            "folio_real": ["folio_real", "constancia_folio_real"],
        }
        requeridos_doc = {"boleta_predial", "identificacion", "comprobante_domicilio", "escritura", "folio_real"}
        guardados = []

        for logical, keys in alias.items():
            fs = next((request.files[k] for k in keys if k in request.files and request.files[k] and request.files[k].filename), None)
            if not fs:
                if logical in requeridos_doc:
                    raise ValueError(f"Falta archivo requerido: {logical.replace('_',' ')}")
                continue
            if not _ext_ok(fs.filename):
                raise ValueError(f"Extensión no permitida: {fs.filename}")

            ruta, mime, size = _save_file(file_storage=fs, folder=f"arrendador/{folio}/{arr_id}", public=True)
            _insert_document_with_folio(
                folio=folio, tipo_usuario="arrendador", usuario_id=arr_id,
                tipo_documento=logical, ruta=ruta, nombre_archivo=fs.filename, mime=mime, size=size
            )
            guardados.append(logical)

        _marcar_uso_folio(folio, "arrendador")
        db.session.commit()

        try:
            save_submission_bundle("propietario", "Formulario de Propietario", folio=folio, email=datos.get("correo"), upload_attachments=False)
        except Exception as e:
            app.logger.warning("Bundle TXT propietario no subido: %s", e)

        lista = ", ".join(guardados) if guardados else "ninguno"
        return _to_home(f"✅ Propietario guardado para <b>{folio}</b>. Documentos almacenados: <b>{len(guardados)}</b> ({lista}).","success")

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
    if not FOLIO_RE.match(folio):
        return _to_home("Folio inválido. Verifica el formato AEPRA-YYYYMM-XXXX.", "danger")
    if not _folio_activo(folio):
        return _to_home("El folio no existe o está desactivado. Solicítalo a administración.", "danger")

    try:
        inq_id = _get_or_create_usuario_id_por_folio(tabla="arrendatarios", folio=folio)

        datos_inq = {
            "folio": folio,
            "lugar_nacimiento": (form.get("lugar_nacimiento") or None),
            "fecha_nacimiento": (form.get("fecha_nacimiento") or None)
        }
        _upsert_arrendatario_datos(datos_inq)

        guardados = []
        for clave, fs in request.files.items():
            if not fs or fs.filename == "":
                continue
            if not _ext_ok(fs.filename):
                raise ValueError(f"Extensión no permitida: {fs.filename}")
            ruta, mime, size = _save_file(file_storage=fs, folder=f"arrendatario/{folio}/{inq_id}", public=True)
            _insert_document_with_folio(
                folio=folio, tipo_usuario="arrendatario", usuario_id=inq_id,
                tipo_documento=clave, ruta=ruta, nombre_archivo=fs.filename, mime=mime, size=size
            )
            guardados.append(clave)

        _marcar_uso_folio(folio, "arrendatario")
        db.session.commit()

        try:
            correo = (form.get("correo") or None)
            save_submission_bundle("inquilino","Formulario de Inquilino", folio=folio, email=correo, upload_attachments=False)
        except Exception as e:
            app.logger.warning("Bundle TXT inquilino no subido: %s", e)

        lista = ", ".join(guardados) if guardados else "ninguno"
        return _to_home(f"✅ Inquilino guardado para <b>{folio}</b>. Documentos almacenados: <b>{len(guardados)}</b> ({lista}).","success")

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Error guardando inquilino")
        return _to_home(f"❌ No se pudieron guardar documentos de inquilino ({folio}). Detalle: {e}", "danger")

# ===== Admin / login
ADMIN_USER = (os.getenv("ADMIN_USER") or "").strip()
ADMIN_PASS = (os.getenv("ADMIN_PASS") or "").strip()
if not ADMIN_USER or not ADMIN_PASS:
    ADMIN_USER = "admin"
    ADMIN_PASS = "admin123"

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("routes.admin"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if username == ADMIN_USER and password == ADMIN_PASS:
            # Guardamos en sesión el MISMO id que espera el user_loader de app/__init__.py
            login_user(SimpleUser(ADMIN_USER), remember=True)
            flash("Bienvenido, acceso concedido.", "success")
            dest = request.args.get("next") or url_for("routes.admin")
            return redirect(dest)
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

# ===== API admin
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
            "tipo_usuario": r[0], "tipo_documento": r[1], "nombre_archivo": r[2],
            "mime": r[3], "tamano_bytes": int(r[4]) if r[4] is not None else None,
            "ruta": r[5], "fecha_subida": r[6].isoformat() if r[6] else None,
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
        fi = date(y, m, d); ff = date(y + 1, m, d)
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
    try:
        max_meses = int(request.args.get("max_meses", 3))
    except ValueError:
        max_meses = 3
    incluir_vencidas = request.args.get("incluir_vencidas", "0") == "1"

    sql = text("""
        with pol as (
          select folio, fecha_inicio, fecha_fin,
            (extract(year from age(fecha_fin, current_date))::int * 12)
          + (extract(month from age(fecha_fin, current_date))::int) as meses_restantes,
            (fecha_fin - current_date) as dias_restantes
          from polizas
        )
        select folio, to_char(fecha_inicio,'YYYY-MM-DD') as fecha_inicio,
               to_char(fecha_fin,'YYYY-MM-DD') as fecha_fin,
               meses_restantes, dias_restantes
        from pol
        where meses_restantes <= :max_meses
          and (:incl = true or dias_restantes >= 0)
        order by dias_restantes asc, folio asc
        limit 500
    """)
    rows = db.session.execute(sql, {"max_meses": max_meses, "incl": incluir_vencidas}).mappings().all()
    items = [{"folio": r["folio"], "fecha_inicio": r["fecha_inicio"], "fecha_fin": r["fecha_fin"],
              "meses_restantes": int(r["meses_restantes"]), "dias_restantes": int(r["dias_restantes"])} for r in rows]
    return jsonify({"items": items, "max_meses": max_meses, "incluir_vencidas": incluir_vencidas})

# ===== Otras páginas
@bp.route("/terminos-mascotas")
def terminos_mascotas():
    return render_template("terminos_mascotas.html")

@bp.route("/politicas")
def politicas():
    return render_template("privacidad.html")

@bp.route("/privacidad")
def privacidad_alias():
    return redirect(url_for("routes.politicas"), code=301)

# ===== Debug
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
        bucket = _current_bucket()
        s3 = _get_s3_client()
        s3.head_bucket(Bucket=bucket)
        return jsonify({"ok": True, "bucket": bucket, "checked_at": datetime.utcnow().isoformat()+"Z"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@bp.get("/api/debug/whoami")
def debug_whoami():
    return jsonify({
        "authenticated": bool(getattr(current_user, "is_authenticated", False)),
        "user_id": getattr(current_user, "id", None),
        "session_keys": {k: session.get(k) for k in ["_user_id", "_fresh"]},
    })

# ===== Contacto (FIX del if)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@bp.route("/contacto", methods=["GET", "POST"])
def contacto():
    if request.method == "POST":
        nombre   = (request.form.get("nombre") or "").strip()
        correo   = (request.form.get("correo") or "").strip()
        telefono = (request.form.get("telefono") or "").strip()
        mensaje  = (request.form.get("mensaje") or "").strip()
        if not nombre or not correo or not mensaje:  # <- FIX aquí
            flash("Nombre, correo y mensaje son obligatorios.", "warning")
            return render_template("contacto.html", form=request.form), 400
        if not EMAIL_RE.match(correo):
            flash("Correo no válido.", "warning")
            return render_template("contacto.html", form=request.form), 400
        try:
            m = MensajeContacto(nombre=nombre, correo=correo, telefono=telefono or None, mensaje=mensaje)
            db.session.add(m); db.session.commit()
            try:
                save_submission_bundle("contacto","Formulario de Contacto", folio=None, email=correo, upload_attachments=True)
            except Exception as e:
                app.logger.warning("No se pudo subir el documento de contacto a S3: %s", e)
            flash("¡Gracias! Tu mensaje fue enviado.", "success")
            return redirect(url_for("routes.contacto"))
        except Exception as e:
            db.session.rollback(); app.logger.exception("Error guardando contacto: %s", e)
            flash("Ocurrió un error al guardar tu mensaje. Intenta de nuevo.", "danger")
            return render_template("contacto.html", form=request.form), 500
    return render_template("contacto.html")

# ===== Asesores / referenciados / asignaciones / filtros =====
def _row_to_dict(row):
    try:
        return dict(row._mapping)
    except Exception:
        return dict(row)

@bp.route("/api/asesores", methods=["GET", "POST"])
def api_asesores():
    if request.method == "GET":
        sql = text("SELECT id, nombre, created_at FROM public.asesores ORDER BY nombre ASC")
        res = db.session.execute(sql).all()
        return jsonify([_row_to_dict(r) for r in res]), 200
    data = request.get_json(silent=True) or request.form or {}
    nombre = (data.get("nombre") or "").strip()
    if not nombre:
        return jsonify({"ok": False, "error": "nombre requerido"}), 400
    try:
        sql = text("""
            INSERT INTO public.asesores(nombre)
            VALUES (:nombre)
            ON CONFLICT (nombre)
            DO UPDATE SET nombre = EXCLUDED.nombre
            RETURNING id, nombre, created_at
        """)
        row = db.session.execute(sql, {"nombre": nombre}).first()
        db.session.commit()
        return jsonify({"ok": True, "asesor": _row_to_dict(row)}), 200
    except Exception as e:
        db.session.rollback(); app.logger.exception("api_asesores POST error: %s", e)
        return jsonify({"ok": False, "error": "error guardando asesor"}), 500

@bp.route("/api/referenciados", methods=["POST"])
def api_referenciados_add():
    data = request.get_json(silent=True) or request.form or {}
    asesor_id = data.get("asesor_id")
    nombre = (data.get("nombre") or "").strip()
    if not asesor_id or not nombre:
        return jsonify({"ok": False, "error": "asesor_id y nombre requeridos"}), 400
    try:
        sql = text("""
            INSERT INTO public.asesores_referenciados(asesor_id, nombre)
            VALUES (:asesor_id, :nombre)
            ON CONFLICT (asesor_id, nombre) DO NOTHING
            RETURNING id, asesor_id, nombre, created_at
        """)
        row = db.session.execute(sql, {"asesor_id": int(asesor_id), "nombre": nombre}).first()
        if row is None:
            row = db.session.execute(text("""
                SELECT id, asesor_id, nombre, created_at
                FROM public.asesores_referenciados
                WHERE asesor_id=:asesor_id AND nombre=:nombre
            """), {"asesor_id": int(asesor_id), "nombre": nombre}).first()
        db.session.commit()
        disp = db.session.execute(text("""
            SELECT UPPER(SUBSTRING(a.nombre FROM 1 FOR 1)) || '. ' || :nombre AS display
            FROM public.asesores a WHERE a.id=:asesor_id
        """), {"asesor_id": int(asesor_id), "nombre": nombre}).scalar()
        out = _row_to_dict(row); out["display"] = disp
        return jsonify({"ok": True, "referenciado": out}), 200
    except Exception as e:
        db.session.rollback(); app.logger.exception("api_referenciados POST error: %s", e)
        return jsonify({"ok": False, "error": "error guardando referenciado"}), 500

@bp.route("/api/asesores/<int:asesor_id>/referenciados", methods=["GET"])
def api_referenciados_list(asesor_id: int):
    sql = text("""
        SELECT r.id, r.asesor_id, r.nombre,
               (UPPER(SUBSTRING(a.nombre FROM 1 FOR 1)) || '. ' || r.nombre) AS display,
               r.created_at
        FROM public.asesores_referenciados r
        JOIN public.asesores a ON a.id = r.asesor_id
        WHERE r.asesor_id=:asesor_id
        ORDER BY r.nombre ASC
    """)
    res = db.session.execute(sql, {"asesor_id": asesor_id}).all()
    return jsonify([_row_to_dict(r) for r in res]), 200

@bp.route("/api/asesores/<int:asesor_id>/destinatarios", methods=["GET"])
def api_destinatarios(asesor_id: int):
    sql = text("""
        SELECT * FROM public.v_destinatarios
        WHERE asesor_id = :asesor_id
        ORDER BY (tipo != 'asesor'), display ASC
    """)
    res = db.session.execute(sql, {"asesor_id": asesor_id}).all()
    return jsonify([_row_to_dict(r) for r in res]), 200

@bp.route("/api/asignaciones", methods=["POST"])
def api_asignar_folio():
    data = request.get_json(silent=True) or request.form or {}
    folio = (data.get("folio") or "").strip().upper()
    asesor_id_raw = data.get("asesor_id")
    referenciado_id_raw = data.get("referenciado_id")

    def norm_id(val):
        if val is None: return None
        if isinstance(val, int): return val if val > 0 else None
        s = str(val).strip().lower()
        if s in ("", "0", "null", "none", "undefined", "false"): return None
        return int(s)

    try:
        asesor_id = norm_id(asesor_id_raw)
        referenciado_id = norm_id(referenciado_id_raw)
    except Exception:
        return jsonify({"ok": False, "error": "IDs inválidos en la solicitud"}), 400

    if not folio or not asesor_id:
        return jsonify({"ok": False, "error": "folio y asesor_id son requeridos"}), 400
    if not FOLIO_RE.match(folio):
        return jsonify({"ok": False, "error": "Folio inválido (AEPRA-YYYYMM-XXXX)"}), 400

    try:
        if referenciado_id:
            ok = db.session.execute(text("""
                SELECT 1 FROM public.asesores_referenciados
                WHERE id=:rid AND asesor_id=:aid
            """), {"rid": referenciado_id, "aid": asesor_id}).first()
            if not ok:
                return jsonify({"ok": False, "error": "El referenciado no pertenece al asesor elegido"}), 400

        row = db.session.execute(text("""
            INSERT INTO public.folios_asignaciones(folio, asesor_id, referenciado_id)
            VALUES (:folio, :asesor_id, :referenciado_id)
            ON CONFLICT (folio)
            DO UPDATE SET asesor_id=EXCLUDED.asesor_id,
                          referenciado_id=EXCLUDED.referenciado_id,
                          assigned_at=now()
            RETURNING id
        """), {"folio": folio, "asesor_id": asesor_id, "referenciado_id": referenciado_id}).first()
        db.session.commit()
        return jsonify({"ok": True, "id": row.id if row else None}), 200

    except Exception as e:
        db.session.rollback(); app.logger.exception("api_asignar_folio POST error: %s", e)
        return jsonify({"ok": False, "error": "error guardando asignación"}), 500

@bp.route("/api/asignaciones/recientes", methods=["GET"])
def api_asignaciones_recientes():
    sql = text("""
        SELECT
          fa.id, fa.folio, fa.asesor_id, a.nombre AS asesor_nombre, fa.referenciado_id,
          CASE WHEN fa.referenciado_id IS NULL THEN a.nombre
               ELSE UPPER(SUBSTRING(a.nombre FROM 1 FOR 1)) || '. ' || ar.nombre END AS asignado_a,
          fa.assigned_at
        FROM public.folios_asignaciones fa
        JOIN public.asesores a ON a.id = fa.asesor_id
        LEFT JOIN public.asesores_referenciados ar ON ar.id = fa.referenciado_id
        ORDER BY fa.assigned_at DESC
        LIMIT 50
    """)
    res = db.session.execute(sql).all()
    return jsonify([_row_to_dict(r) for r in res]), 200

@bp.route("/api/folios/poliza", methods=["POST"])
def api_folios_poliza_upsert():
    data = request.get_json(silent=True) or request.form or {}
    folio = (data.get("folio") or "").strip().upper()
    tipo  = (data.get("tipo") or "").strip().title()

    if not folio or not FOLIO_RE.match(folio):
        return jsonify({"ok": False, "error": "Folio inválido. Formato esperado: AEPRA-YYYYMM-XXXX"}), 400
    if tipo not in ALLOWED_TIPOS_POLIZA:
        return jsonify({"ok": False, "error": f"Tipo inválido. Usa: {', '.join(sorted(ALLOWED_TIPOS_POLIZA))}"}), 400

    try:
        row = db.session.execute(text("""
            INSERT INTO public.folios_poliza (folio, tipo)
            VALUES (:folio, CAST(:tipo AS poliza_tipo))
            ON CONFLICT (folio) DO UPDATE
               SET tipo = EXCLUDED.tipo,
                   assigned_at = now()
            RETURNING folio, tipo::text AS tipo, assigned_at;
        """), {"folio": folio, "tipo": tipo}).mappings().first()
        db.session.commit()
        return jsonify({
            "ok": True,
            "folio": row["folio"],
            "tipo": row["tipo"],
            "assigned_at": row["assigned_at"].isoformat() if hasattr(row["assigned_at"], "isoformat") else row["assigned_at"]
        })
    except Exception as e:
        db.session.rollback(); app.logger.exception("api_folios_poliza_upsert error: %s", e)
        return jsonify({"ok": False, "error": "Error guardando tipo de póliza"}), 500

@bp.route("/api/folios/poliza/recientes", methods=["GET"])
def api_folios_poliza_recientes():
    sql = text("""
        SELECT folio, tipo::text AS tipo, assigned_at
        FROM public.folios_poliza
        ORDER BY assigned_at DESC
        LIMIT 50;
    """)
    rows = db.session.execute(sql).mappings().all()
    out = []
    for r in rows:
        assigned = r["assigned_at"]
        out.append({
            "folio": r["folio"],
            "tipo": r["tipo"],
            "assigned_at": assigned.isoformat() if hasattr(assigned, "isoformat") else assigned
        })
    return jsonify(out)

@bp.route("/api/folios", methods=["GET"])
def api_filtrar_folios():
    asesor_id_raw = request.args.get("asesor_id")
    referenciado_id_raw = request.args.get("referenciado_id")
    q = (request.args.get("q") or "").strip()

    def norm_id(val):
        if val is None: return None
        if isinstance(val, int): return val if val > 0 else None
        s = str(val).strip().lower()
        if s in ("", "0", "null", "none", "undefined", "false"): return None
        return int(s)

    try:
        asesor_id = norm_id(asesor_id_raw)
        referenciado_id = norm_id(referenciado_id_raw)
    except Exception:
        return jsonify({"ok": False, "error": "IDs inválidos en la solicitud"}), 400

    base = """
        SELECT
          fa.id, fa.folio, fa.asesor_id, a.nombre AS asesor_nombre, fa.referenciado_id,
          CASE
            WHEN fa.referenciado_id IS NULL THEN a.nombre
            ELSE UPPER(SUBSTRING(a.nombre FROM 1 FOR 1)) || '. ' || ar.nombre
          END AS asignado_a,
          fa.assigned_at
        FROM public.folios_asignaciones fa
        JOIN public.asesores a ON a.id = fa.asesor_id
        LEFT JOIN public.asesores_referenciados ar ON ar.id = fa.referenciado_id
        WHERE 1=1
    """
    params = {}
    if asesor_id:
        base += " AND fa.asesor_id = :asesor_id"; params["asesor_id"] = asesor_id
    if referenciado_id:
        base += " AND fa.referenciado_id = :referenciado_id"; params["referenciado_id"] = referenciado_id
    if q:
        base += """
            AND (
              fa.folio ILIKE :q OR a.nombre ILIKE :q OR
              (CASE WHEN fa.referenciado_id IS NULL THEN a.nombre
                    ELSE UPPER(SUBSTRING(a.nombre FROM 1 FOR 1)) || '. ' || ar.nombre END) ILIKE :q
            )
        """
        params["q"] = f"%{q}%"
    base += " ORDER BY fa.assigned_at DESC LIMIT 200"
    res = db.session.execute(text(base), params).all()
    return jsonify([_row_to_dict(r) for r in res]), 200
