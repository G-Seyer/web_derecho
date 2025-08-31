# app/routes.py
import os
import re
import mimetypes
from datetime import datetime
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, current_app as app, Response
)
from sqlalchemy import text
from werkzeug.utils import secure_filename

from app import db
from app.models import MensajeContacto

bp = Blueprint("routes", __name__)

# ---------------- Health ----------------
@bp.route("/health")
def healthcheck():
    return jsonify({"ok": True, "ts": datetime.utcnow().isoformat()})


# ---------------- Helpers ----------------
def _to_home(msg: str, cat: str = "info"):
    if msg:
        flash(msg, cat)
    return redirect(url_for("routes.home"))

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from flask_login import current_user
        if not current_user.is_authenticated:
            flash("Debes iniciar sesión para acceder.", "warning")
            return redirect(url_for("routes.login"))
        return view(*args, **kwargs)
    return wrapped

def _to_iso_date(s: str):
    s = (s or "").strip()
    if not s:
        return None
    # dd/mm/yyyy
    if re.match(r"^\d{2}/\d{2}/\d{4}$", s):
        d, m, y = s.split("/")
        return f"{y}-{m}-{d}"
    # yyyy-mm-dd
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return s
    return None

def _to_int(s):
    try:
        return int((s or "").strip())
    except Exception:
        return None

def _to_decimal(s):
    s = (s or "").strip().replace(",", "")
    if not s:
        return None
    try:
        return float(s)
    except Exception:
        return None

def _parse_lugar_fecha_combinado(s: str):
    """
    Entrada: 'CDMX, 01/01/1980' -> ('CDMX', '1980-01-01')
    Si no separa, retorna (texto, None)
    """
    if not s:
        return None, None
    txt = s.strip()
    if "," in txt:
        lugar, fecha_txt = txt.rsplit(",", 1)
        return (lugar.strip() or None), _to_iso_date(fecha_txt.strip())
    return txt, None


# ---------------- Páginas ----------------
@bp.route("/")
def home():
    return render_template("index.html")


# ---------------- Storage (S3 / local) ----------------
FORCE_S3 = os.getenv("FORCE_S3", "0") == "1"
ALLOWED_EXTS = {"pdf", "png", "jpg", "jpeg", "webp", "heic", "heif"}

def _ext_ok(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[-1].lower() in ALLOWED_EXTS

def _get_s3_client():
    try:
        import boto3  # type: ignore
        have_keys = bool(os.getenv("AWS_ACCESS_KEY_ID")) and bool(os.getenv("AWS_SECRET_ACCESS_KEY"))
        if not have_keys:
            return None
        return boto3.client("s3")
    except Exception:
        return None

def _save_file(file_storage, folder: str, public: bool = True):
    filename = secure_filename(file_storage.filename)
    if not _ext_ok(filename):
        raise ValueError("Formato de archivo no permitido.")

    mime = file_storage.mimetype or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    size = 0

    s3 = None if not FORCE_S3 else _get_s3_client()
    if s3:
        bucket = os.getenv("S3_BUCKET", "")
        key = f"{folder}/{filename}"
        file_storage.stream.seek(0)
        s3.upload_fileobj(
            Fileobj=file_storage.stream,
            Bucket=bucket,
            Key=key,
            ExtraArgs={"ContentType": mime, "ACL": "public-read" if public else "private"},
        )
        ruta = f"s3://{bucket}/{key}"
        try:
            size = file_storage.content_length or 0
        except Exception:
            pass
        return ruta, mime, size

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    upload_dir = os.path.join(base_dir, "uploads", folder)
    os.makedirs(upload_dir, exist_ok=True)
    path = os.path.join(upload_dir, filename)
    file_storage.save(path)
    try:
        size = os.path.getsize(path)
    except Exception:
        pass
    ruta = f"/uploads/{folder}/{filename}"
    return ruta, mime, size


# ---------------- DB helpers ----------------
def _folio_activo(folio: str) -> bool:
    row = db.session.execute(text("SELECT activo FROM public.folios WHERE folio = :f LIMIT 1"), {"f": folio}).fetchone()
    return bool(row and row[0])

def _marcar_uso_folio(folio: str, tipo_usuario: str):
    # tipo_usuario: 'arrendatario' | 'arrendador'
    col = "usos_arrendatario" if tipo_usuario == "arrendatario" else "usos_arrendador"
    db.session.execute(text(f"""
        UPDATE public.folios
           SET {col} = {col} + 1,
               ultima_actividad_at = now()
         WHERE folio = :f
    """), {"f": folio})

def _get_or_create_usuario_id_por_folio(tabla: str, folio: str) -> int:
    row = db.session.execute(text(f"SELECT id FROM public.{tabla} WHERE folio = :f LIMIT 1"), {"f": folio}).fetchone()
    if row:
        return int(row[0])
    rid = db.session.execute(
        text(f"INSERT INTO public.{tabla}(folio, created_at, updated_at) VALUES (:f, now(), now()) RETURNING id"),
        {"f": folio}
    ).scalar()
    return int(rid)

def _insert_document_with_folio(*, folio: str, tipo_usuario: str, usuario_id: int,
                                tipo_documento: str, ruta: str, nombre_archivo: str,
                                mime: str, size: int):
    sql = text("""
        INSERT INTO public.documentos(
            folio, tipo_usuario, usuario_id, tipo_documento,
            ruta, nombre_archivo, mime, content_type, tamano_bytes, fecha_subida
        ) VALUES (
            :folio, :tipo_usuario, :usuario_id, :tipo_documento,
            :ruta, :nombre_archivo, :mime, :content_type, :tamano_bytes, now()
        )
        ON CONFLICT (tipo_usuario, usuario_id, tipo_documento)
        DO UPDATE SET
            ruta           = EXCLUDED.ruta,
            nombre_archivo = EXCLUDED.nombre_archivo,
            mime           = EXCLUDED.mime,
            content_type   = EXCLUDED.content_type,
            tamano_bytes   = EXCLUDED.tamano_bytes,
            fecha_subida   = now()
    """)
    db.session.execute(sql, {
        "folio": folio, "tipo_usuario": tipo_usuario, "usuario_id": usuario_id,
        "tipo_documento": tipo_documento, "ruta": ruta, "nombre_archivo": nombre_archivo,
        "mime": mime, "content_type": mime, "tamano_bytes": size
    })


# ---------------- API: verificar folio ----------------
@bp.route("/api/verificar-folio/<folio>")
def api_verificar_folio(folio):
    f = (folio or "").strip().upper()
    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", f):
        return jsonify({"ok": False, "msg": "Formato inválido (AEPRA-YYYYMM-XXXX)."})
    ok = _folio_activo(f)
    return jsonify({"ok": bool(ok), "msg": "Folio verificado" if ok else "Folio no activo"})


# ---------------- Contacto / Políticas ----------------
@bp.route("/contacto", methods=["GET", "POST"])
def contacto():
    if request.method == "GET":
        return render_template("contacto.html")
    nombre = request.form.get("nombre")
    correo = request.form.get("correo")
    telefono = request.form.get("telefono")
    mensaje = request.form.get("mensaje")
    if not nombre or not correo or not mensaje:
        flash("Completa nombre, correo y mensaje.", "warning")
        return redirect(url_for("routes.contacto"))
    m = MensajeContacto(nombre=nombre, correo=correo, telefono=telefono, mensaje=mensaje)
    db.session.add(m)
    db.session.commit()
    flash("Gracias, te responderemos pronto.", "success")
    return redirect(url_for("routes.contacto"))

@bp.route("/privacidad")
def privacidad():
    return render_template("privacidad.html")

@bp.route("/politicas")
def politicas():
    return render_template("privacidad.html")

@bp.route("/politicas/mascotas")
def politicas_mascotas():
    return render_template("terminos_mascotas.html")

@bp.route("/terminos/mascotas")
def terminos_mascotas():
    from flask import redirect
    return redirect(url_for("routes.politicas_mascotas"), code=302)


# ---------------- Login / Admin ----------------
from flask_login import login_user, logout_user, UserMixin

class AdminUser(UserMixin):
    def __init__(self, user_id="admin"):
        self.id = user_id

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "")
    if username == ADMIN_USER and password == ADMIN_PASS:
        login_user(AdminUser(ADMIN_USER))
        flash("Bienvenido.", "success")
        return redirect(url_for("routes.admin"))
    flash("Usuario o contraseña incorrectos.", "danger")
    return redirect(url_for("routes.login"))

@bp.route("/logout")
def logout():
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("routes.home"))

@bp.route("/admin")
@login_required
def admin():
    asesores = db.session.execute(text("SELECT id, nombre FROM public.asesores ORDER BY nombre")).fetchall()
    referenciados = db.session.execute(text("""
        SELECT r.id, COALESCE(a.nombre,'') || ' - ' || r.nombre as nombre
          FROM public.asesores_referenciados r
          LEFT JOIN public.asesores a ON a.id = r.asesor_id
         ORDER BY a.nombre, r.nombre
    """)).fetchall()
    polizas = [
        ("tradicional", "Tradicional"),
        ("intermedia", "Intermedia"),
        ("plus", "Plus"),
        ("mascota", "Mascota")
    ]
    return render_template("admin.html", asesores=asesores, referenciados=referenciados, polizas=polizas)

# ----- CRUD Asesores -----
@bp.route("/admin/asesores/crear", methods=["POST"])
@login_required
def crear_asesor():
    nombre = (request.form.get("nombre") or "").strip()
    if not nombre:
        return _to_home("Nombre de asesor requerido.", "warning")
    db.session.execute(text(
        "INSERT INTO public.asesores(nombre, created_at, updated_at) VALUES (:n, now(), now())"
    ), {"n": nombre})
    db.session.commit()
    flash("Asesor registrado.", "success")
    return redirect(url_for("routes.admin"))

@bp.route("/admin/asesores/referenciados/crear", methods=["POST"])
@login_required
def crear_asesor_referenciado():
    asesor_id = request.form.get("asesor_id")
    nombre = (request.form.get("nombre") or "").strip()
    if not asesor_id or not nombre:
        return _to_home("Selecciona asesor y escribe el nombre del referenciado.", "warning")
    row = db.session.execute(text("SELECT nombre FROM public.asesores WHERE id=:i"), {"i": asesor_id}).fetchone()
    if not row:
        return _to_home("Asesor no encontrado.", "danger")
    inicial = (row[0] or "").strip()[:1].upper()
    nombre_marcado = f"{inicial}. {nombre}"
    db.session.execute(text("""
        INSERT INTO public.asesores_referenciados(asesor_id, nombre, created_at, updated_at)
        VALUES (:a, :n, now(), now())
    """), {"a": asesor_id, "n": nombre_marcado})
    db.session.commit()
    flash("Referenciado registrado.", "success")
    return redirect(url_for("routes.admin"))

# ----- Asignación de folios a asesor/referenciado -----
@bp.route("/admin/folios/asignar", methods=["POST"])
@login_required
def asignar_folio():
    folio = (request.form.get("folio") or "").strip().upper()
    asignado_a = request.form.get("asignado_a")  # "asesor:<id>" o "ref:<id>"
    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return _to_home("Folio inválido.", "warning")
    if not asignado_a:
        return _to_home("Selecciona asesor o referenciado.", "warning")

    tipo, _id = asignado_a.split(":")
    if tipo == "asesor":
        db.session.execute(text("""
            INSERT INTO public.folios_asignados(folio, asesor_id, created_at)
            VALUES (:f, :a, now())
            ON CONFLICT (folio) DO UPDATE SET asesor_id=EXCLUDED.asesor_id
        """), {"f": folio, "a": _id})
    else:
        db.session.execute(text("""
            INSERT INTO public.folios_asignados(folio, referenciado_id, created_at)
            VALUES (:f, :r, now())
            ON CONFLICT (folio) DO UPDATE SET referenciado_id=EXCLUDED.referenciado_id
        """), {"f": folio, "r": _id})
    db.session.commit()
    flash("Folio asignado.", "success")
    return redirect(url_for("routes.admin"))

# ----- Asignar tipo de póliza a un folio -----
@bp.route("/admin/folios/poliza", methods=["POST"])
@login_required
def asignar_poliza_a_folio():
    folio = (request.form.get("folio_poliza") or "").strip().upper()
    tipo_poliza = request.form.get("tipo_poliza")  # tradicional | intermedia | plus | mascota
    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return _to_home("Folio inválido.", "warning")
    if tipo_poliza not in {"tradicional", "intermedia", "plus", "mascota"}:
        return _to_home("Tipo de póliza inválido.", "warning")
    db.session.execute(text("""
        INSERT INTO public.folios_poliza(folio, tipo_poliza, created_at, updated_at)
        VALUES (:f, :t, now(), now())
        ON CONFLICT (folio) DO UPDATE SET tipo_poliza = EXCLUDED.tipo_poliza, updated_at = now()
    """), {"f": folio, "t": tipo_poliza})
    db.session.commit()
    flash("Tipo de póliza asignado al folio.", "success")
    return redirect(url_for("routes.admin"))

# ----- Filtro de folios por asesor/referenciado -----
@bp.route("/admin/folios/filtrar")
@login_required
def filtrar_folios():
    quien = request.args.get("quien")  # "asesor:<id>" o "ref:<id>"
    if not quien:
        return jsonify([])
    tipo, _id = quien.split(":")
    if tipo == "asesor":
        rows = db.session.execute(text(
            "SELECT folio FROM public.folios_asignados WHERE asesor_id=:i ORDER BY folio DESC"
        ), {"i": _id}).fetchall()
    else:
        rows = db.session.execute(text(
            "SELECT folio FROM public.folios_asignados WHERE referenciado_id=:i ORDER BY folio DESC"
        ), {"i": _id}).fetchall()
    return jsonify([r[0] for r in rows])

# ----- Crear folio (JSON) -----
@bp.route("/api/admin/folio-nuevo", methods=["GET"])
@login_required
def api_admin_folio_nuevo():
    yyyymm = datetime.utcnow().strftime("%Y%m")
    folio = _generar_folio(prefijo="AEPRA", yyyymm=yyyymm)
    db.session.execute(text("""
        INSERT INTO public.folios (folio, activo)
        VALUES (:f, true)
        ON CONFLICT (folio) DO NOTHING
    """), {"f": folio})
    db.session.commit()
    return jsonify({"ok": True, "folio": folio})


# ---------------- Propietario (documentos) ----------------
def _upsert_arrendador_datos(datos: dict):
    sql = text("""
        INSERT INTO public.arrendadores(
            folio, nombre, correo, direccion, rfc, curp, telefono,
            lugar_nacimiento, fecha_nacimiento,
            inmueble_direccion, inmueble_tipo, inmueble_precio_renta,
            cuenta_bancaria, clabe, banco,
            boleta_predial, created_at, updated_at
        ) VALUES (
            :folio, :nombre, :correo, :direccion, :rfc, :curp, :telefono,
            :lugar_nacimiento, :fecha_nacimiento,
            :inmueble_direccion, :inmueble_tipo, :inmueble_precio_renta,
            :cuenta_bancaria, :clabe, :banco,
            :boleta_predial, now(), now()
        )
        ON CONFLICT (folio) DO UPDATE SET
            nombre = EXCLUDED.nombre,
            correo = EXCLUDED.correo,
            direccion = EXCLUDED.direccion,
            rfc = EXCLUDED.rfc,
            curp = EXCLUDED.curp,
            telefono = EXCLUDED.telefono,
            lugar_nacimiento = EXCLUDED.lugar_nacimiento,
            fecha_nacimiento = EXCLUDED.fecha_nacimiento,
            inmueble_direccion = EXCLUDED.inmueble_direccion,
            inmueble_tipo = EXCLUDED.inmueble_tipo,
            inmueble_precio_renta = EXCLUDED.inmueble_precio_renta,
            cuenta_bancaria = EXCLUDED.cuenta_bancaria,
            clabe = EXCLUDED.clabe,
            banco = EXCLUDED.banco,
            boleta_predial = EXCLUDED.boleta_predial,
            updated_at = now();
    """)
    db.session.execute(sql, datos)

@bp.route("/documentos/propietario", methods=["GET", "POST"])
def subir_propietario():
    if request.method == "GET":
        return render_template("documentos_propietario.html")

    form = request.form
    folio = (form.get("folio") or "").strip().upper()

    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return _to_home("Folio inválido. Verifica el formato AEPRA-YYYYMM-XXXX.", "danger")
    if not _folio_activo(folio):
        return _to_home("El folio no existe o está desactivado.", "danger")

    try:
        owner_id = _get_or_create_usuario_id_por_folio(tabla="arrendadores", folio=folio)

        datos_prop = {
            "folio": folio,
            "nombre": form.get("nombre"),
            "correo": form.get("correo"),
            "direccion": form.get("direccion_actual"),
            "rfc": form.get("rfc"),
            "curp": form.get("curp"),
            "telefono": form.get("telefono"),
            "lugar_nacimiento": form.get("lugar_nacimiento"),
            "fecha_nacimiento": _to_iso_date(form.get("fecha_nacimiento")),
            "inmueble_direccion": form.get("direccion"),
            "inmueble_tipo": form.get("tipo_inmueble"),
            "inmueble_precio_renta": _to_decimal(form.get("precio_renta")),
            "cuenta_bancaria": form.get("cuenta_bancaria"),
            "clabe": form.get("clabe_interbancaria"),
            "banco": form.get("banco"),
            "boleta_predial": form.get("boleta_predial"),
        }
        _upsert_arrendador_datos(datos_prop)

        campos_archivos = {
            "boleta_predial": "Boleta predial",
            "identificacion": "Identificación oficial (propietario)",
            "comprobante_domicilio": "Comprobante de domicilio (propietario)",
            "escritura": "Escritura del inmueble",
            "folio_real": "Constancia de folio real",
            "contrato_poder": "Contrato o poder notarial (si aplica)",
        }

        for field, etiqueta in campos_archivos.items():
            f = request.files.get(field)
            if not f or not getattr(f, "filename", ""):
                continue
            if not _ext_ok(f.filename):
                raise ValueError(f"Formato no permitido para '{etiqueta}'. Usa PDF/JPG/PNG/WEBP.")
            ruta, mime, size = _save_file(file_storage=f, folder=f"propietarios/{folio}", public=True)
            _insert_document_with_folio(
                folio=folio,
                tipo_usuario="arrendador",
                usuario_id=owner_id,
                tipo_documento=field,
                ruta=ruta, nombre_archivo=f.filename, mime=mime, size=size
            )

        _marcar_uso_folio(folio, "arrendador")
        db.session.commit()
        return _to_home(f"✅ Documentos del propietario guardados correctamente ({folio}).", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Error guardando propietario")
        return _to_home(f"❌ No se pudieron guardar documentos de propietario ({folio}). Detalle: {e}", "danger")


# ---------------- Inquilino (documentos) ----------------
def _upsert_arrendatario_datos(datos: dict):
    sql = text("""
        INSERT INTO public.arrendatarios(
            folio,
            nombre, correo, direccion_actual, rfc, curp, telefono,
            lugar_nacimiento, fecha_nacimiento,
            empleo_nombre, empleo_direccion, empleo_puesto, empleo_ingresos, empleo_antiguedad,
            num_habitantes, nombres_habitantes, empleo_habitantes,
            ref1_nombre, ref1_relacion, ref1_telefono, ref1_direccion,
            ref2_nombre, ref2_relacion, ref2_telefono, ref2_direccion,
            aval_nombre, aval_lugar_nacimiento, aval_fecha_nacimiento, aval_rfc, aval_curp, aval_direccion, aval_telefono, aval_folio_real, aval_lugar_registro,
            inmueble_direccion, inmueble_tipo, inmueble_precio_renta, inmueble_fecha_inicio, inmueble_fecha_contrato,
            updated_at
        ) VALUES (
            :folio,
            :nombre, :correo, :direccion_actual, :rfc, :curp, :telefono,
            :lugar_nacimiento, :fecha_nacimiento,
            :empleo_nombre, :empleo_direccion, :empleo_puesto, :empleo_ingresos, :empleo_antiguedad,
            :num_habitantes, :nombres_habitantes, :empleo_habitantes,
            :ref1_nombre, :ref1_relacion, :ref1_telefono, :ref1_direccion,
            :ref2_nombre, :ref2_relacion, :ref2_telefono, :ref2_direccion,
            :aval_nombre, :aval_lugar_nacimiento, :aval_fecha_nacimiento, :aval_rfc, :aval_curp, :aval_direccion, :aval_telefono, :aval_folio_real, :aval_lugar_registro,
            :inmueble_direccion, :inmueble_tipo, :inmueble_precio_renta, :inmueble_fecha_inicio, :inmueble_fecha_contrato,
            now()
        )
        ON CONFLICT (folio) DO UPDATE SET
            nombre                   = EXCLUDED.nombre,
            correo                   = EXCLUDED.correo,
            direccion_actual         = EXCLUDED.direccion_actual,
            rfc                      = EXCLUDED.rfc,
            curp                     = EXCLUDED.curp,
            telefono                 = EXCLUDED.telefono,
            lugar_nacimiento         = EXCLUDED.lugar_nacimiento,
            fecha_nacimiento         = EXCLUDED.fecha_nacimiento,
            empleo_nombre            = EXCLUDED.empleo_nombre,
            empleo_direccion         = EXCLUDED.empleo_direccion,
            empleo_puesto            = EXCLUDED.empleo_puesto,
            empleo_ingresos          = EXCLUDED.empleo_ingresos,
            empleo_antiguedad        = EXCLUDED.empleo_antiguedad,
            num_habitantes           = EXCLUDED.num_habitantes,
            nombres_habitantes       = EXCLUDED.nombres_habitantes,
            empleo_habitantes        = EXCLUDED.empleo_habitantes,
            ref1_nombre              = EXCLUDED.ref1_nombre,
            ref1_relacion            = EXCLUDED.ref1_relacion,
            ref1_telefono            = EXCLUDED.ref1_telefono,
            ref1_direccion           = EXCLUDED.ref1_direccion,
            ref2_nombre              = EXCLUDED.ref2_nombre,
            ref2_relacion            = EXCLUDED.ref2_relacion,
            ref2_telefono            = EXCLUDED.ref2_telefono,
            ref2_direccion           = EXCLUDED.ref2_direccion,
            aval_nombre              = EXCLUDED.aval_nombre,
            aval_lugar_nacimiento    = EXCLUDED.aval_lugar_nacimiento,
            aval_fecha_nacimiento    = EXCLUDED.aval_fecha_nacimiento,
            aval_rfc                 = EXCLUDED.aval_rfc,
            aval_curp                = EXCLUDED.aval_curp,
            aval_direccion           = EXCLUDED.aval_direccion,
            aval_telefono            = EXCLUDED.aval_telefono,
            aval_folio_real          = EXCLUDED.aval_folio_real,
            aval_lugar_registro      = EXCLUDED.aval_lugar_registro,
            inmueble_direccion       = EXCLUDED.inmueble_direccion,
            inmueble_tipo            = EXCLUDED.inmueble_tipo,
            inmueble_precio_renta    = EXCLUDED.inmueble_precio_renta,
            inmueble_fecha_inicio    = EXCLUDED.inmueble_fecha_inicio,
            inmueble_fecha_contrato  = EXCLUDED.inmueble_fecha_contrato,
            updated_at               = now();
    """)
    db.session.execute(sql, datos)

@bp.route("/documentos/inquilino", methods=["GET", "POST"])
def subir_inquilino():
    if request.method == "GET":
        return render_template("documentos_inquilino.html")

    form = request.form
    folio = (form.get("folio") or "").strip().upper()

    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return _to_home("Folio inválido. Verifica el formato AEPRA-YYYYMM-XXXX.", "danger")
    if not _folio_activo(folio):
        return _to_home("El folio no existe o está desactivado. Solicítalo a administración.", "danger")

    try:
        inq_id = _get_or_create_usuario_id_por_folio(tabla="arrendatarios", folio=folio)

        aval_lugar_nac = form.get("aval_lugar_nacimiento")
        aval_fecha_nac = _to_iso_date(form.get("aval_fecha_nacimiento"))
        if not (aval_lugar_nac or aval_fecha_nac):
            alfn = form.get("aval_lugar_fecha_nac")
            if alfn:
                aval_lugar_nac, aval_fecha_nac = _parse_lugar_fecha_combinado(alfn)

        datos_inq = {
            "folio": folio,
            "nombre": form.get("nombre"),
            "correo": form.get("correo"),
            "direccion_actual": form.get("direccion_actual"),
            "rfc": form.get("rfc"),
            "curp": form.get("curp"),
            "telefono": form.get("telefono"),
            "lugar_nacimiento": form.get("lugar_nacimiento"),
            "fecha_nacimiento": _to_iso_date(form.get("fecha_nacimiento")),

            "empleo_nombre": form.get("empleo_nombre"),
            "empleo_direccion": form.get("empleo_direccion"),
            "empleo_puesto": form.get("puesto"),
            "empleo_ingresos": _to_decimal(form.get("ingresos")),
            "empleo_antiguedad": form.get("antiguedad"),

            "num_habitantes": _to_int(form.get("num_habitantes")),
            "nombres_habitantes": form.get("nombres_habitantes"),
            "empleo_habitantes": form.get("empleo_habitantes"),

            "ref1_nombre": form.get("ref1_nombre"),
            "ref1_relacion": form.get("ref1_relacion"),
            "ref1_telefono": form.get("ref1_telefono"),
            "ref1_direccion": form.get("ref1_direccion"),

            "ref2_nombre": form.get("ref2_nombre"),
            "ref2_relacion": form.get("ref2_relacion"),
            "ref2_telefono": form.get("ref2_telefono"),
            "ref2_direccion": form.get("ref2_direccion"),

            "aval_nombre": form.get("aval_nombre"),
            "aval_lugar_nacimiento": aval_lugar_nac,
            "aval_fecha_nacimiento": aval_fecha_nac,
            "aval_rfc": form.get("aval_rfc"),
            "aval_curp": form.get("aval_curp"),
            "aval_direccion": form.get("aval_direccion"),
            "aval_telefono": form.get("aval_telefono"),
            "aval_folio_real": form.get("folio_real_aval"),
            "aval_lugar_registro": form.get("aval_lugar_registro"),

            # Inmueble (names actuales del formulario de inquilino)
            "inmueble_direccion": form.get("inmueble_direccion") or form.get("direccion"),
            "inmueble_tipo": form.get("inmueble_tipo") or form.get("tipo_inmueble"),
            "inmueble_precio_renta": _to_decimal(form.get("inmueble_precio_renta") or form.get("precio_renta")),
            "inmueble_fecha_inicio": _to_iso_date(form.get("inmueble_fecha_inicio") or form.get("fecha_inicio_renta")),
            "inmueble_fecha_contrato": _to_iso_date(form.get("inmueble_fecha_contrato") or form.get("fecha_firma_contrato")),

        }

        _upsert_arrendatario_datos(datos_inq)

        campos_archivos = {
            # Inquilino
            "identificacion": "Identificación oficial (inquilino)",
            "comprobante_domicilio_anterior_inquilino": "Comprobante domicilio anterior (inquilino)",
            "comprobante_ingresos_inquilino_mes1": "Comprobante de ingresos (inquilino) mes 1",
            "comprobante_ingresos_inquilino_mes2": "Comprobante de ingresos (inquilino) mes 2",
            "comprobante_ingresos_inquilino_mes3": "Comprobante de ingresos (inquilino) mes 3",
            # compatibilidad antigua
            "comprobante_ingresos_inquilino": "Comprobante de ingresos (inquilino)",

            # Aval
            "identificacion_oficial_aval": "Identificación oficial (aval)",
            "predial_inmueble_aval": "Boleta predial inmueble del aval",
            "escritura_inmueble_aval": "Escritura inmueble del aval",
            "domicilio_inmueble_aval": "Comprobante domicilio inmueble del aval",
            "folio_real_aval": "Constancia de folio real del inmueble del aval",
            "comprobante_ingresos_aval_mes1": "Comprobante de ingresos (aval) mes 1",
            "comprobante_ingresos_aval_mes2": "Comprobante de ingresos (aval) mes 2",
            "comprobante_ingresos_aval_mes3": "Comprobante de ingresos (aval) mes 3",
            # compatibilidad antigua
            "comprobante_ingresos_aval": "Comprobante de ingresos (aval)",

            "contrato_poder": "Contrato o poder notarial (si persona moral)",
        }

        for field, etiqueta in campos_archivos.items():
            f = request.files.get(field)
            if not f or not getattr(f, "filename", ""):
                continue
            if not _ext_ok(f.filename):
                raise ValueError(f"Formato no permitido para '{etiqueta}'. Usa PDF/JPG/PNG/WEBP.")
            ruta, mime, size = _save_file(file_storage=f, folder=f"arrendatarios/{folio}", public=True)
            _insert_document_with_folio(
                folio=folio,
                tipo_usuario="arrendatario",
                usuario_id=inq_id,
                tipo_documento=field,
                ruta=ruta, nombre_archivo=f.filename, mime=mime, size=size
            )

        _marcar_uso_folio(folio, "arrendatario")
        db.session.commit()
        return _to_home(f"✅ Documentos del inquilino guardados correctamente ({folio}).", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Error guardando inquilino")
        return _to_home(f"❌ No se pudieron guardar documentos de inquilino ({folio}). Detalle: {e}", "danger")


# ---------------- Otros endpoints ----------------
@bp.route("/ping")
def ping():
    return Response("pong", mimetype="text/plain")


# ---------------- Crear folio (Admin flujo HTML) ----------------
import secrets

def _folio_existe(folio: str) -> bool:
    row = db.session.execute(text("SELECT 1 FROM public.folios WHERE folio=:f LIMIT 1"), {"f": folio}).fetchone()
    return bool(row)

def _generar_folio(prefijo="AEPRA", yyyymm=None) -> str:
    if not yyyymm:
        yyyymm = datetime.utcnow().strftime("%Y%m")
    alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # evitar 0/O/1/I
    for _ in range(50):
        suf = "".join(secrets.choice(alfabeto) for _ in range(4))
        folio = f"{prefijo}-{yyyymm}-{suf}"
        if not _folio_existe(folio):
            return folio
    raise RuntimeError("No se pudo generar un folio único tras varios intentos.")

@bp.route("/admin/folios/crear", methods=["POST"])
@login_required
def crear_folio():
    prefijo = (request.form.get("prefijo") or "AEPRA").strip().upper()
    yyyymm = (request.form.get("yyyymm") or datetime.utcnow().strftime("%Y%m")).strip()
    folio_manual = (request.form.get("folio_manual") or "").strip().upper()

    if folio_manual:
        if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio_manual):
            flash("Formato de folio inválido. Usa AEPRA-YYYYMM-XXXX.", "warning")
            return redirect(url_for("routes.admin"))
        folio = folio_manual
        if _folio_existe(folio):
            flash(f"El folio {folio} ya existe.", "warning")
            return redirect(url_for("routes.admin"))
    else:
        folio = _generar_folio(prefijo=prefijo, yyyymm=yyyymm)

    db.session.execute(text("""
        INSERT INTO public.folios (folio, activo)
        VALUES (:f, true)
        ON CONFLICT (folio) DO NOTHING
    """), {"f": folio})
    db.session.commit()

    flash(f"Folio creado: {folio}", "success")
    return redirect(url_for("routes.admin"))
