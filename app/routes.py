import os
import re
import mimetypes
from datetime import date
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, current_app as app
)
from sqlalchemy import text
import boto3
from botocore.exceptions import BotoCoreError, NoCredentialsError, ClientError

# Si tu app usa SQLAlchemy en app/__init__.py:
#   from app import db
# y aquí lo importas:
from app import db


# =============== Utilidades S3 ===============

def _get_s3_client():
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_sec = os.getenv("AWS_SECRET_ACCESS_KEY")
    region  = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    if not aws_key or not aws_sec:
        raise RuntimeError("AWS credentials missing (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY).")

    return boto3.client(
        "s3",
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_sec,
        region_name=region
    )


def _save_file_to_s3(*, file_storage, folder: str, public: bool = True):
    """
    Sube un FileStorage a S3 dentro de la carpeta indicada.
    Devuelve (ruta, mime, size). 'ruta' será la URL pública (si public=True) o la key s3://bucket/key.
    """
    bucket = os.getenv("S3_BUCKET_NAME") or os.getenv("S3_BUCKET")
    if not bucket:
        raise RuntimeError("S3_BUCKET_NAME (o S3_BUCKET) no está configurado")

    s3 = _get_s3_client()

    filename = file_storage.filename
    raw = file_storage.read()
    size = len(raw)

    mime = mimetypes.guess_type(filename)[0] or file_storage.mimetype or "application/octet-stream"
    key  = f"{folder.strip('/')}/{filename}"

    extra = {"ContentType": mime}
    if public:
        extra["ACL"] = "public-read"

    try:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=raw,
            **extra
        )
    except (BotoCoreError, NoCredentialsError, ClientError) as e:
        raise RuntimeError(f"Error subiendo a S3: {e}")

    ruta = f"https://{bucket}.s3.amazonaws.com/{key}" if public else f"s3://{bucket}/{key}"
    return ruta, mime, size


# =============== Helpers de BD ===============

def _insert_document_with_folio(*, folio, tipo_usuario, usuario_id, tipo_documento, ruta, nombre_archivo, mime, size):
    """
    Inserta/actualiza en public.documentos incluyendo el FOLIO.
    Requiere índice único por (tipo_usuario, usuario_id, tipo_documento) para el ON CONFLICT.
    """
    sql = text("""
        INSERT INTO public.documentos
          (folio, tipo_usuario, usuario_id, tipo_documento, ruta, nombre_archivo, mime, tamano_bytes)
        VALUES
          (:folio, :tipo_usuario, :usuario_id, :tipo_documento, :ruta, :nombre_archivo, :mime, :size)
        ON CONFLICT (tipo_usuario, usuario_id, tipo_documento) DO UPDATE
        SET ruta           = EXCLUDED.ruta,
            nombre_archivo = EXCLUDED.nombre_archivo,
            mime           = EXCLUDED.mime,
            tamano_bytes   = EXCLUDED.tamano_bytes,
            fecha_subida   = now(),
            folio          = EXCLUDED.folio;
    """)
    db.session.execute(sql, dict(
        folio=folio,
        tipo_usuario=tipo_usuario,
        usuario_id=usuario_id,
        tipo_documento=tipo_documento,
        ruta=ruta,
        nombre_archivo=nombre_archivo,
        mime=mime,
        size=size
    ))


def _get_or_create_usuario_id_por_folio(*, tabla: str, folio: str):
    """
    Intenta crear (si no existe) un registro marcador por folio y devuelve el id.
    Requiere que {tabla}.folio sea UNIQUE para que el ON CONFLICT funcione.
    """
    sql = text(f"""
        INSERT INTO public.{tabla} (folio)
        VALUES (:folio)
        ON CONFLICT (folio) DO UPDATE SET folio = EXCLUDED.folio
        RETURNING id;
    """)
    row = db.session.execute(sql, {"folio": folio}).first()
    return row[0]


# =============== Blueprints/Rutas ===============

bp = Blueprint("routes", __name__)


@bp.route("/")
def home():
    return render_template("index.html")


# ---------- Verificación simple del folio (AJAX de los formularios) ----------
@bp.get("/api/verificar-folio/<folio>")
def api_verificar_folio(folio):
    # Ajusta el patrón si tu formato cambia
    ok = re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio or "") is not None
    return jsonify({"ok": ok})


# ================== FORMULARIO PROPIETARIO ==================


@bp.route("/documentos/propietario", methods=["GET", "POST"])
def subir_propietario():
    if request.method == "GET":
        return render_template("documentos_propietario.html")

    form = request.form
    folio = (form.get("folio") or "").strip()

    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return "Folio inválido", 400

    try:
        arr_id = _get_or_create_usuario_id_por_folio(tabla="arrendadores", folio=folio)
    except Exception as e:
        db.session.rollback()
        return f"Error guardando propietario: {e}", 500

    try:
        for clave, fs in request.files.items():
            if not fs or fs.filename == "":
                continue

            ruta, mime, size = _save_file_to_s3(
                file_storage=fs,
                folder=f"arrendador/{folio}/{arr_id}",
                public=True
            )

            _insert_document_with_folio(
                folio=folio,
                tipo_usuario="arrendador",
                usuario_id=arr_id,
                tipo_documento=clave,
                ruta=ruta,
                nombre_archivo=fs.filename,
                mime=mime,
                size=size
            )

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return f"Error guardando propietario: {e}", 500

    flash("✅ Documentos del propietario guardados correctamente.", "success")
    return redirect(url_for("routes.home"))  # 🔹 ahora vuelve al inicio

# ================== FORMULARIO INQUILINO ==================

@bp.route("/documentos/inquilino", methods=["GET", "POST"])
def subir_inquilino():
    if request.method == "GET":
        return render_template("documentos_inquilino.html")

    form = request.form
    folio = (form.get("folio") or "").strip()

    if not re.match(r"^AEPRA-\d{6}-[A-Z0-9]{4}$", folio):
        return "Folio inválido", 400

    try:
        inq_id = _get_or_create_usuario_id_por_folio(tabla="arrendatarios", folio=folio)
    except Exception as e:
        db.session.rollback()
        return f"Error guardando inquilino: {e}", 500

    try:
        for clave, fs in request.files.items():
            if not fs or fs.filename == "":
                continue

            ruta, mime, size = _save_file_to_s3(
                file_storage=fs,
                folder=f"arrendatario/{folio}/{inq_id}",
                public=True
            )

            _insert_document_with_folio(
                folio=folio,
                tipo_usuario="arrendatario",
                usuario_id=inq_id,
                tipo_documento=clave,
                ruta=ruta,
                nombre_archivo=fs.filename,
                mime=mime,
                size=size
            )

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return f"Error guardando inquilino: {e}", 500

    flash("✅ Documentos del inquilino guardados correctamente.", "success")
    return redirect(url_for("routes.home"))  # 🔹 ahora vuelve al inicio


# ================== ADMIN ==================

@bp.route("/admin")
def admin_home():
    return render_template("admin.html")


@bp.get("/api/admin/folio/<folio>")
def api_admin_folio(folio):
    """
    Devuelve:
      - resumen (v_documentos_resumen)
      - documentos (v_documentos_por_folio)
      - póliza (polizas)
    """
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
    """
    Guarda/actualiza la póliza para un folio.
    fecha_fin = fecha_inicio + 1 año.
    """
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

# ================== ADMIN ==================


@bp.route("/terminos-mascotas")
def terminos_mascotas():
    return render_template("terminos_mascotas.html")
