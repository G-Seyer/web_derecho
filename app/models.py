# app/models.py
from datetime import datetime
from app import db

class MensajeContacto(db.Model):
    __tablename__ = "contacto"
    id              = db.Column(db.Integer, primary_key=True)
    nombre          = db.Column(db.String(100), nullable=False)
    correo          = db.Column(db.String(100), nullable=False, index=True)
    telefono        = db.Column(db.String(50))
    mensaje         = db.Column(db.Text, nullable=False)
    fecha_registro  = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Si tu tabla ya tiene DEFAULT en la BD (CURRENT_TIMESTAMP),
    # puedes quitar el 'default=' de arriba.
