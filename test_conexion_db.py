from sqlalchemy import create_engine

# Asegúrate de usar los datos reales de tu base
engine = create_engine("postgresql://webderecho:fAnwqm7EUzRKMSGrLFar9A4xpsbPf5ST@dpg-d260fgu3jp1c73cabia0-a.oregon-postgres.render.com/contactos_fvjv")

try:
    conn = engine.connect()
    print("✅ Conexión exitosa a la base de datos")
    conn.close()
except Exception as e:
    print("❌ Error al conectar:", e)
