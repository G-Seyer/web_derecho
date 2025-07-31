@echo off
cd /d "C:\Users\Giovanni\Documents\Trabajo\web_derecho"

REM Activar entorno virtual
call venv\Scripts\activate.bat

REM Iniciar Flask
set FLASK_APP=run.py
set FLASK_ENV=development
start http://127.0.0.1:5000/
flask run
