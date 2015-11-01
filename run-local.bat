@echo off
set "PYTHON_PATH=C:\Python34\python.exe"
set "SCRIPT_PATH=tsuru2d-server.py"
set "DATABASE_URL=sqlite:///tsuru2d.db"
set "PORT=8080"
%PYTHON_PATH% %SCRIPT_PATH%
