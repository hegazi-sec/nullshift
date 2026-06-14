@echo off
set DIR=%~dp0
set PYTHON=%DIR%.venv\Scripts\python.exe
if not exist "%PYTHON%" set PYTHON=python
"%PYTHON%" "%DIR%cli.py" %*
