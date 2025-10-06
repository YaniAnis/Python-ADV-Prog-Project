batch
@echo off
echo 🔧 Configuration de l'environnement PenTest MultiTools pour Windows...

:: Créer les répertoires nécessaires
if not exist "logs" mkdir logs
if not exist "data\wordlists" mkdir data\wordlists
if not exist "data\reports" mkdir data\reports
if not exist "data\configs" mkdir data\configs

echo ✅ Configuration terminée!
echo.
echo 📋 Prochaines étapes:
echo 1. Installer VcXsrv ou X410 pour le GUI
echo 2. Lancer VcXsrv avec: "Disable access control" coché
echo 3. Exécuter: docker-compose up --build
echo.
pause