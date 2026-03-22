@echo off
setlocal enabledelayedexpansion

REM Générer une clé AES-256 aléatoire et la mettre en variable
set "APP_MASTER_KEY=czSaWenq+bMP7K6Gu3sArWBst3WSbFn7SBP3CtFYYPU="

REM Démarrer l'application avec un timeout de 15 secondes
echo [*] Démarrage du serveur d'authentification...
echo [*] Master Key configurée : %APP_MASTER_KEY%
echo.

timeout /t 2 /nobreak

call mvn spring-boot:run

endlocal

