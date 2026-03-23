#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Lance l'analyse SonarCloud pour le projet auth.

.DESCRIPTION
    Ce script :
    1. Génère le rapport JaCoCo (mvn clean verify)
    2. Lance l'analyse SonarCloud (mvn sonar:sonar)

.PARAMETER Token
    Votre SONAR_TOKEN obtenu depuis https://sonarcloud.io/account/security

.EXAMPLE
    .\run-sonar.ps1 -Token "sqp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

.NOTES
    Prérequis : Java 17, Maven, APP_MASTER_KEY valide
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Token = $env:SONAR_TOKEN
)

# ── Couleurs ─────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "▶  $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "✅ $msg" -ForegroundColor Green }
function Write-Error2 { param($msg) Write-Host "❌ $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║         SonarCloud Analysis - auth-server            ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""

# ── Vérification du token ─────────────────────────────────────────────────────
if ([string]::IsNullOrEmpty($Token)) {
    Write-Error2 "SONAR_TOKEN manquant !"
    Write-Host ""
    Write-Host "Pour obtenir votre token :" -ForegroundColor Yellow
    Write-Host "  1. Allez sur https://sonarcloud.io/account/security" -ForegroundColor White
    Write-Host "  2. Cliquez 'Generate Token' → nom: auth-server → Generate" -ForegroundColor White
    Write-Host "  3. Copiez le token et relancez :" -ForegroundColor White
    Write-Host "     .\run-sonar.ps1 -Token 'sqp_xxxxxxxxxxxx'" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# ── APP_MASTER_KEY pour les tests ─────────────────────────────────────────────
if ([string]::IsNullOrEmpty($env:APP_MASTER_KEY)) {
    $env:APP_MASTER_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    Write-Host "APP_MASTER_KEY définie automatiquement (clé de dev)" -ForegroundColor DarkGray
}

# ── Répertoire auth ───────────────────────────────────────────────────────────
$authDir = Join-Path $PSScriptRoot "auth"
if (-not (Test-Path $authDir)) {
    Write-Error2 "Répertoire 'auth' introuvable : $authDir"
    exit 1
}
Set-Location $authDir

# ── Étape 1 : Build + Tests + JaCoCo ─────────────────────────────────────────
Write-Step "Étape 1/2 — Build, tests et rapport JaCoCo..."
mvn clean verify "-Dspring.profiles.active=test" -q
if ($LASTEXITCODE -ne 0) {
    Write-Error2 "Les tests ont échoué. Corrigez les erreurs avant de lancer Sonar."
    exit 1
}
Write-OK "Build et tests OK (rapport JaCoCo généré)"

# ── Étape 2 : Analyse SonarCloud ─────────────────────────────────────────────
Write-Step "Étape 2/2 — Analyse SonarCloud..."
$env:SONAR_TOKEN = $Token
mvn sonar:sonar "-Dsonar.token=$Token" "-Dspring.profiles.active=test"
if ($LASTEXITCODE -ne 0) {
    Write-Error2 "L'analyse SonarCloud a échoué."
    Write-Host ""
    Write-Host "Vérifiez que :" -ForegroundColor Yellow
    Write-Host "  • Le projet 'Andrimirana_auth-server' existe sur SonarCloud" -ForegroundColor White
    Write-Host "  • L'organisation 'andrimirana' existe sur SonarCloud" -ForegroundColor White
    Write-Host "  • Le token est valide" -ForegroundColor White
    exit 1
}

Write-Host ""
Write-OK "Analyse SonarCloud terminée !"
Write-Host ""
Write-Host "📊 Résultats : https://sonarcloud.io/project/overview?id=Andrimirana_auth-server" -ForegroundColor Cyan
Write-Host ""

