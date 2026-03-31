# Documentation Technique — Serveur d'Authentification HMAC-SHA256

> **Projet :** `auth-server` — TP1 à TP5  
> **Framework :** Spring Boot 3.2.5 — Java 17  
> **Base de données :** MySQL (production) / H2 (tests)  
> **Qualité :** SonarCloud — `Andrimirana_auth-server`  
> **Date :** Mars 2026

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Stack technique](#2-stack-technique)
3. [Architecture du projet](#3-architecture-du-projet)
4. [Base de données — Modèle de données](#4-base-de-données--modèle-de-données)
5. [API REST — Endpoints](#5-api-rest--endpoints)
6. [Protocole d'authentification HMAC-SHA256](#6-protocole-dauthentification-hmac-sha256)
7. [Détail des services](#7-détail-des-services)
8. [Sécurité](#8-sécurité)
9. [Gestion des erreurs](#9-gestion-des-erreurs)
10. [Configuration](#10-configuration)
11. [Tests](#11-tests)
12. [Évolution par TP](#12-évolution-par-tp)
13. [Limites pédagogiques](#13-limites-pédagogiques)

---

## 1. Vue d'ensemble

Ce projet est un **serveur d'authentification REST stateless** développé progressivement sur 4 travaux pratiques (TP1 à TP4). Son objectif pédagogique est d'illustrer, étape par étape, les bonnes pratiques de sécurité dans une API d'authentification.

Le principe fondamental du protocole (TP3) est le suivant :

> **Le mot de passe ne circule jamais sur le réseau.**

Au lieu d'envoyer le mot de passe, le client prouve qu'il le connaît en calculant une signature cryptographique :

```
HMAC = HMAC_SHA256( clé = mot_de_passe , données = email:nonce:timestamp )
```

Le serveur recalcule la même signature et compare les deux. Si elles correspondent, l'utilisateur est authentifié.

---

## 2. Stack technique

| Composant          | Technologie                          | Version    |
|--------------------|--------------------------------------|------------|
| Langage            | Java                                 | 17         |
| Framework          | Spring Boot                          | 3.2.5      |
| Persistance        | Spring Data JPA / Hibernate          | inclus     |
| Base de données    | MySQL (prod) / H2 in-memory (tests)  | —          |
| Sécurité           | Spring Security                      | inclus     |
| Build              | Maven                                | 3.9+       |
| Réduction boilerplate | Lombok                            | inclus     |
| Tests              | JUnit 5 + Spring Boot Test           | inclus     |
| Couverture         | JaCoCo                               | inclus     |
| Qualité            | SonarCloud                           | —          |

---

## 3. Architecture du projet

```
auth/
└── src/
    ├── main/
    │   ├── java/com/example/auth/
    │   │   ├── AuthApplication.java          ← Point d'entrée Spring Boot
    │   │   ├── config/
    │   │   │   └── SecurityConfig.java       ← Configuration Spring Security
    │   │   ├── controller/
    │   │   │   └── AuthController.java       ← Endpoints REST (/api/auth/*)
    │   │   ├── dto/
    │   │   │   ├── LoginRequest.java         ← Corps de la requête POST /login
    │   │   │   ├── LoginResponse.java        ← Corps de la réponse (token + expiration)
    │   │   │   └── RegisterRequest.java      ← Corps de la requête POST /register
    │   │   ├── entity/
    │   │   │   ├── User.java                 ← Table `users`
    │   │   │   ├── AccessToken.java          ← Table `access_tokens`
    │   │   │   └── AuthNonce.java            ← Table `auth_nonce`
    │   │   ├── exception/
    │   │   │   ├── GlobalExceptionHandler.java    ← Gestion centralisée des erreurs
    │   │   │   ├── AuthenticationFailedException.java
    │   │   │   ├── InvalidInputException.java
    │   │   │   └── ResourceConflictException.java
    │   │   ├── repository/
    │   │   │   ├── UserRepository.java       ← CRUD utilisateurs
    │   │   │   ├── AccessTokenRepository.java← CRUD tokens + purge
    │   │   │   └── AuthNonceRepository.java  ← CRUD nonces + purge
    │   │   └── service/
    │   │       ├── AuthService.java          ← Logique métier (register + login)
    │   │       ├── HmacService.java          ← Calcul et comparaison HMAC-SHA256
    │   │       ├── TokenService.java         ← Génération et validation des tokens
    │   │       └── PasswordPolicyValidator.java ← Politique de mot de passe
    │   └── resources/
    │       └── application.properties        ← Config MySQL, JPA, logs
    └── test/
        ├── java/...                          ← Tests JUnit 5
        └── resources/
            └── application.properties        ← Config H2 pour les tests
```

### Flux de données (Architecture en couches)

```
Client HTTP
    │
    ▼
┌───────────────────┐
│  AuthController   │  ← Reçoit les requêtes JSON, délègue, retourne les réponses
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   AuthService     │  ← Logique métier, orchestration des vérifications
└──┬──────┬─────────┘
   │      │
   │      ├──────────────────────┐
   ▼      ▼                      ▼
HmacService  TokenService  PasswordPolicyValidator
   │               │
   ▼               ▼
HMAC-SHA256   UUID Token (15 min)
   │
   ▼
┌───────────────────────────────────────────┐
│ UserRepository / AccessTokenRepository   │  ← Spring Data JPA
│ AuthNonceRepository                      │
└───────────────────────────────────────────┘
         │
         ▼
   Base de données (MySQL / H2)
```

---

## 4. Base de données — Modèle de données

### Table `users`

Stocke les comptes utilisateurs.

| Colonne              | Type           | Contrainte         | Description                                     |
|----------------------|----------------|--------------------|-------------------------------------------------|
| `id`                 | BIGINT         | PK, AUTO_INCREMENT | Identifiant technique                          |
| `email`              | VARCHAR        | UNIQUE, NOT NULL   | Identifiant métier de l'utilisateur            |
| `password_encrypted` | VARCHAR        | NOT NULL           | Mot de passe (en clair en TP3 — voir §13)      |
| `failed_attempts`    | INT            | défaut = 0         | Compteur de tentatives échouées consécutives   |
| `lock_until`         | DATETIME       | nullable           | Date de fin de verrouillage (anti brute-force) |
| `created_at`         | DATETIME       |                    | Date de création du compte                     |

### Table `access_tokens`

Stocke les tokens SSO émis après chaque login réussi.

| Colonne      | Type     | Contrainte         | Description                              |
|--------------|----------|--------------------|------------------------------------------|
| `id`         | BIGINT   | PK, AUTO_INCREMENT | Identifiant technique                   |
| `user_id`    | BIGINT   | FK → users(id)     | Propriétaire du token                   |
| `token`      | VARCHAR  | UNIQUE, NOT NULL   | Valeur UUID du token Bearer             |
| `expires_at` | DATETIME | NOT NULL           | Date d'expiration (`now + 15 minutes`)  |
| `created_at` | DATETIME | NOT NULL           | Date de génération du token             |

### Table `auth_nonce`

Stocke les nonces déjà consommés pour bloquer les attaques par rejeu.

| Colonne      | Type     | Contrainte                         | Description                             |
|--------------|----------|------------------------------------|-----------------------------------------|
| `id`         | BIGINT   | PK, AUTO_INCREMENT                 | Identifiant technique                  |
| `user_id`    | BIGINT   | FK → users(id)                     | Utilisateur émetteur                   |
| `nonce`      | VARCHAR  | UNIQUE (user_id, nonce), NOT NULL  | Valeur UUID du nonce                   |
| `expires_at` | DATETIME |                                    | Date d'expiration (TTL = 120 secondes) |
| `consumed`   | BOOLEAN  | défaut = true                      | Marqueur de consommation               |

---

## 5. API REST — Endpoints

### Base URL : `http://localhost:8080/api/auth`

---

### `POST /register` — Inscription

Inscrit un nouvel utilisateur. Le mot de passe est soumis à une politique stricte.

**Corps de la requête :**
```json
{
  "email"           : "user@example.com",
  "password"        : "MonMotDePasse1!",
  "passwordConfirm" : "MonMotDePasse1!"
}
```

**Réponse succès — HTTP 200 :**
```json
{
  "message" : "Inscription réussie",
  "email"   : "user@example.com"
}
```

**Réponses d'erreur :**

| Code HTTP | Cause                                            |
|-----------|--------------------------------------------------|
| `400`     | Email vide, format invalide, mots de passe non concordants, politique de mot de passe non respectée |
| `409`     | Email déjà utilisé                               |

---

### `POST /login` — Connexion via HMAC

Authentifie un utilisateur via la preuve cryptographique HMAC-SHA256.  
**Le mot de passe ne transit pas sur le réseau.**

**Corps de la requête :**
```json
{
  "email"     : "user@example.com",
  "nonce"     : "550e8400-e29b-41d4-a716-446655440000",
  "timestamp" : 1711234567,
  "hmac"      : "Base64( HMAC_SHA256(key=password, data=email:nonce:timestamp) )"
}
```

**Réponse succès — HTTP 200 :**
```json
{
  "accessToken" : "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "expiresAt"   : "2026-03-25T01:00:00"
}
```

**Réponses d'erreur :**

| Code HTTP | Cause                                                    |
|-----------|----------------------------------------------------------|
| `400`     | Email manquant                                           |
| `401`     | Email inconnu, HMAC invalide, timestamp hors fenêtre, nonce déjà utilisé |
| `429`     | Compte verrouillé (5 échecs consécutifs → blocage 2 min) |

---

### `POST /password-strength` — Évaluation de force

Évalue la force d'un mot de passe sans le stocker. Utile pour l'indicateur visuel côté client.

**Corps de la requête :**
```json
{ "password": "MonMotDePasse1!" }
```

**Réponse succès — HTTP 200 :**
```json
{ "strength": "STRONG" }
```

Valeurs possibles : `"WEAK"`, `"MEDIUM"`, `"STRONG"`.

> **Note :** POST est utilisé intentionnellement (et non GET) pour que le mot de passe ne soit jamais exposé dans l'URL ni dans les access logs du serveur.

---

## 6. Protocole d'authentification HMAC-SHA256

### 6.1 — Schéma complet du flux de login

```
CLIENT                                              SERVEUR
  │                                                    │
  │ 1. Génère nonce = UUID aléatoire                  │
  │ 2. Récupère timestamp = now() en secondes Unix    │
  │ 3. Calcule :                                       │
  │    message = email:nonce:timestamp                 │
  │    hmac = HMAC_SHA256(key=password, msg=message)   │
  │    hmac_b64 = Base64(hmac)                         │
  │                                                    │
  │──── POST /api/auth/login ────────────────────────►│
  │     { email, nonce, timestamp, hmac_b64 }          │
  │                                                    │
  │                    4. Vérifie que l'email existe   │
  │                    5. Vérifie que le compte        │
  │                       n'est pas verrouillé         │
  │                    6. Vérifie |now - timestamp|    │
  │                       ≤ 60 secondes               │
  │                    7. Vérifie que le nonce n'a     │
  │                       pas encore été utilisé       │
  │                    8. Enregistre le nonce en BD    │
  │                       (bloque tout rejeu concurrent)│
  │                    9. Recalcule :                  │
  │                       message = email:nonce:ts     │
  │                       expected = HMAC_SHA256(      │
  │                         key=password_stocké,       │
  │                         msg=message)               │
  │                   10. Compare en temps constant    │
  │                       MessageDigest.isEqual(       │
  │                         expected, hmac_reçu)       │
  │                   11. Si OK → génère token UUID    │
  │                       (15 minutes de validité)     │
  │                   12. Réinitialise compteur échecs │
  │                                                    │
  │◄─── HTTP 200 ──────────────────────────────────── │
  │     { accessToken, expiresAt }                     │
  │                                                    │
  │ 13. Stocke le token localement                     │
  │ 14. Pour chaque requête suivante :                 │
  │     Authorization: Bearer <accessToken>            │
```

### 6.2 — Pourquoi le timestamp ?

Le timestamp permet d'empêcher les **attaques par rejeu différées** : si un attaquant intercepte une requête HMAC valide et tente de la rejouer plus tard, le serveur la rejettera car le timestamp sera trop éloigné de l'heure actuelle (fenêtre de ±60 secondes).

### 6.3 — Pourquoi le nonce ?

Le nonce (Number Used Once) est un UUID aléatoire généré par le client pour chaque requête. Il empêche les **attaques par rejeu immédiates** : même dans la fenêtre de 60 secondes, une requête interceptée et renvoyée sera rejetée car le nonce a déjà été enregistré en base.

### 6.4 — Pourquoi la comparaison en temps constant ?

La méthode `MessageDigest.isEqual()` est utilisée à la place de `equals()`. Cela empêche les **attaques temporelles (timing attacks)** : avec `equals()`, une comparaison caractère par caractère s'arrête dès la première différence — un attaquant peut mesurer les temps de réponse pour deviner le HMAC correct bit par bit. `isEqual()` prend toujours le même temps, quelle que soit la position de la différence.

### 6.5 — Calcul HMAC côté client (exemple Java)

```java
Mac mac = Mac.getInstance("HmacSHA256");
SecretKeySpec key = new SecretKeySpec(password.getBytes(UTF_8), "HmacSHA256");
mac.init(key);
String message = email + ":" + nonce + ":" + timestamp;
byte[] result = mac.doFinal(message.getBytes(UTF_8));
String hmacB64 = Base64.getEncoder().encodeToString(result);
```

---

## 7. Détail des services

### 7.1 — `AuthService` — Orchestrateur principal

Classe centrale qui orchestre toute la logique métier. Elle coordonne les appels aux autres services et aux repositories.

**Méthodes publiques :**

| Méthode                                         | Rôle                                                 |
|-------------------------------------------------|------------------------------------------------------|
| `register(email, password, passwordConfirm)`    | Valide les données, crée l'utilisateur en base       |
| `login(LoginRequest)`                           | Exécute les 6 vérifications du protocole HMAC        |
| `getUserByToken(tokenValue)`                    | Délègue à `TokenService` pour valider un Bearer token|
| `evaluatePasswordStrength(password)`            | Délègue à `PasswordPolicyValidator`                  |

**Constantes de sécurité :**
- `MAX_ATTEMPTS = 5` — seuil de verrouillage anti brute-force
- `LOCK_MINUTES = 2` — durée de verrouillage après dépassement du seuil
- `TIMESTAMP_WINDOW_SECONDS = 60` — tolérance horaire client/serveur

---

### 7.2 — `HmacService` — Cryptographie HMAC

Responsable unique du calcul et de la vérification des signatures HMAC-SHA256.

| Méthode                             | Rôle                                                              |
|-------------------------------------|-------------------------------------------------------------------|
| `compute(key, data)`                | Calcule `HMAC_SHA256(key, data)` et retourne la signature en Base64|
| `compare(expected, received)`       | Compare deux signatures en **temps constant** via `MessageDigest.isEqual()` |

---

### 7.3 — `TokenService` — Gestion des tokens SSO

Émet et valide les tokens d'accès Bearer après authentification réussie.

| Méthode                    | Rôle                                                           |
|----------------------------|----------------------------------------------------------------|
| `generate(user)`           | Crée un token UUID, le persist en BD, expiration dans 15 min  |
| `getUserByToken(tokenValue)` | Recherche le token en BD, vérifie qu'il n'est pas expiré   |

---

### 7.4 — `PasswordPolicyValidator` — Politique de mot de passe

Vérifie et évalue la robustesse des mots de passe.

**Règles de validation (inscription) :**

| Règle                             | Détail                                                |
|-----------------------------------|-------------------------------------------------------|
| Longueur minimale                 | ≥ 12 caractères                                       |
| Majuscule obligatoire             | Au moins 1 lettre A–Z                                |
| Minuscule obligatoire             | Au moins 1 lettre a–z                                |
| Chiffre obligatoire               | Au moins 1 chiffre 0–9                               |
| Caractère spécial obligatoire     | Au moins 1 caractère non alphanumérique (`!@#$%...`) |

**Grille d'évaluation de force (`evaluateStrength`) :**

| Score (critères satisfaits)       | Résultat   |
|-----------------------------------|------------|
| ≤ 2 critères OU longueur < 12    | `WEAK`     |
| 3 critères                        | `MEDIUM`   |
| ≥ 4 critères ET longueur ≥ 16   | `STRONG`   |

> Les patterns regex sont pré-compilés en constantes statiques (`Pattern.compile(...)` une seule fois au chargement de la classe) pour des raisons de performance et de protection contre les attaques ReDoS.

---

## 8. Sécurité

### 8.1 — Spring Security (`SecurityConfig`)

L'application utilise Spring Security en mode **stateless total** :

```java
http
  .csrf(AbstractHttpConfigurer::disable)          // CSRF inutile (pas de session)
  .sessionManagement(session ->
      session.sessionCreationPolicy(STATELESS))    // Aucune session HTTP
  .headers(headers -> headers
      .contentTypeOptions(...)                     // X-Content-Type-Options: nosniff
      .frameOptions(frame -> frame.deny())         // X-Frame-Options: DENY
      .httpStrictTransportSecurity(hsts -> ...)    // HSTS : 1 an, includeSubDomains
      .referrerPolicy(...)                         // Referrer-Policy: strict-origin-when-cross-origin
  )
  .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
```

**Pourquoi CSRF est désactivé ?**  
Le CSRF (Cross-Site Request Forgery) exploite le fait qu'un navigateur envoie automatiquement les cookies de session sur toutes les requêtes vers un domaine. Dans cette API :
- Il n'y a **aucune session HTTP** (`STATELESS`)
- Il n'y a **aucun cookie de session** — l'authentification passe par un token Bearer dans le header `Authorization`
- Le vecteur d'attaque CSRF **ne s'applique donc pas**

L'annotation `@SuppressWarnings("java:S4502")` documente explicitement ce choix dans le code.

### 8.2 — Protection contre le brute-force

| Mécanisme                       | Valeur          |
|---------------------------------|-----------------|
| Seuil de verrouillage           | 5 échecs        |
| Durée de verrouillage           | 2 minutes       |
| Réinitialisation du compteur    | Après login réussi |
| Code HTTP retourné si verrouillé | `429 Too Many Requests` |

### 8.3 — Protection contre le rejeu

| Mécanisme          | Rôle                                                                      |
|--------------------|---------------------------------------------------------------------------|
| **Nonce UUID**     | Chaque requête est unique — le nonce est enregistré en BD après usage     |
| **Timestamp ±60s** | Empêche le rejeu différé — la requête doit être fraîche                   |
| TTL nonce (120s)   | Les nonces expirés sont purgés périodiquement de la base                  |

### 8.4 — Protection contre les attaques temporelles

La comparaison des signatures HMAC utilise `MessageDigest.isEqual()` (temps constant) et non `String.equals()` (temps variable) pour empêcher toute inférence par mesure du temps de réponse.

### 8.5 — En-têtes HTTP de sécurité

| En-tête                         | Valeur                                        | Protection                          |
|---------------------------------|-----------------------------------------------|-------------------------------------|
| `X-Content-Type-Options`        | `nosniff`                                     | Empêche le MIME sniffing            |
| `X-Frame-Options`               | `DENY`                                        | Empêche le clickjacking             |
| `Strict-Transport-Security`     | `max-age=31536000; includeSubDomains`         | Force HTTPS sur 1 an                |
| `Referrer-Policy`               | `strict-origin-when-cross-origin`             | Limite les informations dans Referer|

---

## 9. Gestion des erreurs

Toutes les exceptions sont interceptées par `GlobalExceptionHandler` (`@RestControllerAdvice`) qui retourne une réponse JSON standardisée.

### Format JSON des erreurs

```json
{
  "timestamp" : "2026-03-25T00:30:00",
  "status"    : 401,
  "error"     : "Unauthorized",
  "message"   : "Identifiants incorrects",
  "path"      : "/api/auth/login"
}
```

### Table de correspondance exception → HTTP

| Exception                       | Code HTTP | Cas d'usage                                                  |
|---------------------------------|-----------|--------------------------------------------------------------|
| `InvalidInputException`         | `400`     | Email vide, format invalide, politique mot de passe non respectée, mots de passe différents |
| `AuthenticationFailedException` | `401`     | Email inconnu, HMAC invalide, timestamp hors fenêtre, nonce déjà utilisé |
| `AuthenticationFailedException` | `429`     | Message contient "bloqué" → compte verrouillé anti brute-force |
| `ResourceConflictException`     | `409`     | Email déjà utilisé à l'inscription                           |

> **Note :** Les messages d'erreur d'authentification sont volontairement **génériques** (`"Identifiants incorrects"`) pour ne pas révéler à un attaquant si l'email existe ou non (protection contre l'énumération d'utilisateurs).

---

## 10. Configuration

### `application.properties` (production — MySQL)

```properties
server.port=8080

# MySQL
spring.datasource.url=jdbc:mysql://localhost:3306/auth?useSSL=false&serverTimezone=UTC
spring.datasource.driverClassName=com.mysql.cj.jdbc.Driver
spring.datasource.username=root
spring.datasource.password=

# JPA
spring.jpa.hibernate.ddl-auto=update     # Crée/met à jour le schéma automatiquement
spring.jpa.show-sql=true

# Logs
logging.file.name=logs/auth.log
logging.level.com.example.auth=INFO
spring.jpa.open-in-view=false
```

### `application.properties` (tests — H2)

```properties
spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1
spring.datasource.driverClassName=org.h2.Driver
spring.jpa.hibernate.ddl-auto=create-drop    # Recréé pour chaque test
spring.jpa.show-sql=false
```

### Variable d'environnement requise

| Variable          | Description                                 | Exemple                                     |
|-------------------|---------------------------------------------|---------------------------------------------|
| `APP_MASTER_KEY`  | Clé maître de l'application (Base64)        | `MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=` |

---

## 11. Tests

Les tests sont situés dans `src/test/java/com/example/auth/`.  
Ils utilisent **Spring Boot Test** avec une base **H2 in-memory** (pas besoin de MySQL).

### Profil de test

Activé via : `-Dspring.profiles.active=test`

### Couverture JaCoCo

Le rapport est généré dans `target/site/jacoco/jacoco.xml` lors de `mvn clean verify`.  
Il est automatiquement importé par SonarCloud lors de l'analyse.

### Lancer les tests

```bash
# Tests + rapport JaCoCo
mvn clean verify -Dspring.profiles.active=test

# Analyse SonarCloud complète
.\run-sonar.ps1 -Token "votre_token_sonarcloud"
```

---

## 12. Évolution par TP

| TP    | Nouveautés introduites                                                              | Problème restant                             |
|-------|-------------------------------------------------------------------------------------|----------------------------------------------|
| **TP1** | Authentification basique — email + mot de passe en clair sur le réseau          | Mot de passe visible dans les requêtes HTTP  |
| **TP2** | Hachage BCrypt + politique de mot de passe (12 car., maj, min, chiffre, spécial) + anti brute-force (5 tentatives → blocage 2 min) | Vulnérable aux attaques par rejeu |
| **TP3** | Protocole HMAC-SHA256 + nonce UUID + fenêtre timestamp ±60s + token SSO UUID 15 min + protection timing attack | Mot de passe toujours stocké en clair (nécessaire pour HMAC) |
| **TP4** | *(Prévu)* Chiffrement du mot de passe stocké (ex. AES-256 avec `APP_MASTER_KEY`) + dérivation de clé PBKDF2/Argon2 | — |

---

## 13. Limites pédagogiques

> ⚠️ **Ce projet est volontairement imparfait à des fins d'apprentissage. Ne jamais utiliser ce code en production.**

| Limite                              | Explication                                                                                   |
|-------------------------------------|-----------------------------------------------------------------------------------------------|
| **Mot de passe stocké en clair**    | En TP3, le serveur doit pouvoir recalculer `HMAC(key=password, ...)`. Il faut donc connaître le mot de passe original, ce qui impose son stockage en clair. En production, on utiliserait un protocole SRP (Secure Remote Password) ou OPAQUE qui ne nécessite pas de stocker le secret en clair. |
| **Pas de HTTPS forcé**              | L'application tourne en HTTP. En production, HTTPS est obligatoire (TLS 1.3 minimum). Sans HTTPS, le HMAC peut être intercepté et le nonce + timestamp rejoués dans la fenêtre de 60 secondes. |
| **Token UUID non signé**            | Le token d'accès est un simple UUID stocké en BD. En production, on utiliserait un JWT signé (RS256 ou HS256) qui n'exige pas de requête en BD pour être validé. |
| **Pas d'expiration des nonces** | La purge des nonces expirés n'est pas déclenchée automatiquement (pas de `@Scheduled`). La table `auth_nonce` grossit indéfiniment sans intervention manuelle. |
| **Pas de rate limiting global**    | Le rate limiting est uniquement par compte (5 tentatives par email). Un attaquant distribuant les tentatives sur plusieurs comptes ou IPs n'est pas bloqué. |
| `spring.jpa.show-sql=true`          | Les requêtes SQL sont loggées, ce qui peut exposer des données sensibles dans les logs de prod.|

