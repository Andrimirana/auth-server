# Explication détaillée des 5 TP — Serveur d'Authentification

> **Projet :** Serveur d'Authentification REST — Java Spring Boot + MySQL  
> **Parcours :** CDWFS — Travail individuel  
> **Objectif global :** Construire progressivement une API REST sécurisée, en passant d'une authentification dangereuse à une authentification robuste de niveau industriel.

---

## Table des matières

1. [TP1 — Authentification Dangereuse](#tp1--authentification-dangereuse)
2. [TP2 — Authentification Fragile](#tp2--authentification-fragile)
3. [TP3 — Authentification Forte](#tp3--authentification-forte)
4. [TP4 — Industrialisation (Master Key + CI/CD)](#tp4--industrialisation-master-key--cicd)
5. [TP5 — Changement de mot de passe + Docker](#tp5--changement-de-mot-de-passe--docker)
6. [Synthèse de l'évolution](#synthèse-de-lévolution)
7. [Correspondance avec le projet](#correspondance-avec-le-projet)

---

## TP1 — Authentification Dangereuse

**Tag Git :** `v1-tp1`  
**Durée estimée :** 10 heures (1 semaine)

### Objectif pédagogique

Mettre en place une authentification **volontairement dangereuse** pour comprendre pourquoi un système peut *fonctionner* tout en restant *inacceptable en production*. Ce TP sert de base pour les améliorations progressives des TP suivants.

### Fonctionnalités implémentées

| Fonctionnalité | Détail |
|---|---|
| **Inscription** | `POST /api/auth/register` — crée un compte avec email + mot de passe |
| **Connexion** | `POST /api/auth/login` — vérifie email + mot de passe, retourne succès ou échec |
| **Route protégée** | `GET /api/me` — accessible uniquement si l'utilisateur est authentifié (token basique ou session) |
| **Compte de test** | `toto@example.com` / `pwd1234` |

### Modèle de données (TP1)

```
Table users :
  - id              BIGINT       AUTO_INCREMENT PRIMARY KEY
  - email           VARCHAR(255) UNIQUE NOT NULL
  - password_clear   VARCHAR(255) NOT NULL
  - created_at      DATETIME     NOT NULL
```

Le mot de passe est stocké **en clair** en base — c'est le danger principal de ce TP.

### Règles de mot de passe

Volontairement faibles : **minimum 4 caractères**, aucune autre exigence.

### Architecture imposée

- **Back-end :** Spring Boot API REST + MySQL
- **Client :** Java lourd (Swing/JavaFX)
- **Structure packages :** `com.example.auth` → `controller`, `service`, `repository`, `entity`, `exception`

### Gestion des exceptions (obligatoire dès TP1)

Trois exceptions personnalisées avec un `@ControllerAdvice` (`GlobalExceptionHandler`) qui renvoie du JSON cohérent :

| Exception | Code HTTP | Cas d'usage |
|---|---|---|
| `InvalidInputException` | **400** Bad Request | Email vide, format incorrect, mot de passe < 4 caractères |
| `AuthenticationFailedException` | **401** Unauthorized | Login échoué (email inconnu ou mot de passe incorrect) |
| `ResourceConflictException` | **409** Conflict | Email déjà existant à l'inscription |

Format de réponse JSON standardisé :
```json
{
  "timestamp": "2026-03-24T10:00:00",
  "status": 400,
  "error": "Bad Request",
  "message": "Email ne peut pas être vide",
  "path": "/api/auth/register"
}
```

### Tests JUnit obligatoires (minimum 8)

| # | Test | Statut dans le projet |
|---|---|---|
| 1 | Validation email vide | ✅ `testEmailVide()` |
| 2 | Validation format email incorrect | ✅ `testEmailFormatIncorrect()` |
| 3 | Validation mot de passe trop court | ✅ `testMotDePasseTropCourt()` |
| 4 | Inscription OK | ✅ `testInscriptionOK()` |
| 5 | Inscription refusée si email déjà existant | ✅ `testInscriptionEmailDejaExistant()` |
| 6 | Login OK | ✅ `testLoginOkHmacValide()` |
| 7 | Login KO si mot de passe incorrect | ✅ `testLoginKoHmacInvalide()` |
| 8 | Login KO si email inconnu | ✅ `testLoginKoUserInconnu()` |
| 9 | Accès `/api/me` refusé sans auth | ✅ `testApiMeSansTokenKo()` |
| 10 | Accès `/api/me` OK après login | ✅ `testTokenEmisEtApiMeOk()` |

### Qualité logicielle TP1

- **JavaDoc** obligatoire sur : `User`, `AuthService`, `AuthController`, exceptions — avec la phrase : *« Cette implémentation est volontairement dangereuse et ne doit jamais être utilisée en production. »*
- **Logging fichier** (`logs/auth.log`) : inscription réussie/échouée, connexion réussie/échouée — **jamais le mot de passe**
- **README** avec : instructions de lancement, compte de test, section « Analyse de sécurité TP1 » avec 5 risques majeurs

### 5 risques majeurs identifiés (TP1)

1. **Mot de passe stocké en clair** — base compromise = tous les mots de passe exposés
2. **Mot de passe transmis en clair** — écoute réseau (MITM) suffit à le capturer
3. **Aucune politique de mot de passe** — « abcd » est accepté → brute-force trivial
4. **Aucune protection anti brute-force** — tentatives illimitées
5. **Token de session non sécurisé** — UUID sans expiration, vol = accès permanent

### Tags Git imposés (TP1)

| Tag | Étape |
|---|---|
| `v1.0-init` | Projet vide Spring Boot + structure packages + README squelette |
| `v1.1-model` | Entité `User` + repository |
| `v1.2-register` | Endpoint `/api/auth/register` + exceptions + `@ControllerAdvice` |
| `v1.3-login` | Endpoint `/api/auth/login` + logging |
| `v1.4-protected` | Route `/api/me` + mécanisme de token basique |
| `v1-tp1` | TP1 final — qualité + JavaDoc + tous les tests verts |

---

## TP2 — Authentification Fragile

**Tag Git :** `v2-tp2`  
**Durée estimée :** 10 heures (1 semaine)

### Objectif pédagogique

Améliorer l'authentification du TP1 en ajoutant : une **politique de mot de passe stricte**, un **stockage serveur correct** (hash adaptatif BCrypt) et un **verrouillage anti brute-force**. Introduire **SonarCloud** pour la qualité. Malgré tout, l'authentification reste *fragile* car le secret circule encore dans la phase de login.

### Nouvelles fonctionnalités serveur

| Fonctionnalité | Détail | Implémentation dans le projet |
|---|---|---|
| **Politique de mot de passe** | 12 caractères min, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial | `PasswordPolicyValidator.java` — patterns regex compilés |
| **Hash adaptatif BCrypt** | Stockage `password_hash` au lieu de `password_clear` | Migration de la colonne en base |
| **Anti brute-force** | 5 échecs consécutifs → blocage 2 minutes | Champs `failed_attempts` + `lock_until` dans `User` |
| **Code HTTP verrouillage** | HTTP 429 (Too Many Requests) si compte bloqué | `GlobalExceptionHandler` détecte le message « bloqué » |

### Nouvelles fonctionnalités client (Swing)

| Fonctionnalité | Détail | Implémentation dans le projet |
|---|---|---|
| **Double saisie** | `password` + `passwordConfirm` côté client avant inscription | Champs `regPasswordField` + `regPasswordConfirmField` dans `AuthClientApp.java` |
| **Indicateur de force** | 🔴 Rouge (WEAK), 🟠 Orange (MEDIUM), 🟢 Vert (STRONG) | `JProgressBar` + méthode `evaluateStrength()` locale + appel serveur `/api/auth/password-strength` |
| **Vérification correspondance** | Message en temps réel « Les mots de passe correspondent / ne correspondent pas » | `DocumentListener` sur les deux champs |

### Tests JUnit obligatoires (minimum 10 + 2 recommandés)

Tous les tests TP1 + :

| # | Test supplémentaire | Statut |
|---|---|---|
| 11 | Non-divulgation : même message pour email inconnu et mauvais mot de passe | ✅ `testNonDivulgationErreur()` |
| 12 | Lockout expire correctement après la durée de blocage | ✅ `testLockoutExpireCorrectement()` |

### SonarCloud (obligatoire dès TP2)

- Corriger bugs majeurs, vulnérabilités majeures, code smells significatifs
- Quality Gate en succès (ou justification écrite dans le README)
- **Couverture de tests : objectif 60% minimum** (mesuré via JaCoCo)

### Faiblesse restante TP2

> *TP2 améliore le stockage mais ne protège pas encore contre le rejeu. Si un attaquant capture la requête de login, il peut tenter de la rejouer. Corrigé en TP3 avec HMAC + nonce + timestamp.*

### Tags Git imposés (TP2)

| Tag | Étape |
|---|---|
| `v2.0-start` | README mis à jour avec objectifs TP2 |
| `v2.1-db-migration` | `password_clear` → `password_hash` |
| `v2.2-password-policy` | `PasswordPolicyValidator` + tests |
| `v2.3-hashing` | BCrypt — inscription stocke hash, login vérifie |
| `v2.4-lockout` | `failed_attempts` + `lock_until` + tests |
| `v2.5-ui-strength` | Indicateur force rouge/orange/vert côté client |
| `v2.6-sonarcloud` | SonarCloud configuré + corrections |
| `v2-tp2` | TP2 final |

---

## TP3 — Authentification Forte

**Tag Git :** `v3-tp3`  
**Durée estimée :** 10 heures (1 semaine)

### Objectif pédagogique

Changer le **protocole d'authentification** : le mot de passe ne doit plus être transmis dans la requête de login (même en version hachée). Le client prouve qu'il connaît le secret **sans l'envoyer**. On introduit : clé secrète partagée, HMAC, nonce, timestamp, comparaison en temps constant et protection anti-rejeu.

> **Concept clé :** On passe de *« J'envoie un mot de passe »* à *« Je prouve que je connais un secret sans l'envoyer »*.

### Protocole HMAC-SHA256 en 2 étapes

#### Étape 1 — Côté client (`AuthClientApp.java`)

Le client collecte et calcule :
```
email      = saisie utilisateur
nonce      = UUID aléatoire (java.util.UUID)
timestamp  = Instant.now().getEpochSecond()
message    = email + ":" + nonce + ":" + timestamp
hmac       = HMAC_SHA256(key = password, data = message)
```

Le client envoie au serveur :
```json
POST /api/auth/login
{
  "email":     "user@example.com",
  "nonce":     "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1711234567,
  "hmac":      "Base64(HMAC_SHA256(...))"
}
```

**Le mot de passe ne circule jamais sur le réseau.**

#### Étape 2 — Côté serveur (`AuthService.login()`)

Vérifications obligatoires dans cet ordre :

| Étape | Vérification | Si échoue |
|---|---|---|
| 1 | Email existe en base | 401 |
| 2 | Compte non verrouillé (anti brute-force) | 401 / 429 |
| 3 | Timestamp dans la fenêtre ±60 secondes | 401 |
| 4 | Nonce non déjà utilisé (anti-rejeu) | 401 |
| 5 | Recalcul du HMAC : `HMAC_SHA256(key=password_serveur, data=email:nonce:timestamp)` | — |
| 6 | Comparaison en **temps constant** (`MessageDigest.isEqual()`) | 401 |
| 7 | Émission d'un token SSO Bearer (UUID, valide 15 minutes) | 200 + `{accessToken, expiresAt}` |

### Modèle de données (TP3)

```
Table users :
  - id, email, password_encrypted, failed_attempts, lock_until, created_at

Table auth_nonce :
  - id, user_id, nonce, expires_at, consumed, created_at
  - Contrainte UNIQUE sur (user_id, nonce)

Table access_tokens :
  - id, user_id, token (UUID unique), expires_at, created_at
```

### Durées configurées

| Paramètre | Valeur |
|---|---|
| Fenêtre timestamp | ±60 secondes |
| TTL nonce en base | 120 secondes |
| Validité access token | 15 minutes |

### Tests JUnit obligatoires (minimum 15, couverture ≥ 80%)

| # | Test | Statut |
|---|---|---|
| 1 | Login OK avec HMAC valide | ✅ `testLoginOkHmacValide()` |
| 2 | Login KO HMAC invalide | ✅ `testLoginKoHmacInvalide()` |
| 3 | KO timestamp expiré (passé) | ✅ `testLoginKoTimestampExpire()` |
| 4 | KO timestamp futur | ✅ `testLoginKoTimestampFutur()` |
| 5 | KO nonce déjà utilisé | ✅ `testLoginKoNonceDejaUtilise()` |
| 6 | KO user inconnu | ✅ `testLoginKoUserInconnu()` |
| 7 | Comparaison temps constant testée | ✅ `testComparaisonTempsConstant()` |
| 8 | Token émis et `/api/me` OK | ✅ `testTokenEmisEtApiMeOk()` |
| 9 | `/api/me` sans token KO | ✅ `testApiMeSansTokenKo()` |

### Limite restante TP3

> *Le mot de passe est stocké en clair en base pour permettre le recalcul HMAC. En industrie, on préfère un hash non réversible. Corrigé en TP4 avec chiffrement AES-GCM.*

### Tags Git imposés (TP3)

| Tag | Étape |
|---|---|
| `v3.0-start` | Démarrage TP3 |
| `v3.1-db-nonce` | Table `auth_nonce` |
| `v3.2-hmac-client` | Calcul HMAC côté client Swing |
| `v3.3-hmac-server` | Vérification HMAC côté serveur |
| `v3.4-anti-replay` | Protection anti-rejeu nonce |
| `v3.5-token` | Émission token SSO + `/api/me` |
| `v3.6-tests-80` | Couverture 80% + 15 tests |
| `v3-tp3` | TP3 final |

---

## TP4 — Industrialisation (Master Key + CI/CD)

**Tag Git :** `v4-tp4`  
**Durée estimée :** 10 heures (1 semaine)

### Objectif pédagogique

On ne modifie plus le protocole HMAC. On **industrialise** : protection des mots de passe au repos via une **Master Key**, et automatisation complète via **GitHub Actions** avec blocage des merges si qualité insuffisante.

### Partie 1 — Chiffrement AES-256-GCM par Master Key

#### Principe

Les mots de passe ne sont plus stockés en clair en base. Ils sont chiffrés avec une **Master Key** (variable d'environnement `APP_MASTER_KEY`) avant insertion.

#### Implémentation (`MasterKeyService.java`)

| Aspect | Détail |
|---|---|
| **Algorithme** | AES en mode GCM (Galois/Counter Mode) |
| **Taille de clé** | 256 bits (dérivée par SHA-256 de `APP_MASTER_KEY`) |
| **IV** | 12 octets aléatoires générés à chaque chiffrement (`SecureRandom`) |
| **Tag GCM** | 128 bits — garantit confidentialité + intégrité |
| **Format stockage** | `v1:Base64(iv):Base64(ciphertext)` |
| **Démarrage** | `@PostConstruct` → refus si `APP_MASTER_KEY` absente ou vide (`IllegalStateException`) |

#### Processus à l'inscription
```
password_plain → AES-GCM encrypt(APP_MASTER_KEY) → stockage password_encrypted
```

#### Processus au login
```
password_encrypted → AES-GCM decrypt(APP_MASTER_KEY) → password_plain → recalcul HMAC → vérification
```

#### Interdictions strictes

- ❌ Pas de clé codée en dur
- ❌ Pas d'IV fixe (un IV aléatoire est généré à chaque appel)
- ❌ Pas de mode ECB
- ❌ Pas de log de mot de passe

### Partie 2 — GitHub Actions CI/CD

Le fichier `.github/workflows/ci.yml` déclenche automatiquement sur chaque push / pull request vers `main` :

| Étape | Action | Bloquant ? |
|---|---|---|
| 1 | Checkout du code (historique complet pour SonarCloud) | — |
| 2 | Installation JDK 17 (Temurin) | — |
| 3 | Cache Maven | — |
| 4 | Build + Tests JUnit (H2 en mémoire, pas de MySQL) | ✅ Bloque si un test échoue |
| 5 | Analyse SonarCloud (`sonar.qualitygate.wait=true`) | ✅ Bloque si Quality Gate rouge |

#### Secrets GitHub à configurer

| Secret | Description |
|---|---|
| `SONAR_TOKEN` | Token SonarCloud |
| `SONAR_PROJECT_KEY` | Clé du projet (aussi dans `pom.xml` : `Andrimirana_auth-server`) |
| `SONAR_ORGANIZATION` | Organisation SonarCloud (`andrimirana`) |
| `APP_MASTER_KEY` | Optionnel — fallback sur clé de test fictive |

#### Gestion de la Master Key en CI

La clé réelle n'est **jamais exposée**. Pour les tests, une clé fictive est injectée :
```
APP_MASTER_KEY=test_master_key_for_ci_only_32chars
```

### Tests obligatoires liés à la Master Key

| # | Test | Statut |
|---|---|---|
| 1 | Démarrage KO si `APP_MASTER_KEY` absente | ✅ `testStartupKoIfMasterKeyAbsent()` (dans `MasterKeyAbsentTest.java`) |
| 2 | Encryption/decryption OK | ✅ `testMasterKeyEncryptDecryptOk()` |
| 3 | Mot de passe chiffré ≠ mot de passe clair | ✅ `testEncryptedDifferentFromClear()` |
| 4 | Déchiffrement KO si ciphertext modifié | ✅ `testDecryptKoIfCiphertextModified()` |
| 5 | Login OK avec mot de passe chiffré en base | ✅ `testLoginOkAvecMotDePasseChiffre()` |

---

## TP5 — Changement de mot de passe + Docker

**Tag Git :** `v5-tp5`  
**Durée estimée :** 10 heures (1 semaine)

### Objectif pédagogique

Ajouter une nouvelle fonctionnalité (**changement de mot de passe**) en conservant toutes les règles de sécurité du TP4, puis **conteneuriser** l'application avec Docker et automatiser le build de l'image dans la pipeline CI/CD.

### Nouvelle fonctionnalité — Changement de mot de passe

#### Endpoint

```
PUT /api/auth/change-password
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "oldPassword":     "AncienMotDePasse1!",
  "newPassword":     "NouveauMotDePasse2@",
  "confirmPassword": "NouveauMotDePasse2@"
}
```

#### Logique serveur (`AuthService.changePassword()`)

| Étape | Vérification | Si échoue |
|---|---|---|
| 1 | Token Bearer valide → identification de l'utilisateur | 401 |
| 2 | Déchiffrement AES-GCM du mot de passe stocké + comparaison avec `oldPassword` | 401 |
| 3 | `newPassword` == `confirmPassword` | 400 |
| 4 | Politique de sécurité sur `newPassword` (12 car., maj., min., chiffre, spécial) | 400 |
| 5 | Chiffrement AES-256-GCM du nouveau mot de passe + mise à jour en base | 200 |

#### Implémentation côté client (`AuthClientApp.java`)

- Vue dédiée « Changer le mot de passe » (`buildChangePasswordView()`)
- Saisie : ancien mot de passe + nouveau + confirmation
- Indicateur de force sur le nouveau mot de passe (rouge/orange/vert)
- Appel `PUT /api/auth/change-password` avec Bearer token
- Bouton de retour à la page d'accueil post-connexion

### Tests JUnit obligatoires (changement de mot de passe)

| # | Test | Statut |
|---|---|---|
| 1 | Changement réussi | ✅ `testChangementMotDePasseOk()` |
| 2 | Ancien mot de passe incorrect | ✅ `testChangementKoAncienMotDePasseIncorrect()` |
| 3 | Confirmation différente | ✅ `testChangementKoConfirmationDifferente()` |
| 4 | Mot de passe trop faible | ✅ `testChangementKoNouveauMotDePasseTropFaible()` |
| 5 | Token invalide (utilisateur inexistant) | ✅ `testChangementKoTokenInvalide()` |
| 6 | Endpoint HTTP `PUT /api/auth/change-password` → 200 | ✅ `testChangementMotDePasseEndpointOk()` |

### Conteneurisation Docker

#### Dockerfile (multi-stage build)

```dockerfile
# Étape 1 : Build Maven avec JDK 17 Alpine
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app
COPY mvnw mvnw.cmd pom.xml ./
COPY .mvn .mvn
RUN chmod +x ./mvnw
RUN ./mvnw dependency:go-offline -B
COPY src ./src
RUN ./mvnw package -DskipTests -B

# Étape 2 : Image finale légère avec JRE 17 Alpine
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/auth-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

#### Commandes Docker

```bash
# Construire l'image
docker build -t cdwfs-auth-app .

# Lancer le conteneur
docker run -p 8080:8080 \
  -e APP_MASTER_KEY=<votre_cle_base64_32_octets> \
  -e SPRING_DATASOURCE_URL=jdbc:mysql://host.docker.internal:3306/auth \
  cdwfs-auth-app
```

> ⚠️ `APP_MASTER_KEY` ne doit **JAMAIS** apparaître dans le Dockerfile ni dans l'image.

### Pipeline CI/CD mise à jour (TP5)

La pipeline GitHub Actions ajoute le build Docker en étape 6 :

| Étape | Action |
|---|---|
| 1-5 | Checkout → JDK 17 → Cache → Build + Tests → SonarCloud (identique TP4) |
| **6** | **Build de l'image Docker** (`docker build -t cdwfs-auth-app:$SHA .`) |
| **7** | **Tag `latest`** sur la branche `main` uniquement |

Le pipeline échoue si : un test échoue, le Quality Gate SonarCloud est rouge, ou le build Docker échoue.

### Tags Git imposés (TP5)

| Tag | Étape |
|---|---|
| `v5.0-start` | README TP5 |
| `v5.1-change-password` | Endpoint `PUT /api/auth/change-password` |
| `v5.2-tests` | Tests JUnit changement de mot de passe |
| `v5.3-docker` | Dockerfile Spring Boot |
| `v5.4-cicd-docker` | Pipeline CI/CD mise à jour avec Docker build |
| `v5-tp5` | TP5 final |

---

## Synthèse de l'évolution

| TP | Niveau | Stockage MDP | Protocole login | Protection | Qualité |
|---|---|---|---|---|---|
| **TP1** | Dangereuse | En clair | Email + MDP en clair | Aucune | 8 tests, JavaDoc, logs |
| **TP2** | Fragile | Hash BCrypt | Email + MDP (hash) | Anti brute-force (5 échecs → 2 min) | 10+ tests, SonarCloud, couverture 60% |
| **TP3** | Forte | En clair (pour HMAC) | HMAC-SHA256 + nonce + timestamp | Anti-rejeu + fenêtre temporelle | 15+ tests, couverture 80% |
| **TP4** | Industrielle | Chiffré AES-256-GCM | HMAC-SHA256 (identique TP3) | Master Key + CI/CD GitHub Actions | Quality Gate SonarCloud |
| **TP5** | Production | Chiffré AES-256-GCM | HMAC-SHA256 + change-password | Docker + pipeline complète | 42 tests, Docker build en CI |

### Évolution du schéma réseau

```
TP1 :  Client ---[ email + password_clair ]---> Serveur
TP2 :  Client ---[ email + password_hash  ]---> Serveur
TP3+:  Client ---[ email + nonce + timestamp + HMAC ]---> Serveur
                  (le mot de passe ne circule JAMAIS)
```

---

## Correspondance avec le projet

### Structure des fichiers

```
Auth_TP1_sonarcloud/
├── .github/workflows/ci.yml          ← Pipeline CI/CD (TP4/TP5)
├── DOC_TECHNIQUE.md                   ← Documentation technique détaillée
├── rule.md                            ← Cahier des charges des 5 TP
├── run-sonar.ps1                      ← Script PowerShell pour SonarCloud
│
├── auth/                              ← SERVEUR Spring Boot
│   ├── Dockerfile                     ← Conteneurisation (TP5)
│   ├── pom.xml                        ← Maven + Spring Boot 3.2.5 + JaCoCo + SonarCloud
│   ├── Readme.md                      ← README serveur complet
│   ├── logs/auth.log                  ← Fichier de logs (TP1+)
│   └── src/
│       ├── main/java/com/example/auth/
│       │   ├── AuthApplication.java
│       │   ├── config/SecurityConfig.java
│       │   ├── controller/
│       │   │   ├── AuthController.java        ← register, login, password-strength, change-password
│       │   │   └── UserController.java        ← /api/me
│       │   ├── dto/
│       │   │   ├── LoginRequest.java          ← email, nonce, timestamp, hmac
│       │   │   ├── LoginResponse.java         ← accessToken, expiresAt
│       │   │   ├── RegisterRequest.java       ← email, password, passwordConfirm
│       │   │   └── ChangePasswordRequest.java ← oldPassword, newPassword, confirmPassword
│       │   ├── entity/
│       │   │   ├── User.java                  ← id, email, password_encrypted, failed_attempts, lock_until
│       │   │   ├── AccessToken.java           ← id, user_id, token, expires_at (15 min)
│       │   │   └── AuthNonce.java             ← id, user_id, nonce, expires_at (120s), consumed
│       │   ├── exception/
│       │   │   ├── GlobalExceptionHandler.java ← @ControllerAdvice JSON
│       │   │   ├── InvalidInputException.java  ← 400
│       │   │   ├── AuthenticationFailedException.java ← 401 / 429
│       │   │   └── ResourceConflictException.java     ← 409
│       │   ├── repository/
│       │   │   ├── UserRepository.java
│       │   │   ├── AccessTokenRepository.java
│       │   │   └── AuthNonceRepository.java
│       │   └── service/
│       │       ├── AuthService.java           ← Logique métier register + login + changePassword
│       │       ├── HmacService.java           ← compute() + compare() temps constant
│       │       ├── TokenService.java          ← generate() + getUserByToken()
│       │       ├── PasswordPolicyValidator.java ← validate() + evaluateStrength()
│       │       └── MasterKeyService.java      ← encrypt() + decrypt() AES-256-GCM
│       ├── main/resources/application.properties ← MySQL + logs + APP_MASTER_KEY
│       └── test/
│           ├── java/.../AuthApplicationTests.java ← 42 tests (TP1 à TP5)
│           ├── java/.../MasterKeyAbsentTest.java  ← Test démarrage KO sans Master Key
│           └── resources/application.properties   ← H2 en mémoire + clé fictive
│
└── auth-client/                       ← CLIENT Swing
    ├── pom.xml
    ├── Readme.md
    └── src/main/java/org/example/
        ├── Main.java                  ← Point d'entrée SwingUtilities.invokeLater
        └── AuthClientApp.java         ← UI complète : login HMAC, register, change-password, force MDP
```

### Bilan des tests : 42 tests + 1 = 43 tests au total

| Catégorie | Nombre | Fichier |
|---|---|---|
| Inscription (validation, OK, conflit) | 6 | `AuthApplicationTests.java` |
| Login HMAC (OK, KO, timestamp, nonce, user inconnu) | 6 | `AuthApplicationTests.java` |
| Token + `/api/me` (Bearer, sans token, token invalide) | 5 | `AuthApplicationTests.java` |
| Non-divulgation + lockout | 2 | `AuthApplicationTests.java` |
| Force mot de passe (WEAK, MEDIUM, STRONG) | 3 | `AuthApplicationTests.java` |
| Politique (sans majuscule, sans minuscule, sans chiffre, sans spécial) | 4 | `AuthApplicationTests.java` |
| Endpoints HTTP (register, doublon, password-strength) | 3 | `AuthApplicationTests.java` |
| Master Key (encrypt/decrypt, format, intégrité, login chiffré) | 4 | `AuthApplicationTests.java` |
| Démarrage KO sans Master Key | 1 | `MasterKeyAbsentTest.java` |
| Changement de mot de passe (OK, ancien KO, confirm KO, faible, token KO, endpoint) | 6 | `AuthApplicationTests.java` |
| Endpoints MockMvc `/api/me` (Bearer OK, sans header, non-Bearer, token invalide) | 4 | `AuthApplicationTests.java` |
| **TOTAL** | **43** | |

