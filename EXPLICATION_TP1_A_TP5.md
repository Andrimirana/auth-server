# Explication des 5 TP — Serveur d'Authentification

> **Parcours :** CDWFS — D. Samfat — Travail individuel  
> **Projet :** API REST sécurisée — Java 17 · Spring Boot 3.2.5 · MySQL  
> **Objectif global :** Construire progressivement une authentification dangereuse → fragile → forte → industrielle → déployée.

---

## Table des matières

1. [TP1 — Authentification Dangereuse](#tp1--authentification-dangereuse)
2. [TP2 — Authentification Fragile](#tp2--authentification-fragile)
3. [TP3 — Authentification Forte](#tp3--authentification-forte)
4. [TP4 — Industrialisation (Master Key + CI/CD)](#tp4--industrialisation-master-key--cicd)
5. [TP5 — Changement de mot de passe + Docker](#tp5--changement-de-mot-de-passe--docker)
6. [Synthèse comparative](#synthèse-comparative)
7. [Structure du projet](#structure-du-projet)

---

## TP1 — Authentification Dangereuse

**Tag Git final :** `v1-tp1` | **Durée :** 10 heures

### Pourquoi « dangereuse » ?

Ce TP implémente une authentification qui **fonctionne** mais qui est **inacceptable en production** :
- Le mot de passe est stocké **en clair** dans la base de données
- Le mot de passe est transmis **en clair** sur le réseau
- Les règles de mot de passe sont volontairement très faibles (4 caractères minimum)

Le but pédagogique est de **comprendre les risques** avant de les corriger dans les TP suivants.

---

### Fonctionnalités à implémenter

| Endpoint | Méthode | Description |
|---|---|---|
| `/api/auth/register` | `POST` | Inscription avec email + mot de passe |
| `/api/auth/login` | `POST` | Connexion — retourne succès ou échec |
| `/api/me` | `GET` | Route protégée — accessible uniquement si authentifié |

**Compte de test obligatoire :** `toto@example.com` / `pwd1234`

**Authentification :** session HTTP simple ou token basique (UUID) généré côté serveur et stocké en base.

---

### Modèle de données

```sql
CREATE TABLE users (
  id             BIGINT AUTO_INCREMENT PRIMARY KEY,
  email          VARCHAR(255) UNIQUE NOT NULL,
  password_clear VARCHAR(255) NOT NULL,         -- ⚠️ En clair, volontairement dangereux
  created_at     DATETIME NOT NULL
);
```

---

### Architecture Spring Boot imposée

```
com.example.auth/
├── controller/   → AuthController, UserController
├── service/      → AuthService
├── repository/   → UserRepository
├── entity/       → User
└── exception/    → GlobalExceptionHandler (@ControllerAdvice)
                    InvalidInputException
                    AuthenticationFailedException
                    ResourceConflictException
```

**Client :** application Java lourde (Swing / JavaFX / WindowBuilder)

---

### Gestion des exceptions (obligatoire dès TP1)

Toutes les erreurs retournent un **JSON standardisé** :

```json
{
  "timestamp": "2026-03-24T10:00:00",
  "status": 400,
  "error": "Bad Request",
  "message": "Email ne peut pas être vide",
  "path": "/api/auth/register"
}
```

| Exception | Code HTTP | Déclenchée quand |
|---|---|---|
| `InvalidInputException` | `400` | Email vide/invalide, mot de passe trop court |
| `AuthenticationFailedException` | `401` | Email inconnu ou mot de passe incorrect |
| `ResourceConflictException` | `409` | Email déjà existant à l'inscription |

---

### Tests JUnit (minimum 8 obligatoires)

| # | Test |
|---|---|
| 1 | Validation email vide → 400 |
| 2 | Validation format email incorrect → 400 |
| 3 | Validation mot de passe < 4 caractères → 400 |
| 4 | Inscription OK → 200 |
| 5 | Inscription refusée si email déjà existant → 409 |
| 6 | Login OK → succès |
| 7 | Login KO si mot de passe incorrect → 401 |
| 8 | Login KO si email inconnu → 401 |
| 9 | Accès `/api/me` refusé sans token → 401 |
| 10 | Accès `/api/me` OK après login → 200 |

---

### Qualité logicielle TP1

- **JavaDoc** obligatoire sur `User`, `AuthService`, `AuthController`, toutes les exceptions  
  → Phrase obligatoire : *« Cette implémentation est volontairement dangereuse et ne doit jamais être utilisée en production. »*
- **Logging fichier** (`logs/auth.log`) : inscription/connexion réussie ou échouée — **jamais le mot de passe en clair**
- **README** : instructions de lancement, compte de test, section « Analyse de sécurité TP1 » avec **5 risques majeurs** expliqués

**5 risques majeurs à documenter :**

| # | Risque |
|---|---|
| 1 | Mot de passe stocké en clair — base compromise = tous les mots de passe exposés |
| 2 | Mot de passe transmis en clair — écoute réseau (MITM) suffit à le capturer |
| 3 | Aucune politique de mot de passe — « abcd » accepté → brute-force trivial |
| 4 | Aucune protection anti brute-force — tentatives illimitées |
| 5 | Token de session non sécurisé — UUID sans expiration, vol = accès permanent |

---

### Tags Git imposés (TP1)

| Tag | Contenu |
|---|---|
| `v1.0-init` | Projet vide Spring Boot + structure packages + README squelette |
| `v1.1-model` | Entité `User` + repository |
| `v1.2-register` | `/api/auth/register` + exceptions + `@ControllerAdvice` |
| `v1.3-login` | `/api/auth/login` + logging |
| `v1.4-protected` | `/api/me` + mécanisme token basique |
| `v1-tp1` | TP1 final — JavaDoc + tous les tests verts |

---

## TP2 — Authentification Fragile

**Tag Git final :** `v2-tp2` | **Durée :** 10 heures

### Pourquoi « fragile » ?

TP2 améliore **le stockage** du mot de passe (BCrypt au lieu du clair) et renforce les règles de sécurité, mais **le protocole reste vulnérable** : le secret dérivé du mot de passe circule encore dans la requête de login. Une requête capturée peut être rejouée. Ce problème sera corrigé au TP3.

---

### Nouvelles fonctionnalités — Côté Serveur

| Fonctionnalité | Détail |
|---|---|
| **Politique de mot de passe** | 12 caractères min, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial |
| **Hash BCrypt adaptatif** | Le champ `password_clear` est **supprimé**, remplacé par `password_hash` |
| **Anti brute-force** | 5 échecs consécutifs → compte bloqué **2 minutes** → HTTP `429` |

**Nouveaux champs dans `users` :**

```sql
ALTER TABLE users
  DROP COLUMN password_clear,
  ADD COLUMN password_hash     VARCHAR(255) NOT NULL,
  ADD COLUMN failed_attempts   INT DEFAULT 0,
  ADD COLUMN lock_until        DATETIME;
```

---

### Nouvelles fonctionnalités — Côté Client (Swing)

| Fonctionnalité | Détail |
|---|---|
| **Double saisie** | Champs `password` + `passwordConfirm` avant inscription |
| **Indicateur de force** | 🔴 Faible / 🟠 Moyen / 🟢 Fort — mis à jour en temps réel |
| **Vérification correspondance** | Message « Les mots de passe correspondent / ne correspondent pas » |

---

### Tests JUnit (minimum 10 + 2 recommandés)

Tous les tests TP1 conservés, plus :

| # | Test supplémentaire |
|---|---|
| 11 | Non-divulgation : même message d'erreur pour email inconnu ET mauvais mot de passe |
| 12 | Le lockout expire correctement après la durée de blocage |

---

### SonarCloud (obligatoire dès TP2)

**Première analyse qualité industrielle.** À corriger obligatoirement :
- Bugs majeurs
- Vulnérabilités majeures
- Code smells sur : gestion des exceptions, validation, duplication, complexité

**Objectif :** Quality Gate en succès (ou justification écrite dans README si blocage).  
**Couverture de tests :** minimum **60 %** mesurée avec JaCoCo.

---

### Tags Git imposés (TP2)

| Tag | Contenu |
|---|---|
| `v2.0-start` | README mis à jour — objectifs TP2 |
| `v2.1-db-migration` | `password_clear` → `password_hash` |
| `v2.2-password-policy` | `PasswordPolicyValidator` + tests |
| `v2.3-hashing` | BCrypt — inscription stocke hash, login vérifie |
| `v2.4-lockout` | `failed_attempts` + `lock_until` + tests |
| `v2.5-ui-strength` | Indicateur force rouge/orange/vert côté client |
| `v2.6-sonarcloud` | SonarCloud configuré + corrections + section README |
| `v2-tp2` | TP2 final |

---

## TP3 — Authentification Forte

**Tag Git final :** `v3-tp3` | **Durée :** 10 heures

### Pourquoi « forte » ?

TP3 change complètement le **protocole d'authentification**. Le mot de passe ne circule plus jamais sur le réseau — même sous forme hachée. Le client **prouve** qu'il connaît le secret sans l'envoyer, grâce à HMAC-SHA256 + nonce + timestamp.

> **Concept clé :** On passe de *« J'envoie mon mot de passe »* à *« Je prouve que je connais un secret sans l'envoyer »*.

---

### Protocole HMAC-SHA256 en 2 étapes

#### Étape 1 — Client (`AuthClientApp.java`)

```
email     = saisie utilisateur
nonce     = UUID.randomUUID()           ← unique à chaque requête
timestamp = Instant.now().getEpochSecond()
message   = email + ":" + nonce + ":" + timestamp
hmac      = HMAC_SHA256(key=password, data=message)
```

**Le client envoie :**

```json
POST /api/auth/login
{
  "email":     "user@example.com",
  "nonce":     "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1711234567,
  "hmac":      "Base64(HMAC_SHA256(...))"
}
```

⚠️ **Le mot de passe ne circule jamais sur le réseau.**

#### Étape 2 — Serveur (`AuthService.login()`)

Vérifications dans cet ordre précis :

| Ordre | Vérification | Échec → |
|---|---|---|
| 1 | Email existe en base | `401` |
| 2 | Timestamp dans la fenêtre **±60 secondes** | `401` |
| 3 | Nonce **non encore utilisé** pour cet utilisateur | `401` |
| 4 | Enregistrer/réserver le nonce | — |
| 5 | Recalcul : `HMAC_SHA256(key=password_serveur, data=email:nonce:timestamp)` | — |
| 6 | Comparaison en **temps constant** (`MessageDigest.isEqual()`) | `401` |
| 7 | Marquer nonce comme consommé | — |
| 8 | Émettre token Bearer (UUID, valide **15 minutes**) | `200 + {accessToken, expiresAt}` |

---

### Modèle de données (TP3)

```sql
CREATE TABLE auth_nonce (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id    BIGINT NOT NULL,
  nonce      VARCHAR(36) NOT NULL,
  expires_at DATETIME NOT NULL,        -- now + 120 secondes
  consumed   BOOLEAN DEFAULT FALSE,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uk_user_nonce (user_id, nonce)
);

CREATE TABLE access_tokens (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id    BIGINT NOT NULL,
  token      VARCHAR(36) UNIQUE NOT NULL,
  expires_at DATETIME NOT NULL,        -- now + 15 minutes
  created_at DATETIME NOT NULL
);
```

---

### Durées configurées

| Paramètre | Valeur |
|---|---|
| Fenêtre timestamp acceptée | ± 60 secondes |
| TTL nonce en base | 120 secondes |
| Validité access token | 15 minutes |

---

### Tests JUnit (minimum 15, couverture ≥ 80 %)

| # | Test |
|---|---|
| 1 | Login OK avec HMAC valide |
| 2 | Login KO — HMAC invalide → 401 |
| 3 | Login KO — timestamp expiré (> 60s) → 401 |
| 4 | Login KO — timestamp futur (> 60s) → 401 |
| 5 | Login KO — nonce déjà utilisé (anti-rejeu) → 401 |
| 6 | Login KO — utilisateur inconnu → 401 |
| 7 | Comparaison en temps constant (pas de fuite par timing) |
| 8 | Token émis → accès `/api/me` OK |
| 9 | Accès `/api/me` sans token → 401 |

---

### Limite restante TP3

> Le mot de passe est encore stocké de manière récupérable en base pour permettre le recalcul HMAC côté serveur. En industrie, on préfère un chiffrement réversible avec clé. **Corrigé en TP4 avec AES-256-GCM.**

---

### Tags Git imposés (TP3)

| Tag | Contenu |
|---|---|
| `v3.0-start` | Démarrage TP3 |
| `v3.1-db-nonce` | Table `auth_nonce` |
| `v3.2-hmac-client` | Calcul HMAC côté client Swing |
| `v3.3-hmac-server` | Vérification HMAC côté serveur |
| `v3.4-anti-replay` | Protection anti-rejeu nonce |
| `v3.5-token` | Émission token Bearer + `/api/me` |
| `v3.6-tests-80` | 15 tests + couverture 80 % |
| `v3-tp3` | TP3 final |

---

## TP4 — Industrialisation (Master Key + CI/CD)

**Tag Git final :** `v4-tp4` | **Durée :** 10 heures

### Objectif

**On ne change plus le protocole** HMAC/nonce/timestamp. On industrialise sur deux axes :
1. **Protection des mots de passe au repos** → chiffrement AES-256-GCM avec une Master Key
2. **Automatisation de la qualité** → pipeline GitHub Actions avec blocage si qualité insuffisante

---

### Partie 1 — Chiffrement AES-256-GCM (Master Key)

#### Principe

Les mots de passe ne sont plus stockés en clair. Ils sont **chiffrés** avec une clé (`APP_MASTER_KEY`) fournie par l'administrateur via variable d'environnement. Si la clé est absente, **l'application refuse de démarrer**.

#### Implémentation — `MasterKeyService.java`

| Aspect | Détail |
|---|---|
| Algorithme | `AES/GCM/NoPadding` (confidentialité + intégrité) |
| Clé | SHA-256(`APP_MASTER_KEY`) → 256 bits |
| IV | 12 octets aléatoires (`SecureRandom`) — **différent à chaque chiffrement** |
| Tag GCM | 128 bits |
| Format stocké | `v1:Base64(iv):Base64(ciphertext)` |
| Démarrage | `@PostConstruct` → `IllegalStateException` si `APP_MASTER_KEY` absente |

#### Flux à l'inscription

```
[mot de passe saisi]
      ↓
AES-256-GCM encrypt(APP_MASTER_KEY)
      ↓
password_encrypted stocké en base
```

#### Flux au login

```
password_encrypted (base)
      ↓
AES-256-GCM decrypt(APP_MASTER_KEY)
      ↓
password_plain récupéré
      ↓
Recalcul HMAC → vérification (protocole TP3 inchangé)
```

#### Règle absolue

```
APP_MASTER_KEY → variable d'environnement UNIQUEMENT
                  ❌ jamais dans le code
                  ❌ jamais dans le Dockerfile
                  ❌ jamais loggée
                  ❌ jamais commitée
```

---

### Partie 2 — Pipeline GitHub Actions CI/CD

Fichier : `.github/workflows/ci.yml`

**Déclencheurs :** push sur `main` + pull request vers `main`

| Étape | Action | Bloquant ? |
|---|---|---|
| 1 | Checkout (`fetch-depth: 0` requis par SonarCloud) | — |
| 2 | Installation JDK 17 Temurin | — |
| 3 | Cache Maven (`~/.m2/repository`) | — |
| 4 | `chmod +x mvnw` (droits Ubuntu) | — |
| 5 | `mvn verify` — Build + Tests JUnit (H2 en mémoire) | ✅ **Bloque** si un test échoue |
| 6 | `mvn sonar:sonar` — Analyse SonarCloud | ✅ **Bloque** si Quality Gate rouge |

**Secrets à configurer dans GitHub :**  
`Settings → Secrets and variables → Actions`

| Secret | Description |
|---|---|
| `SONAR_TOKEN` | Token généré sur [sonarcloud.io/account/security](https://sonarcloud.io/account/security) |
| `SONAR_PROJECT_KEY` | Clé du projet SonarCloud (ex : `Andrimirana_auth-server`) |
| `SONAR_ORGANIZATION` | Organisation SonarCloud (ex : `andrimirana`) |
| `APP_MASTER_KEY` | Optionnel — une clé fictive est utilisée en fallback pour les tests |

**Gestion de la Master Key en CI :**  
La clé réelle n'est **jamais exposée**. Les tests utilisent une clé fictive injectée via le profil `test` :
```
APP_MASTER_KEY=test_master_key_for_ci_only
```

---

### Tests obligatoires — Master Key

| # | Test |
|---|---|
| 1 | Démarrage KO si `APP_MASTER_KEY` absente (`MasterKeyAbsentTest.java`) |
| 2 | Chiffrement/déchiffrement OK — texte récupéré intact |
| 3 | Mot de passe chiffré ≠ mot de passe clair |
| 4 | Déchiffrement KO si le ciphertext est modifié (intégrité GCM) |
| 5 | Login OK avec mot de passe chiffré en base |

---

### Tags Git imposés (TP4)

| Tag | Contenu |
|---|---|
| `v4.0-start` | Démarrage TP4 |
| `v4.1-master-key` | `MasterKeyService` AES-256-GCM |
| `v4.2-encrypt-db` | Inscription chiffre le mot de passe en base |
| `v4.3-decrypt-login` | Login déchiffre avant recalcul HMAC |
| `v4.4-tests-key` | Tests Master Key |
| `v4.5-github-actions` | Pipeline CI/CD `.github/workflows/ci.yml` |
| `v4-tp4` | TP4 final |

---

## TP5 — Changement de mot de passe + Docker

**Tag Git final :** `v5-tp5` | **Durée :** 10 heures

### Objectif

Deux axes :
1. **Nouvelle fonctionnalité** : changement de mot de passe sécurisé (toutes les règles TP4 conservées)
2. **Conteneurisation** : Dockerfile multi-stage + intégration dans la pipeline CI/CD

---

### Partie 1 — Endpoint Changement de mot de passe

```
PUT /api/auth/change-password
Authorization: Bearer <accessToken>
Content-Type: application/json
```

```json
{
  "oldPassword":     "AncienMotDePasse1!",
  "newPassword":     "NouveauMotDePasse2@",
  "confirmPassword": "NouveauMotDePasse2@"
}
```

#### Logique serveur — `AuthService.changePassword()`

| Ordre | Vérification | Échec → |
|---|---|---|
| 1 | Token Bearer valide → utilisateur identifié | `401` |
| 2 | Déchiffrement AES-GCM + comparaison avec `oldPassword` | `401` |
| 3 | `newPassword` == `confirmPassword` | `400` |
| 4 | Politique de sécurité sur `newPassword` (12 car., maj., min., chiffre, spécial) | `400` |
| 5 | Chiffrement AES-256-GCM + mise à jour en base | `200` |

#### Côté Client (Swing)

- Vue dédiée « Changer le mot de passe » accessible après connexion
- Champs : ancien mot de passe + nouveau + confirmation
- Indicateur de force rouge/orange/vert sur le nouveau mot de passe
- Appel `PUT /api/auth/change-password` avec header `Authorization: Bearer <token>`

---

### Tests JUnit — Changement de mot de passe

| # | Test |
|---|---|
| 1 | Changement réussi → 200 |
| 2 | Ancien mot de passe incorrect → 401 |
| 3 | `newPassword` ≠ `confirmPassword` → 400 |
| 4 | Nouveau mot de passe trop faible → 400 |
| 5 | Token invalide (utilisateur inexistant) → 401 |
| 6 | Endpoint HTTP `PUT /api/auth/change-password` → 200 |

---

### Partie 2 — Conteneurisation Docker

#### Dockerfile (multi-stage build)

```dockerfile
# ── Étape 1 : Build Maven ──────────────────────────────────
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app
COPY mvnw mvnw.cmd pom.xml ./
COPY .mvn .mvn
RUN chmod +x ./mvnw
RUN ./mvnw dependency:go-offline -B      # Cache des dépendances Maven
COPY src ./src
RUN ./mvnw package -DskipTests -B        # Build du JAR (tests déjà faits en CI)

# ── Étape 2 : Image finale légère ─────────────────────────
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/auth-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
ENV SPRING_PROFILES_ACTIVE=prod
ENTRYPOINT ["java", "-jar", "app.jar"]
```

> ⚠️ `APP_MASTER_KEY` n'est **jamais** dans le Dockerfile — elle est injectée au démarrage du conteneur via `-e`.

#### Commandes Docker

```bash
# 1. Construire l'image
docker build -t cdwfs-auth-app .

# 2. Lancer le conteneur
docker run -p 8080:8080 \
  -e APP_MASTER_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" \
  -e SPRING_DATASOURCE_URL="jdbc:mysql://host.docker.internal:3306/auth" \
  cdwfs-auth-app

# 3. Vérifier que le conteneur tourne
docker ps
```

#### Docker Desktop sur Windows

| Contexte | Docker Desktop requis ? |
|---|---|
| GitHub Actions (`ubuntu-latest`) | ❌ Non — Docker pré-installé sur Ubuntu |
| **Windows en local** | ✅ **Oui — obligatoire** pour `docker build` et `docker run` |

> L'installeur `DockerDesktopInstaller.exe` est fourni dans le projet.

---

### Pipeline CI/CD mise à jour (TP5)

La pipeline TP4 est conservée intégralement, avec **2 étapes Docker ajoutées** :

| Étape | Action | Bloquant ? |
|---|---|---|
| 1–5 | Identique TP4 (checkout → JDK → cache → tests → SonarCloud) | ✅ |
| **6** | **`docker build -t cdwfs-auth-app:$SHA .`** | ✅ **Bloque** si Dockerfile invalide |
| **7** | **Tag `latest`** sur `main` uniquement | — |

---

### Tags Git imposés (TP5)

| Tag | Contenu |
|---|---|
| `v5.0-start` | README TP5 + branche `tp5-change-password` |
| `v5.1-change-password` | Endpoint `PUT /api/auth/change-password` |
| `v5.2-tests` | Tests JUnit changement de mot de passe |
| `v5.3-docker` | Dockerfile multi-stage |
| `v5.4-cicd-docker` | Pipeline CI/CD mise à jour avec `docker build` |
| `v5-tp5` | TP5 final |

---

## Synthèse comparative

| | TP1 | TP2 | TP3 | TP4 | TP5 |
|---|---|---|---|---|---|
| **Niveau** | Dangereuse | Fragile | Forte | Industrielle | Production |
| **Stockage MDP** | En clair | Hash BCrypt | Récupérable (HMAC) | Chiffré AES-256-GCM | Chiffré AES-256-GCM |
| **Protocole login** | Email + MDP en clair | Email + MDP hashé | HMAC + nonce + timestamp | HMAC + nonce + timestamp | HMAC + nonce + timestamp |
| **Anti brute-force** | ❌ | ✅ 5 échecs → 2 min | ✅ | ✅ | ✅ |
| **Anti-rejeu** | ❌ | ❌ | ✅ nonce en base | ✅ | ✅ |
| **MDP sur le réseau** | ✅ En clair | ✅ Hash | ❌ Jamais | ❌ Jamais | ❌ Jamais |
| **CI/CD** | ❌ | ❌ | ❌ | ✅ GitHub Actions | ✅ + Docker build |
| **Conteneurisation** | ❌ | ❌ | ❌ | ❌ | ✅ Docker |
| **Tests minimum** | 8 | 10 | 15 | 15+ | 15+ |
| **Couverture** | — | 60 % | 80 % | Quality Gate vert | Quality Gate vert |

### Évolution du protocole réseau

```
TP1 :  Client ──[ email + password_clair ]──────────────────────────▶ Serveur
TP2 :  Client ──[ email + BCrypt(password) ]────────────────────────▶ Serveur
TP3+ : Client ──[ email + nonce + timestamp + HMAC(password) ]──────▶ Serveur
                  └─ Le mot de passe ne circule JAMAIS sur le réseau ─┘
```

---

## Structure du projet

```
Auth_TP1_sonarcloud/
│
├── .github/workflows/ci.yml              ← Pipeline CI/CD (TP4/TP5)
├── DockerDesktopInstaller.exe             ← Installeur Docker Desktop Windows (TP5)
├── run-sonar.ps1                          ← Script PowerShell analyse SonarCloud locale
├── rule.md                                ← Cahier des charges des 5 TP
│
├── auth/                                  ← ★ SERVEUR Spring Boot
│   ├── Dockerfile                         ← Conteneurisation multi-stage (TP5)
│   ├── pom.xml                            ← Spring Boot 3.2.5 + JaCoCo + SonarCloud
│   ├── logs/auth.log                      ← Fichier de logs applicatifs
│   └── src/
│       ├── main/java/com/example/auth/
│       │   ├── AuthApplication.java
│       │   ├── config/SecurityConfig.java
│       │   ├── controller/
│       │   │   ├── AuthController.java        ← register, login, password-strength, change-password
│       │   │   └── UserController.java        ← /api/me
│       │   ├── dto/
│       │   │   ├── LoginRequest.java          ← { email, nonce, timestamp, hmac }
│       │   │   ├── LoginResponse.java         ← { accessToken, expiresAt }
│       │   │   ├── RegisterRequest.java       ← { email, password, passwordConfirm }
│       │   │   └── ChangePasswordRequest.java ← { oldPassword, newPassword, confirmPassword }
│       │   ├── entity/
│       │   │   ├── User.java                  ← id, email, password_encrypted, failed_attempts, lock_until
│       │   │   ├── AccessToken.java           ← id, user_id, token, expires_at (15 min)
│       │   │   └── AuthNonce.java             ← id, user_id, nonce, expires_at (120s), consumed
│       │   ├── exception/
│       │   │   ├── GlobalExceptionHandler.java      ← @ControllerAdvice → JSON standardisé
│       │   │   ├── InvalidInputException.java        ← 400
│       │   │   ├── AuthenticationFailedException.java ← 401 / 429
│       │   │   └── ResourceConflictException.java    ← 409
│       │   ├── repository/
│       │   │   ├── UserRepository.java
│       │   │   ├── AccessTokenRepository.java
│       │   │   └── AuthNonceRepository.java
│       │   └── service/
│       │       ├── AuthService.java               ← register + login + changePassword
│       │       ├── HmacService.java               ← compute() + comparaison temps constant
│       │       ├── TokenService.java              ← generate() + getUserByToken()
│       │       ├── PasswordPolicyValidator.java   ← validate() + evaluateStrength()
│       │       └── MasterKeyService.java          ← encrypt() + decrypt() AES-256-GCM
│       ├── main/resources/application.properties  ← MySQL prod + APP_MASTER_KEY
│       └── test/
│           ├── java/.../AuthApplicationTests.java     ← Tests principaux (TP1 → TP5)
│           ├── java/.../MasterKeyAbsentTest.java      ← Démarrage KO sans Master Key
│           └── resources/application.properties       ← H2 en mémoire + clé fictive CI
│
└── auth-client/                           ← ★ CLIENT Java Swing
    └── src/main/java/org/example/
        ├── Main.java                      ← Point d'entrée SwingUtilities.invokeLater
        └── AuthClientApp.java             ← UI : login HMAC, inscription, changement MDP
```
