# Serveur d'Authentification HMAC-SHA256

> **Parcours :** CDWFS — D. Samfat  
> **Framework :** Spring Boot 3.2.5 — Java 17  
> **Base de données :** MySQL (prod) / H2 (tests)  
> **Qualité :** SonarCloud — `Andrimirana_auth-server`

---

## Demarrage rapide

### Prerequis

- Java 17
- Maven 3.9+
- MySQL 8.x (pour la production)
- Docker Desktop (pour TP5)

### 1. Configurer MySQL

```sql
CREATE DATABASE auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Editer `src/main/resources/application.properties` si necessaire :

```properties
spring.datasource.username=root
spring.datasource.password=votre_mot_de_passe
```

### 2. Definir la Master Key

```powershell
$env:APP_MASTER_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
```

### 3. Lancer l'API

```powershell
mvn spring-boot:run
```

L'API est disponible sur `http://localhost:8080`.

### 4. Lancer les tests (H2, sans MySQL)

```powershell
$env:APP_MASTER_KEY = "test_master_key_for_ci_only_32chars__"
mvn clean verify -Dspring.profiles.active=test
```

---

## Compte de test obligatoire

| Email | Mot de passe |
|---|---|
| `toto@example.com` | `TestPassword1!` |

---

## Client Java (Swing)

```powershell
cd auth-client
mvn spring-boot:run
```

Le client se connecte automatiquement sur `http://localhost:8080`.

---

## Docker (TP5)

```powershell
# Construire l'image
docker build -t cdwfs-auth-app .

# Lancer le conteneur
docker run -p 8080:8080 `
  -e APP_MASTER_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" `
  -e SPRING_DATASOURCE_URL="jdbc:mysql://host.docker.internal:3306/auth" `
  cdwfs-auth-app
```

---

## Endpoints API

| Methode | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/api/auth/register` | Inscription | Non |
| POST | `/api/auth/login` | Connexion HMAC-SHA256 | Non |
| POST | `/api/auth/password-strength` | Force du mot de passe | Non |
| PUT | `/api/auth/change-password` | Changement mot de passe | Bearer |
| GET | `/api/me` | Infos utilisateur connecte | Bearer |

---

## Qualite SonarCloud

```powershell
.\run-sonar.ps1 -Token "sqp_votre_token"
```

Resultats : https://sonarcloud.io/project/overview?id=Andrimirana_auth-server

---

## Analyse de securite TP1

> Cette implementation est volontairement dangereuse et ne doit jamais etre utilisee en production.

| # | Risque | Impact |
|---|---|---|
| 1 | **Mot de passe stocke en clair (TP1)** | Base compromise = tous les mots de passe exposes en clair |
| 2 | **Mot de passe transmis en clair sur le reseau (TP1)** | Ecoute reseau (MITM) suffit a capturer le mot de passe |
| 3 | **Aucune politique de mot de passe (TP1)** | "abcd" accepte, brute-force trivial |
| 4 | **Aucune protection anti brute-force (TP1)** | Tentatives de connexion illimitees |
| 5 | **Token non signe et sans expiration (TP1)** | Vol du token = acces permanent et indefini |

---

## Evolution par TP

| TP | Niveau | Stockage MDP | Protocole | Anti BF | Anti-rejeu |
|---|---|---|---|---|---|
| TP1 | Dangereuse | En clair | Email + MDP clair | Non | Non |
| TP2 | Fragile | BCrypt | Email + hash | 5 echecs -> 2 min | Non |
| TP3 | Forte | Reversible | HMAC + nonce + timestamp | Oui | Oui |
| TP4 | Industrielle | AES-256-GCM | HMAC + nonce + timestamp | Oui | Oui |
| TP5 | Production | AES-256-GCM | HMAC + change-password | Oui | Oui |

