# Serveur d'Authentification — TP1 à TP4

Projet individuel — Parcours CDWFS  
API REST sécurisée construite progressivement avec Java, Spring Boot et MySQL.

---

## Prérequis

- Java 17+
- Maven 3.x
- MySQL 8.x
- IntelliJ IDEA

---

## Lancer le projet

### 1. Créer la base MySQL
```sql
CREATE DATABASE auth;
```

### 2. Configurer `application.properties`
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/auth
spring.datasource.username=root
spring.datasource.password=TON_MOT_DE_PASSE
```

### 3. Générer et définir la Master Key AES-256 (obligatoire depuis TP4)

**Linux / Mac :**
```bash
export APP_MASTER_KEY=$(openssl rand -base64 32)
```

**Windows (PowerShell) :**
```powershell
$env:APP_MASTER_KEY = [Convert]::ToBase64String((1..32 | ForEach-Object { [byte](Get-Random -Max 256) }))
```

> ⚠️ La clé doit être une chaîne Base64 représentant exactement 32 octets (AES-256).  
> Sans cette variable, le serveur **refuse de démarrer**.

### 4. Lancer le serveur
```bash
mvn spring-boot:run
```

L'API démarre sur : http://localhost:8080

### 5. Lancer le client Java (Swing)
```bash
cd ../auth-client
mvn exec:java -Dexec.mainClass="org.example.Main"
```

---

## Comptes de test

| TP | Email | Mot de passe | Remarque |
|----|-------|-------------|----------|
| TP1 (historique) | toto@example.com | pwd1234 | Stocké en clair, politique faible |
| TP4 (actuel) | toto@example.com | Password123! | Chiffré AES-GCM, politique stricte |

---

## Endpoints

| Méthode | URL | Description |
|---------|-----|-------------|
| POST | /api/auth/register | Inscription |
| POST | /api/auth/login | Connexion HMAC-SHA256 |
| GET | /api/me | Route protégée (Bearer token) |
| GET | /api/auth/password-strength?password=xxx | Force du mot de passe |

---

## Analyse de sécurité TP1

> ⚠️ Cette implémentation est volontairement dangereuse et ne doit jamais être utilisée en production.

**Risque 1 — Mot de passe stocké en clair en base**  
Si la base est compromise, tous les mots de passe sont exposés immédiatement, sans aucun effort de déchiffrement.

**Risque 2 — Mot de passe transmis en clair sur le réseau**  
Le mot de passe voyage dans la requête HTTP. Une écoute réseau (man-in-the-middle) suffit à le capturer.

**Risque 3 — Aucune politique de mot de passe**  
4 caractères minimum seulement. Des mots de passe comme "1234" ou "abcd" sont acceptés, rendant les attaques par dictionnaire triviales.

**Risque 4 — Aucune protection contre le brute-force**  
Aucune limite de tentatives. Un attaquant peut tester des millions de combinaisons automatiquement.

**Risque 5 — Token de session non sécurisé**  
Token UUID sans expiration, non invalidable facilement. Un token volé reste valide indéfiniment.

---

## Analyse de sécurité TP2

**Amélioration 1 — Hash BCrypt**  
Le mot de passe est haché avant stockage. La base compromise ne révèle pas les mots de passe.

**Amélioration 2 — Politique stricte**  
12 caractères minimum, majuscule, minuscule, chiffre et caractère spécial obligatoires.

**Amélioration 3 — Anti brute-force**  
Blocage après 5 échecs consécutifs pendant 2 minutes (HTTP 429).

**Limite restante TP2** : la requête de login contient encore une preuve directe du mot de passe. Si une requête est capturée, elle peut être rejouée. Corrigé en TP3.

---

## Analyse de sécurité TP3

> TP3 change le protocole : le mot de passe ne circule plus jamais sur le réseau.

**Amélioration 1 — Protocole HMAC-SHA256**  
Le client envoie une signature : `hmac = HMAC_SHA256(clé=password, data=email:nonce:timestamp)`.  
Le mot de passe n'est jamais transmis, ni en clair ni en hash.

**Amélioration 2 — Anti-rejeu (nonce)**  
Chaque requête contient un UUID unique consommé immédiatement. Une requête capturée ne peut pas être rejouée.

**Amélioration 3 — Fenêtre temporelle (timestamp)**  
Le timestamp est vérifié à ±60 secondes. Une requête capturée expire rapidement.

**Amélioration 4 — Token SSO Bearer**  
Après login réussi, un token Bearer valable 15 minutes est émis pour accéder aux routes protégées.

**Limite restante TP3** : le mot de passe est stocké en clair en base pour permettre le recalcul HMAC. Corrigé en TP4.

---

## Analyse de sécurité TP4

> TP4 industrialise la protection des mots de passe au repos et automatise la qualité via CI/CD.

**Amélioration 1 — Chiffrement AES-GCM par Master Key**  
Les mots de passe ne sont plus jamais stockés en clair. Ils sont chiffrés avec AES-256-GCM avant insertion en base.  
Format : `v1:Base64(iv):Base64(ciphertext)`.

**Amélioration 2 — IV aléatoire à chaque chiffrement**  
Un vecteur d'initialisation de 12 octets est généré aléatoirement à chaque appel, garantissant que deux chiffrements du même mot de passe produisent des résultats différents.

**Amélioration 3 — Intégrité garantie par GCM**  
AES-GCM inclut un tag d'authenticité de 128 bits. Toute modification du ciphertext est détectée et lève une exception.

**Amélioration 4 — Master Key injectée par variable d'environnement**  
La clé n'est jamais dans le code source. L'application refuse de démarrer si `APP_MASTER_KEY` est absente ou invalide.

**Amélioration 5 — CI/CD automatisée**  
Chaque push déclenche automatiquement build, tests JUnit et analyse SonarCloud. Un merge est bloqué si la qualité est insuffisante.

**Limite pédagogique** : le chiffrement réversible (AES-GCM) est conservé uniquement pour permettre le protocole HMAC du TP3.  
En production industrielle pure, on utiliserait OAuth2/OIDC avec un hash non réversible (bcrypt/argon2).

---

## Qualité

- **Tests JUnit** : 29 tests — tous verts ✅
- **Couverture JaCoCo** : ≥ 80%
- **SonarCloud** : configuré et Quality Gate en succès

### Configuration SonarCloud

Ajouter dans GitHub → Settings → Secrets and variables → Actions :

| Secret | Valeur |
|--------|--------|
| `SONAR_TOKEN` | Token généré sur sonarcloud.io |
| `SONAR_PROJECT_KEY` | Clé du projet SonarCloud |
| `SONAR_ORGANIZATION` | Organisation SonarCloud |

---

## CI/CD GitHub Actions

Le fichier `.github/workflows/ci.yml` déclenche automatiquement sur chaque push / pull request vers `main` :

1. Checkout du code
2. Installation JDK 17
3. Build Maven + exécution des tests (H2 en mémoire, pas de MySQL)
4. Analyse SonarCloud avec Quality Gate
5. Échec automatique si un test échoue ou si le Quality Gate est rouge

> La Master Key de CI est une clé fictive injectée via `APP_MASTER_KEY` dans les secrets GitHub.  
> Elle n'est jamais committée dans le code.

---

## Tags Git

| Tag | Description |
|-----|-------------|
| v1.0-init | Projet vide Spring Boot + structure packages |
| v1.1-model | Entité User + repository |
| v1.2-register | Endpoint /api/auth/register + exceptions |
| v1.3-login | Endpoint /api/auth/login + logging |
| v1.4-protected | Route /api/me + token simple |
| v1-tp1 | TP1 final — authentification dangereuse |
| v2.0-start | Démarrage TP2 |
| v2.1-db-migration | Migration password_clear → password_hash |
| v2.2-password-policy | PasswordPolicyValidator + tests |
| v2.3-hashing | BCrypt — inscription et login |
| v2.4-lockout | Anti brute-force : 5 échecs → blocage 2 min |
| v2.5-ui-strength | Indicateur force mot de passe client |
| v2.6-sonarcloud | SonarCloud configuré + corrections |
| v2-tp2 | TP2 final — authentification fragile |
| v3.0-start | Démarrage TP3 |
| v3.1-db-nonce | Table auth_nonce |
| v3.2-hmac-client | Calcul HMAC côté client Swing |
| v3.3-hmac-server | Vérification HMAC côté serveur |
| v3.4-anti-replay | Protection anti-rejeu nonce |
| v3.5-token | Émission token SSO + /api/me |
| v3.6-tests-80 | Couverture 80% + 15 tests |
| v3-tp3 | TP3 final — authentification forte HMAC |
| v4-tp4 | TP4 final — Master Key AES-GCM + CI/CD |

