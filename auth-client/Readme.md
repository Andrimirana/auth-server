# Serveur d'Authentification — TP1 à TP4

Projet individuel — Parcours CDWFS  
API REST sécurisée construite progressivement avec Java, Spring Boot et MySQL.

---

## Prérequis

- Java 17
- Maven 3.x
- MySQL 8.x
- IntelliJ IDEA

---

## TP1 — Authentification Dangereuse

### Lancer MySQL et configurer application.properties

1. Démarrer MySQL :
```bash
# Windows
net start mysql

# Mac/Linux
sudo service mysql start
```

2. Créer la base de données :
```sql
CREATE DATABASE auth_db;
```

3. Configurer `src/main/resources/application.properties` :
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db
spring.datasource.username=root
spring.datasource.password=TON_MOT_DE_PASSE
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
```

### Lancer l'API
```bash
mvn spring-boot:run
```

L'API démarre sur : http://localhost:8080

### Lancer le client Java
```bash
mvn compile
mvn exec:java -Dexec.mainClass="com.example.auth.client.MainClient"
```

### Compte de test

| Champ    | Valeur            |
|----------|-------------------|
| Email    | toto@example.com  |
| Password | pwd1234           |

### Endpoints disponibles

| Méthode | Endpoint                  | Description              |
|---------|---------------------------|--------------------------|
| POST    | /api/auth/register        | Créer un compte          |
| POST    | /api/auth/login           | Se connecter             |
| GET     | /api/me                   | Profil (authentifié)     |

### Analyse de sécurité TP1 — 5 risques majeurs

#### Risque 1 — Mot de passe stocké en clair
Le mot de passe est stocké tel quel dans la base MySQL.
Si un attaquant accède à la base, il obtient directement tous les mots de passe
de tous les utilisateurs sans aucun effort.

#### Risque 2 — Mot de passe transmis en clair sur le réseau
Le mot de passe voyage dans la requête HTTP sans chiffrement.
Une simple écoute réseau (attaque man-in-the-middle) suffit à le capturer.

#### Risque 3 — Aucune politique de mot de passe
Le minimum est fixé à 4 caractères. Un mot de passe comme "abcd" est accepté.
Cela rend les attaques par dictionnaire ou brute-force triviales.

#### Risque 4 — Aucune protection contre le brute-force
Il n'existe aucune limite de tentatives de connexion.
Un attaquant peut essayer des millions de combinaisons automatiquement
sans jamais être bloqué.

#### Risque 5 — Token de session non sécurisé
Le token généré est un simple UUID stocké en base sans expiration.
Il ne peut pas être invalidé facilement et reste valide indéfiniment
en cas de vol.

---

## TP2 — Authentification Fragile

### Nouveautés

- Politique de mot de passe stricte (12 caractères min, majuscule, chiffre, caractère spécial)
- Hachage BCrypt — le mot de passe n'est plus jamais stocké en clair
- Anti brute-force : 5 échecs consécutifs → blocage 2 minutes (HTTP 429)
- Indicateur de force côté client (Rouge / Orange / Vert)
- Double saisie du mot de passe à l'inscription
- Analyse SonarCloud intégrée

### Faiblesse restante

> TP2 améliore le stockage mais ne protège pas encore contre le rejeu.  
> Si un attaquant capture la requête de login, il peut tenter de la rejouer.  
> Cette faiblesse sera corrigée au TP3 avec HMAC + nonce + timestamp.

### Qualité — SonarCloud

- Projet analysé sur SonarCloud
- Quality Gate : **à compléter après analyse**
- Couverture de tests : **objectif 60% minimum**

