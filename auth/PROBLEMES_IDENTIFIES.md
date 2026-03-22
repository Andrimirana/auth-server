# Rapport d'Analyse du Projet Auth - Problèmes Identifiés

**Date:** 22 Mars 2026  
**Projet:** Serveur d'Authentification TP1 à TP4  
**Status:** ⚠️ Plusieurs problèmes détectés

---

## Résumé Exécutif

Le projet compile correctement et tous les tests passent (28/28 tests ✅). Cependant, **plusieurs problèmes critiques et majeurs** ont été identifiés :

1. ⚠️ **Configuration non sécurisée** - Master Key manquante en environnement de production
2. ⚠️ **Absence de validation de token sur les endpoints** - Seul `/api/me` est vraiment protégé
3. ⚠️ **CORS non configuré** - Tous les endpoints sont ouverts sans validation
4. ⚠️ **Réversibilité du mot de passe** - Chiffrement AES-GCM au lieu de hash
5. ⚠️ **Configuration inadéquate de sécurité Spring** - Tous les endpoints autorisés sans restriction
6. ⚠️ **Password exposure dans les logs** - JPA SQL logs activés (`show-sql=true`)
7. ⚠️ **Plugin JaCoCo version manquante** - Avertissement Maven

---

## 1. ⚠️ CRITIQUE - Master Key Manquante en Production

### Localisation
- `src/main/resources/application.properties` (ligne 23)
- `src/main/java/com/example/auth/service/MasterKeyEncryptionService.java` (PostConstruct)

### Description du Problème
```properties
# Master Key AES-256 (OBLIGATOIRE - TP4)
app.master.key=${APP_MASTER_KEY}  # ← Injecté depuis variable d'environnement
```

L'application **refuse de démarrer** si `APP_MASTER_KEY` n'est pas définie :
```java
@PostConstruct
public void init() {
    if (masterKeyBase64 == null || masterKeyBase64.isBlank()) {
        throw new IllegalStateException(
            "[SÉCURITÉ - TP4] La variable d'environnement APP_MASTER_KEY est absente. " +
            "L'application refuse de démarrer sans clé de chiffrement."
        );
    }
    // ... validation que la clé fait exactement 32 octets (AES-256)
}
```

### Risque de Sécurité
- 🔴 **CRITIQUE** : Sans cette clé, **l'application ne peut pas démarrer en production**
- La clé doit être générée et gérée via un gestionnaire de secrets (Vault, AWS Secrets Manager, etc.)
- Actuellement, elle doit être fournie en variable d'environnement

### Recommandations
```bash
# Générer une clé AES-256 valide :
openssl rand -base64 32

# Exporter en variable d'environnement :
export APP_MASTER_KEY="votre_clé_base64_ici"

# Ou en fichier .env (à NE JAMAIS commiter) :
APP_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

**À faire :**
- [ ] Utiliser un gestionnaire de secrets en production (Vault, AWS Secrets Manager)
- [ ] Ne JAMAIS commiter la clé dans Git
- [ ] Ajouter un `.env.example` sans la clé réelle
- [ ] Documenter la génération et le stockage de la clé

---

## 2. ⚠️ MAJEURE - Endpoints d'Authentification Non Protégés

### Localisation
- `src/main/java/com/example/auth/config/SecurityConfig.java`
- `src/main/java/com/example/auth/controller/AuthController.java`

### Description du Problème
**Tous les endpoints sont ouverts sans authentification** :
```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());  // ← TOUS LES ENDPOINTS OUVERTS !
        return http.build();
    }
}
```

**Endpoints exposés sans protection :**
```
POST   /api/auth/register                  ← Peut être spammé
POST   /api/auth/login                     ← Pas de rate limiting
GET    /api/auth/password-strength?xxx     ← Information disclosure
POST   /api/me                             ← SEUL ENDPOINT CENSÉMENT PROTÉGÉ
```

### Risque de Sécurité
- 🔴 **CRITIQUE** : Attaque par brute-force sur `/api/auth/login`
- 🟠 **MAJEURE** : Spam d'inscriptions (creation d'accounts)
- 🟠 **MAJEURE** : Information disclosure via `/api/auth/password-strength`
- Le token Bearer est généré mais **jamais validé** sur `/api/auth/register` et `/api/auth/login`

### Evidence du Code
**UserController.java :**
```java
@GetMapping("/me")
public ResponseEntity<Map<String, Object>> me(
        @RequestHeader(value = "Authorization", required = false) String authHeader) {
    // Seul endpoint qui fait la validation manuelle du token
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        throw new AuthenticationFailedException(
            "Token manquant. Utilisez : Authorization: Bearer <token>"
        );
    }
}
```

**AuthController.java :**
```java
@PostMapping("/register")
public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
    // ← AUCUNE VALIDATION DE TOKEN !
    // N'importe qui peut créer un compte
}

@PostMapping("/login")
public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
    // ← AUCUNE VALIDATION DE TOKEN !
    // Pas de rate limiting
}
```

### Recommandations
**Solution 1 : Utiliser Spring Security Filter**
```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/password-strength").permitAll()
                .requestMatchers("/api/**").authenticated()  // ← Toutes autres routes protégées
                .anyRequest().permitAll()
            );
        return http.build();
    }
}
```

**Solution 2 : Ajouter Rate Limiting**
```xml
<!-- Ajouter au pom.xml -->
<dependency>
    <groupId>io.github.bucket4j</groupId>
    <artifactId>bucket4j-core</artifactId>
    <version>7.6.0</version>
</dependency>
```

**À faire :**
- [ ] Implémenter la validation de token sur tous les endpoints sensibles
- [ ] Ajouter du rate limiting (max 5 tentatives par IP/minute)
- [ ] Restreindre `/api/auth/password-strength` en production
- [ ] Ajouter une validation CAPTCHA sur `/api/auth/register`

---

## 3. ⚠️ MAJEURE - CORS Complètement Ouvert

### Localisation
- `src/main/resources/application.properties`
- `src/main/java/com/example/auth/config/SecurityConfig.java`

### Description du Problème
**CORS n'est pas configuré du tout**. Par défaut, Spring Boot accepte les requêtes CORS de **n'importe quelle origine** :

```
Access-Control-Allow-Origin: *
```

**Cela signifie :**
- Un site malveillant peut faire une requête CORS vers votre serveur
- Les cookies et tokens peuvent être volés
- Attaque CSRF possible même avec `csrf.disable()`

### Risque de Sécurité
- 🔴 **CRITIQUE** : CSRF (Cross-Site Request Forgery)
- 🟠 **MAJEURE** : Vol de tokens via sites malveillants
- 🟠 **MAJEURE** : Information disclosure

### Recommandations
**À ajouter dans `SecurityConfig.java` :**
```java
@Configuration
@EnableWebMvc
public class SecurityConfig {
    
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("http://localhost:3000", "https://yourfrontend.com")  // ← Whitelist uniquement
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    .allowedHeaders("*")
                    .allowCredentials(true)
                    .maxAge(3600);
            }
        };
    }
}
```

**À faire :**
- [ ] Ajouter une liste blanche de domaines CORS
- [ ] Ne permettre que `http://localhost:3000` en développement
- [ ] Configurer uniquement `https://` en production

---

## 4. ⚠️ MAJEURE - Réversibilité du Mot de Passe (Chiffrement au lieu de Hash)

### Localisation
- `src/main/java/com/example/auth/entity/User.java` (ligne 39)
- `src/main/java/com/example/auth/service/MasterKeyEncryptionService.java`
- `src/main/java/com/example/auth/service/AuthService.java` (ligne 107)

### Description du Problème
Les mots de passe sont **chiffrés (AES-GCM)** au lieu d'être **hachés (bcrypt/Argon2)** :

```java
// User.java
@Column(name = "password_encrypted", nullable = false)
private String passwordEncrypted;  // ← Format : v1:Base64(iv):Base64(ciphertext)

// AuthService.java
public User register(String email, String password, String passwordConfirm) {
    String encrypted = encryptionService.encrypt(password);  // ← Chiffrement réversible
    User user = new User(email, encrypted);
    userRepository.save(user);
}
```

**Pendant le login :**
```java
public LoginResponse login(LoginRequest request) {
    // Déchiffrer le mot de passe en clair pour vérifier le HMAC
    String passwordPlain = encryptionService.decrypt(user.getPasswordEncrypted());  // ← EXPOSÉ EN MÉMOIRE !
}
```

### Risque de Sécurité
- 🔴 **CRITIQUE** : Si la base de données est compromise, **tous les mots de passe peuvent être déchiffrés**
- 🟠 **MAJEURE** : Le mot de passe en clair est stocké en mémoire pendant le vérification du HMAC
- 🟠 **MAJEURE** : Aucune protection contre les attaques par force brute (pas de salt, pas de coût computationnel)
- 🟡 **MINEURE** : Note pédagogique : C'est voulu pour permettre le protocole HMAC TP3

### Evidence du Code
```java
// MasterKeyEncryptionService.java
public String encrypt(String plaintext) {
    // Chiffrement AES-GCM - RÉVERSIBLE
    byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
    return "v1:" + Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
}

public String decrypt(String encryptedValue) {
    // Déchiffrement - Le mot de passe est exposé
    return new String(cipher.doFinal(ciphertext));
}
```

### Recommandations
**ATTENTION : C'est un choix pédagogique pour TP3/TP4**

Pour une **vraie application de production**, il faut :
```xml
<!-- Ajouter au pom.xml -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-crypto</artifactId>
</dependency>
```

```java
// Utiliser BCryptPasswordEncoder au lieu de AES-GCM
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

// Lors de l'enregistrement :
String hashed = passwordEncoder().encode(password);
user.setPasswordHash(hashed);

// Lors du login :
if (passwordEncoder().matches(plainPassword, user.getPasswordHash())) {
    // Authentification réussie
}
```

**À faire (après TP4) :**
- [ ] Remplacer AES-GCM par bcrypt/Argon2 pour la production
- [ ] Ajouter du salting automatique (bcrypt le fait)
- [ ] Ajouter un coût computationnel pour ralentir les attaques (bcrypt le fait)

---

## 5. ⚠️ MAJEURE - Exposition des Logs SQL

### Localisation
- `src/main/resources/application.properties` (ligne 14)

### Description du Problème
```properties
spring.jpa.show-sql=true  # ← DANGER : Affiche TOUTES les requêtes SQL en logs !
```

**Cela affiche en logs de production :**
```sql
-- LOGS EXPOSANT LES DONNÉES SENSIBLES
select user0_.id, user0_.created_at, user0_.failed_attempts, user0_.lock_until, 
       user0_.email, user0_.password_encrypted from users user0_ where user0_.email=?

-- Les champs password_encrypted contiennent :
-- v1:Base64(iv):Base64(ciphertext)
```

**Les logs vont dans :**
- `logs/auth.log` (fichier accessible)
- stdout (console)
- Système centralisé de logs (ELK, Splunk, etc.)

### Risque de Sécurité
- 🔴 **CRITIQUE** : Exposition des données sensibles dans les logs
- 🟠 **MAJEURE** : Peut révéler la structure interne de la base de données
- 🟠 **MAJEURE** : Si quelqu'un accède aux logs, il peut voir les données sensibles

### Evidence du Code
```java
// Dans AuthService.java
logger.info("Inscription réussie pour : {}", email);  // ← Email en clair dans logs
logger.warn("Connexion échouée - HMAC invalide pour : {}", request.getEmail());  // ← Email exposé
```

### Recommandations
**Immédiatemment :**
```properties
# src/main/resources/application.properties
spring.jpa.show-sql=false  # ← DÉSACTIVER EN PRODUCTION

# Pour le débugging en développement seulement :
logging.level.org.hibernate.SQL=DEBUG
logging.level.org.hibernate.type.descriptor.sql.BasicBinder=TRACE  # Pour les paramètres
```

**À faire :**
- [ ] Désactiver `show-sql=true` dans `application.properties` (production)
- [ ] Utiliser des profiles Spring (`@Profile("dev")` vs `@Profile("prod")`)
- [ ] Utiliser un gestionnaire de logs centralisé avec masquage des données sensibles
- [ ] Ajouter du masquage des emails dans les logs (`***.example.com`)

---

## 6. ⚠️ MINEURE - Plugin JaCoCo Version Manquante

### Localisation
- `pom.xml` (ligne 111)

### Description du Problème
```xml
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <!-- ← VERSION MANQUANTE ! -->
</plugin>
```

**Avertissement Maven :**
```
[WARNING] 'build.plugins.plugin.version' for org.jacoco:jacoco-maven-plugin is missing. @ line 111, column 21
[WARNING] It is highly recommended to fix these problems because they threaten the stability of your build.
```

### Impact
- 🟡 **MINEUR** : La version est héritée du parent (0.8.14), mais c'est fragile
- Peut causer des problèmes lors de mises à jour Maven

### Recommandations
**Ajouter la version explicitement :**
```xml
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <version>0.8.14</version>  <!-- ← AJOUTER -->
    <executions>
        <!-- ... -->
    </executions>
</plugin>
```

---

## 7. ⚠️ MINEURE - Tests Manquants pour les Endpoints

### Localisation
- `src/test/java/com/example/auth/`

### Description du Problème
Les tests couvrent :
- ✅ `AuthApplicationTests` (18 tests)
- ✅ `MasterKeyEncryptionServiceTest` (10 tests)

**Manquent les tests pour :**
- ❌ `AuthController` - endpoints REST
- ❌ `UserController` - endpoint `/api/me`
- ❌ `PasswordPolicyValidator` - validation des mots de passe
- ❌ `HmacService` - vérification HMAC
- ❌ Tests de sécurité Spring Security

### Recommandations
**À faire :**
- [ ] Ajouter `@SpringBootTest` pour les endpoints REST
- [ ] Tester les cas d'erreur (brute-force, nonce dupliqué, etc.)
- [ ] Tester la validation du token Bearer
- [ ] Tester le rate limiting (quand implémenté)

---

## 8. ⚠️ MINEURE - Validation du Token Bearer Manquante sur `/api/auth/register`

### Description du Problème
L'endpoint `/api/auth/register` **ne requiert pas d'authentification** :
```java
@PostMapping("/register")
public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
    // ← N'importe qui peut créer un compte
}
```

### Risque de Sécurité
- 🟡 **MINEUR** : Spam d'inscriptions (DoS)
- Peut être intentionnel (inscription publique)

### Recommandations
**Selon votre modèle de sécurité :**
- Option A : Laisser ouvert (inscription publique)
- Option B : Requérir un token d'invitation
- Option C : Ajouter un CAPTCHA + rate limiting

---

## Résumé des Problèmes par Sévérité

### 🔴 CRITIQUES (2)
1. Master Key manquante en production (`APP_MASTER_KEY`)
2. Endpoints non protégés par authentification Spring Security

### 🟠 MAJEURES (4)
1. CORS complètement ouvert
2. Réversibilité du mot de passe (chiffrement au lieu de hash)
3. Exposition des logs SQL
4. Absence de rate limiting sur `/api/auth/login`

### 🟡 MINEURES (2)
1. Plugin JaCoCo version manquante
2. Tests manquants pour les endpoints

---

## Plan d'Action Recommandé

### Phase 1 : Correctifs Immédiatement (Avant Production)
- [ ] **Ajouter gestion de la Master Key** via gestionnaire de secrets
- [ ] **Implémenter Spring Security Filter** pour protéger les endpoints
- [ ] **Configurer CORS** avec liste blanche de domaines
- [ ] **Désactiver SQL logging** en production
- [ ] **Ajouter plugin JaCoCo version** dans pom.xml

### Phase 2 : Améliorations Importantes (Sprint Suivant)
- [ ] **Ajouter rate limiting** sur `/api/auth/login`
- [ ] **Ajouter CAPTCHA** sur `/api/auth/register`
- [ ] **Ajouter tests** pour les endpoints REST
- [ ] **Remplacer chiffrement par hash bcrypt** (après TP4)

### Phase 3 : Optimisations (Long terme)
- [ ] **Ajouter OAuth2/OIDC** pour une vraie gestion d'identité
- [ ] **Ajouter 2FA** (Two-Factor Authentication)
- [ ] **Ajouter monitoring** des tentatives de connexion
- [ ] **Audit logging** complet des actions sensibles

---

## Conclusion

**État général du projet :** ✅ Bon pour apprentissage, 🔴 **Non prêt pour production**

Le projet est **bien structuré et fonctionne correctement** pour un exercice pédagogique (TP1-TP4). Cependant, **plusieurs failles de sécurité critiques** doivent être corrigées avant toute utilisation en production.

**Priorités absolues :**
1. Configurer la Master Key
2. Implémenter Spring Security Filter
3. Configurer CORS
4. Désactiver SQL logging
5. Ajouter rate limiting

---

**Rapport généré :** 22 Mars 2026  
**Compilé avec :** Maven 3.9.11  
**Version Java :** 17 (LTS)  
**Spring Boot :** 3.2.5

