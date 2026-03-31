# TP5 — Dockerfile Spring Boot
#
# Construction en deux étapes (multi-stage build) :
#   1. Build Maven avec JDK 17
#   2. Image finale légère avec JRE 17 Alpine
#
# Usage :
#   docker build -t cdwfs-auth-app .
#   docker run -p 8080:8080 -e APP_MASTER_KEY=<votre_cle> cdwfs-auth-app
#
# IMPORTANT : APP_MASTER_KEY NE DOIT JAMAIS être dans ce fichier.
#             Elle doit être injectée via -e au démarrage du conteneur.

# ──────────────────────────────────────────────
# Étape 1 : Build
# ──────────────────────────────────────────────
FROM eclipse-temurin:17-jdk-alpine AS build

WORKDIR /app

# Copier les fichiers Maven en premier pour exploiter le cache Docker
COPY mvnw mvnw.cmd pom.xml ./
COPY .mvn .mvn

# Rendre mvnw exécutable (nécessaire quand le fichier provient de Windows)
RUN chmod +x ./mvnw

# Télécharger les dépendances (couche mise en cache si pom.xml inchangé)
RUN ./mvnw dependency:go-offline -B

# Copier les sources et builder le JAR (sans tests : les tests tournent en CI)
COPY src ./src
RUN ./mvnw package -DskipTests -B

# ──────────────────────────────────────────────
# Étape 2 : Image finale légère
# ──────────────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Copier uniquement le JAR produit à l'étape de build
COPY --from=build /app/target/auth-0.0.1-SNAPSHOT.jar app.jar

# Port exposé par Spring Boot
EXPOSE 8080

# Variables d'environnement injectables au runtime (jamais de valeur par défaut pour APP_MASTER_KEY)
ENV SPRING_PROFILES_ACTIVE=prod

# Démarrage de l'application
ENTRYPOINT ["java", "-jar", "app.jar"]
