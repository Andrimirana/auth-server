package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité JPA représentant un utilisateur du serveur d'authentification.
 *
 * <h2>Évolution par TP</h2>
 * <ul>
 *   <li><b>TP1</b> : mot de passe stocké en clair ({@code password_clear}).</li>
 *   <li><b>TP2</b> : mot de passe haché BCrypt ({@code password_hash}) +
 *       compteur d'échecs + verrouillage anti brute-force.</li>
 *   <li><b>TP3</b> : champ renommé {@code password_encrypted} — stocké en clair
 *       pour permettre le recalcul HMAC côté serveur lors du login.</li>
 * </ul>
 *
 * <p><b>Note pédagogique TP3 :</b> Le stockage en clair est intentionnellement
 * conservé pour permettre l'apprentissage du protocole HMAC signé.
 * Cette implémentation est volontairement dangereuse et ne doit jamais
 * être utilisée en production.</p>
 *
 * @see com.example.auth.service.AuthService
 * @see com.example.auth.repository.UserRepository
 * @version 3.0
 */
@Entity
@Table(name = "users")
public class User {

    /** Identifiant technique auto-généré. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Adresse email de l'utilisateur — unique en base.
     * Sert d'identifiant métier pour l'authentification.
     */
    @Column(unique = true, nullable = false)
    private String email;

    /**
     * Mot de passe stocké côté serveur.
     *
     * <p>En TP3, le mot de passe est conservé en clair (champ nommé
     * {@code password_encrypted} par anticipation du TP4) afin de permettre
     * au serveur de recalculer {@code HMAC_SHA256(key=password, data=email:nonce:timestamp)}
     * lors du login.</p>
     *
     * <p><b>AVERTISSEMENT :</b> Ne jamais logger ce champ.</p>
     */
    @Column(name = "password_encrypted", nullable = false)
    private String passwordEncrypted;

    /**
     * Nombre de tentatives de connexion échouées consécutives.
     * Réinitialisé à 0 après un login réussi.
     */
    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    /**
     * Date/heure jusqu'à laquelle le compte est verrouillé (anti brute-force).
     * {@code null} si le compte n'est pas verrouillé.
     */
    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    /** Date et heure de création du compte. */
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    /**
     * Constructeur par défaut requis par JPA.
     */
    public User() {}

    /**
     * Constructeur principal — initialise la date de création à l'instant courant.
     *
     * @param email             adresse email unique de l'utilisateur
     * @param passwordEncrypted mot de passe (en clair en TP3, chiffré en TP4)
     */
    public User(String email, String passwordEncrypted) {
        this.email = email;
        this.passwordEncrypted = passwordEncrypted;
        this.createdAt = LocalDateTime.now();
    }

    /**
     * Retourne l'identifiant technique.
     *
     * @return identifiant généré en base
     */
    public Long getId() { return id; }

    /**
     * Retourne l'email de l'utilisateur.
     *
     * @return adresse email
     */
    public String getEmail() { return email; }

    /**
     * Modifie l'adresse email.
     *
     * @param email nouvelle adresse email
     */
    public void setEmail(String email) { this.email = email; }

    /**
     * Retourne le mot de passe stocké (en clair en TP3).
     *
     * <p><b>AVERTISSEMENT :</b> Ne jamais exposer cette valeur dans les logs
     * ni dans les réponses HTTP.</p>
     *
     * @return mot de passe stocké
     */
    public String getPasswordEncrypted() { return passwordEncrypted; }

    /**
     * Modifie le mot de passe stocké.
     *
     * @param passwordEncrypted nouvelle valeur du mot de passe
     */
    public void setPasswordEncrypted(String passwordEncrypted) { this.passwordEncrypted = passwordEncrypted; }

    /**
     * Retourne le nombre de tentatives d'authentification échouées.
     *
     * @return compteur d'échecs
     */
    public int getFailedAttempts() { return failedAttempts; }

    /**
     * Modifie le compteur de tentatives échouées.
     *
     * @param failedAttempts nouveau nombre d'échecs
     */
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

    /**
     * Retourne la date/heure de fin de verrouillage du compte.
     *
     * @return date de fin de blocage, ou {@code null} si non verrouillé
     */
    public LocalDateTime getLockUntil() { return lockUntil; }

    /**
     * Définit la date/heure de fin de verrouillage.
     *
     * @param lockUntil date jusqu'à laquelle le compte est bloqué
     */
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }

    /**
     * Retourne la date de création du compte.
     *
     * @return date/heure de création
     */
    public LocalDateTime getCreatedAt() { return createdAt; }

    /**
     * Modifie la date de création.
     *
     * @param createdAt nouvelle date de création
     */
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}