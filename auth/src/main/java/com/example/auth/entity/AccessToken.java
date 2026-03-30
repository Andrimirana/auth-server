package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité JPA représentant un token d'accès SSO émis après authentification réussie.
 *
 * <p>Le token est un UUID valable {@value #EXPIRY_MINUTES} minutes.
 * Il doit être transmis dans l'en-tête HTTP {@code Authorization: Bearer <token>}
 * pour accéder aux routes protégées (ex. {@code GET /api/me}).</p>
 *
 * <p>Le cycle de vie du token est :</p>
 * <ol>
 *   <li>Émis par {@link com.example.auth.service.TokenService#generate(User)} après login réussi.</li>
 *   <li>Vérifié par {@link com.example.auth.service.TokenService#getUserByToken(String)}.</li>
 *   <li>Purgé automatiquement via {@link com.example.auth.repository.AccessTokenRepository#deleteExpired}.</li>
 * </ol>
 *
 * @see com.example.auth.service.TokenService
 * @see com.example.auth.repository.AccessTokenRepository
 * @version 3.0
 */
@Entity
@Table(name = "access_tokens")
public class AccessToken {

    /**
     * Durée de validité d'un token en minutes.
     * Après ce délai, le token est considéré expiré et l'accès refusé.
     */
    public static final long EXPIRY_MINUTES = 15L;

    /** Identifiant technique auto-généré. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Utilisateur propriétaire du token.
     * Chargé en EAGER pour éviter la LazyInitializationException
     * quand open-in-view=false (stateless REST API).
     */
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * Valeur UUID du token, unique en base.
     * Transmis dans le header {@code Authorization: Bearer <token>}.
     */
    @Column(nullable = false, unique = true)
    private String token;

    /** Date et heure d'expiration du token ({@code createdAt + EXPIRY_MINUTES}). */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /** Date et heure de création du token. */
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    /**
     * Constructeur par défaut requis par JPA.
     */
    public AccessToken() {}

    /**
     * Crée un token pour l'utilisateur donné.
     * La date de création est positionnée à l'instant courant,
     * l'expiration à {@code now + EXPIRY_MINUTES}.
     *
     * @param user  utilisateur propriétaire
     * @param token valeur UUID du token
     */
    public AccessToken(User user, String token) {
        this.user = user;
        this.token = token;
        this.createdAt = LocalDateTime.now();
        this.expiresAt = LocalDateTime.now().plusMinutes(EXPIRY_MINUTES);
    }

    /**
     * Retourne l'identifiant technique.
     *
     * @return identifiant généré en base
     */
    public Long getId() { return id; }

    /**
     * Retourne l'utilisateur propriétaire du token.
     *
     * @return utilisateur associé
     */
    public User getUser() { return user; }

    /**
     * Modifie l'utilisateur propriétaire.
     *
     * @param user utilisateur à associer
     */
    public void setUser(User user) { this.user = user; }

    /**
     * Retourne la valeur UUID du token.
     *
     * @return valeur du token Bearer
     */
    public String getToken() { return token; }

    /**
     * Modifie la valeur du token.
     *
     * @param token nouvelle valeur UUID
     */
    public void setToken(String token) { this.token = token; }

    /**
     * Retourne la date/heure d'expiration du token.
     *
     * @return date d'expiration
     */
    public LocalDateTime getExpiresAt() { return expiresAt; }

    /**
     * Modifie la date d'expiration.
     *
     * @param expiresAt nouvelle date d'expiration
     */
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    /**
     * Retourne la date de création du token.
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