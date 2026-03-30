package com.example.auth.dto;

import java.time.LocalDateTime;

/**
 * DTO (Data Transfer Object) de réponse retourné après une authentification réussie.
 *
 * <p>Contient le token SSO Bearer à utiliser dans les appels ultérieurs :</p>
 * <pre>
 *   Authorization: Bearer &lt;accessToken&gt;
 * </pre>
 *
 * @see com.example.auth.entity.AccessToken
 * @see com.example.auth.service.TokenService
 * @version 3.0
 */
public class LoginResponse {

    /**
     * Valeur UUID du token d'accès Bearer.
     * À inclure dans le header {@code Authorization} des requêtes protégées.
     */
    private String accessToken;

    /**
     * Date et heure d'expiration du token.
     * Passé ce délai, le token est invalide et un nouveau login est nécessaire.
     */
    private LocalDateTime expiresAt;

    /**
     * Construit la réponse de login.
     *
     * @param accessToken valeur UUID du token Bearer
     * @param expiresAt   date/heure d'expiration du token
     */
    public LoginResponse(String accessToken, LocalDateTime expiresAt) {
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
    }

    /**
     * Retourne le token d'accès Bearer.
     *
     * @return valeur UUID du token
     */
    public String getAccessToken() { return accessToken; }

    /**
     * Retourne la date d'expiration du token.
     *
     * @return date/heure d'expiration
     */
    public LocalDateTime getExpiresAt() { return expiresAt; }
}