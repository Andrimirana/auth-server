package com.example.auth.dto;

/**
 * DTO (Data Transfer Object) de la requête de login — protocole TP3 HMAC-SHA256.
 *
 * <p>Le mot de passe ne circule <b>jamais</b> sur le réseau.
 * Le client calcule une preuve cryptographique et envoie :</p>
 * <pre>
 *   POST /api/auth/login
 *   {
 *     "email"     : "user@example.com",
 *     "nonce"     : "uuid-aléatoire",
 *     "timestamp" : 1711234567,
 *     "hmac"      : "Base64(HMAC_SHA256(key=password, data=email:nonce:timestamp))"
 *   }
 * </pre>
 *
 * @see com.example.auth.service.HmacService
 * @see com.example.auth.service.AuthService#login(LoginRequest)
 * @version 3.0
 */
public class LoginRequest {

    /** Adresse email de l'utilisateur. */
    private String email;

    /**
     * Nonce UUID aléatoire généré par le client pour chaque requête.
     * Garantit l'unicité de la preuve et empêche les attaques par rejeu.
     */
    private String nonce;

    /**
     * Timestamp Unix (secondes depuis epoch) au moment de la requête.
     * Le serveur accepte une fenêtre de ±60 secondes.
     */
    private long timestamp;

    /**
     * Signature HMAC-SHA256 encodée en Base64.
     * Calculée côté client : {@code HMAC_SHA256(key=password, data=email:nonce:timestamp)}.
     */
    private String hmac;

    /**
     * Constructeur par défaut requis pour la désérialisation JSON.
     */
    public LoginRequest() {}

    /**
     * Retourne l'adresse email.
     *
     * @return email de l'utilisateur
     */
    public String getEmail() { return email; }

    /**
     * Définit l'adresse email.
     *
     * @param email adresse email
     */
    public void setEmail(String email) { this.email = email; }

    /**
     * Retourne le nonce de la requête.
     *
     * @return UUID nonce
     */
    public String getNonce() { return nonce; }

    /**
     * Définit le nonce.
     *
     * @param nonce UUID aléatoire
     */
    public void setNonce(String nonce) { this.nonce = nonce; }

    /**
     * Retourne le timestamp Unix de la requête.
     *
     * @return secondes depuis epoch
     */
    public long getTimestamp() { return timestamp; }

    /**
     * Définit le timestamp Unix.
     *
     * @param timestamp secondes depuis epoch
     */
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    /**
     * Retourne la signature HMAC-SHA256 en Base64.
     *
     * @return signature HMAC
     */
    public String getHmac() { return hmac; }

    /**
     * Définit la signature HMAC.
     *
     * @param hmac signature Base64
     */
    public void setHmac(String hmac) { this.hmac = hmac; }
}