package com.example.auth.dto;

/**
 * DTO de la requête de login TP3.
 *
 * <p>Le mot de passe ne figure plus dans ce DTO.
 * Le client envoie une preuve HMAC calculée avec le mot de passe
 * comme clé secrète — le mot de passe ne circule jamais sur le réseau.</p>
 */
public class LoginRequest {

    private String email;
    private String nonce;
    private long timestamp;
    private String hmac;

    public LoginRequest() {}

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    public String getHmac() { return hmac; }
    public void setHmac(String hmac) { this.hmac = hmac; }
}