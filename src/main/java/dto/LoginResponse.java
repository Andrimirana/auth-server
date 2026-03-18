package com.example.auth.dto;

import java.time.LocalDateTime;

/**
 * DTO de réponse après authentification réussie.
 * Contient le token SSO et sa date d'expiration.
 */
public class LoginResponse {

    private String accessToken;
    private LocalDateTime expiresAt;

    public LoginResponse(String accessToken, LocalDateTime expiresAt) {
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
    }

    public String getAccessToken() { return accessToken; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
}