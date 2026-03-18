package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur de l'application.
 *
 * <p><b>NOTE PÉDAGOGIQUE TP3 :</b> Le mot de passe est stocké en clair
 * ({@code passwordClear}) pour permettre au serveur de recalculer le HMAC
 * lors de l'authentification. Ce choix est volontairement pédagogique
 * et ne doit jamais être utilisé en production.
 * TP4 remplacera ce stockage par un chiffrement AES-GCM via Master Key.</p>
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    /**
     * Mot de passe stocké en clair — pédagogique TP3.
     * Nécessaire pour recalculer le HMAC côté serveur.
     * Sera chiffré AES-GCM en TP4.
     */
    @Column(name = "password_clear", nullable = false)
    private String passwordClear;

    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public User() {}

    public User(String email, String passwordClear) {
        this.email = email;
        this.passwordClear = passwordClear;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPasswordClear() { return passwordClear; }
    public void setPasswordClear(String passwordClear) { this.passwordClear = passwordClear; }
    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }
    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}