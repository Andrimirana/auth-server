package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur en base de données.
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement
 * fragile. Le mot de passe est haché avec BCrypt mais la phase de
 * login reste rejouable si une requête est capturée.

 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    /** Mot de passe haché BCrypt — plus en clair  */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    /** Nombre d'échecs de connexion consécutifs. */
    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    /** Date jusqu'à laquelle le compte est bloqué (null = pas bloqué). */
    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public User() {}

    public User(String email, String passwordHash) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.createdAt = LocalDateTime.now();
    }

    // Getters & Setters
    public Long getId() { return id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}