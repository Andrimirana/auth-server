package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur en base de données.
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    // TP1 volontairement dangereux : mot de passe en clair
    @Column(name = "password_clear", nullable = false)
    private String passwordClear;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public User() {}

    public User(String email, String passwordClear) {
        this.email = email;
        this.passwordClear = passwordClear;
        this.createdAt = LocalDateTime.now();
    }

    // Getters & Setters
    public Long getId() { return id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordClear() { return passwordClear; }
    public void setPasswordClear(String passwordClear) { this.passwordClear = passwordClear; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}