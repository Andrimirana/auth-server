package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur de l'application.
 *
 * <p><b>Évolution TP3 → TP4 :</b> Le champ {@code password_clear} est définitivement
 * supprimé et remplacé par {@code password_encrypted}. Le mot de passe est désormais
 * chiffré avec AES-GCM via la {@code MasterKeyEncryptionService} avant tout stockage.</p>
 *
 * <p><b>Format du champ password_encrypted :</b>
 * {@code v1:Base64(iv):Base64(ciphertext)}</p>
 *
 * <p><b>Note pédagogique TP4 :</b> Le chiffrement réversible est conservé pour permettre
 * au serveur de recalculer le HMAC lors du login (protocole TP3). En production industrielle
 * pure, on éviterait tout stockage réversible du mot de passe.</p>
 *
 * @author Étudiant CDWFS
 * @version 4.0
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
     * Mot de passe chiffré AES-GCM via la Master Key.
     * Format : v1:Base64(iv):Base64(ciphertext)
     *
     * <p>Remplace password_clear (TP1/TP3). Jamais en clair, jamais loggé.</p>
     */
    @Column(name = "password_encrypted", nullable = false)
    private String passwordEncrypted;

    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public User() {}

    public User(String email, String passwordEncrypted) {
        this.email = email;
        this.passwordEncrypted = passwordEncrypted;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() { return id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordEncrypted() { return passwordEncrypted; }
    public void setPasswordEncrypted(String passwordEncrypted) { this.passwordEncrypted = passwordEncrypted; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}