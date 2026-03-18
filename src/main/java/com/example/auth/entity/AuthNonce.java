package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un nonce d'authentification pour la protection anti-rejeu.
 *
 * <p>Chaque nonce est unique par utilisateur. Une fois consommé,
 * il ne peut plus être réutilisé, empêchant les attaques par rejeu.</p>
 */
@Entity
@Table(
        name = "auth_nonce",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "nonce"})
)
public class AuthNonce {

    /** Durée de vie d'un nonce en secondes. */
    public static final long TTL_SECONDS = 120L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String nonce;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean consumed = false;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    public AuthNonce() {}

    public AuthNonce(User user, String nonce) {
        this.user = user;
        this.nonce = nonce;
        this.createdAt = LocalDateTime.now();
        this.expiresAt = LocalDateTime.now().plusSeconds(TTL_SECONDS);
        this.consumed = true;
    }

    public Long getId() { return id; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean consumed) { this.consumed = consumed; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}