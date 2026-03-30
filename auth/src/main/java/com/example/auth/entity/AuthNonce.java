package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité JPA représentant un nonce d'authentification pour la protection anti-rejeu.
 *
 * <p>Dans le protocole TP3, chaque requête de login inclut un nonce (UUID aléatoire).
 * Le serveur vérifie que ce nonce n'a pas encore été utilisé par cet utilisateur,
 * puis l'enregistre immédiatement pour bloquer tout rejeu concurrent.</p>
 *
 * <h2>Garanties de sécurité</h2>
 * <ul>
 *   <li>Contrainte unique {@code (user_id, nonce)} en base de données.</li>
 *   <li>TTL de {@value #TTL_SECONDS} secondes : les nonces expirés peuvent être purgés.</li>
 *   <li>Le champ {@code consumed} est positionné à {@code true} dès la création.</li>
 * </ul>
 *
 * @see com.example.auth.repository.AuthNonceRepository
 * @see com.example.auth.service.AuthService
 * @version 3.0
 */
@Entity
@Table(
        name = "auth_nonce",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "nonce"})
)
public class AuthNonce {

    /**
     * Durée de vie d'un nonce en secondes.
     * Après ce délai, le nonce peut être purgé par la tâche de nettoyage.
     */
    public static final long TTL_SECONDS = 120L;

    /** Identifiant technique auto-généré. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Utilisateur propriétaire du nonce.
     * La contrainte d'unicité porte sur le couple {@code (user_id, nonce)}.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * Valeur du nonce (UUID) envoyée par le client dans la requête de login.
     * Unique par utilisateur.
     */
    @Column(nullable = false)
    private String nonce;

    /**
     * Date/heure d'expiration du nonce ({@code createdAt + TTL_SECONDS}).
     * Passé cette date, le nonce peut être supprimé de la base.
     */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /**
     * Indique si le nonce a été consommé.
     * Toujours {@code true} dès l'insertion : tout nonce enregistré est considéré consommé.
     */
    @Column(nullable = false)
    private boolean consumed = false;

    /** Date et heure d'enregistrement du nonce. */
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    /**
     * Constructeur par défaut requis par JPA.
     */
    public AuthNonce() {}

    /**
     * Crée et marque immédiatement le nonce comme consommé.
     * La date d'expiration est positionnée à {@code now + TTL_SECONDS}.
     *
     * @param user  utilisateur associé au nonce
     * @param nonce valeur UUID du nonce
     */
    public AuthNonce(User user, String nonce) {
        this.user = user;
        this.nonce = nonce;
        this.createdAt = LocalDateTime.now();
        this.expiresAt = LocalDateTime.now().plusSeconds(TTL_SECONDS);
        this.consumed = true;
    }

    /**
     * Retourne l'identifiant technique.
     *
     * @return identifiant généré en base
     */
    public Long getId() { return id; }

    /**
     * Retourne l'utilisateur associé à ce nonce.
     *
     * @return utilisateur propriétaire
     */
    public User getUser() { return user; }

    /**
     * Modifie l'utilisateur propriétaire.
     *
     * @param user utilisateur à associer
     */
    public void setUser(User user) { this.user = user; }

    /**
     * Retourne la valeur du nonce.
     *
     * @return UUID du nonce
     */
    public String getNonce() { return nonce; }

    /**
     * Modifie la valeur du nonce.
     *
     * @param nonce nouvelle valeur UUID
     */
    public void setNonce(String nonce) { this.nonce = nonce; }

    /**
     * Retourne la date d'expiration du nonce.
     *
     * @return date/heure d'expiration
     */
    public LocalDateTime getExpiresAt() { return expiresAt; }

    /**
     * Modifie la date d'expiration.
     *
     * @param expiresAt nouvelle date d'expiration
     */
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    /**
     * Indique si le nonce a été consommé.
     *
     * @return {@code true} si consommé (toujours vrai après création)
     */
    public boolean isConsumed() { return consumed; }

    /**
     * Modifie l'état de consommation.
     *
     * @param consumed {@code true} pour marquer comme consommé
     */
    public void setConsumed(boolean consumed) { this.consumed = consumed; }

    /**
     * Retourne la date de création du nonce.
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