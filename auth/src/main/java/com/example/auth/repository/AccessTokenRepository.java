package com.example.auth.repository;

import com.example.auth.entity.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository Spring Data JPA pour les tokens d'accès SSO.
 *
 * <p>Fournit la recherche par valeur de token et la purge des tokens expirés.
 * La purge peut être déclenchée périodiquement pour maintenir la table propre.</p>
 *
 * @see com.example.auth.entity.AccessToken
 * @see com.example.auth.service.TokenService
 * @version 3.0
 */
public interface AccessTokenRepository extends JpaRepository<AccessToken, Long> {

    /**
     * Recherche un token par sa valeur UUID.
     *
     * <p>Utilisé par {@link com.example.auth.service.TokenService#getUserByToken(String)}
     * pour authentifier les requêtes Bearer.</p>
     *
     * @param token valeur UUID du token Bearer
     * @return un {@link Optional} contenant le token si trouvé, vide sinon
     */
    Optional<AccessToken> findByToken(String token);

    /**
     * Supprime en base tous les tokens dont la date d'expiration est antérieure à {@code now}.
     *
     * <p>Requête JPQL transactionnelle de nettoyage des tokens périmés.</p>
     *
     * @param now date/heure de référence pour la purge
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM AccessToken t WHERE t.expiresAt < :now")
    void deleteExpired(LocalDateTime now);
}