package com.example.auth.repository;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository Spring Data JPA pour les nonces d'authentification anti-rejeu.
 *
 * <p>Fournit la recherche d'un nonce pour un utilisateur donné et la purge
 * des nonces expirés. Ces deux opérations sont le cœur de la protection
 * anti-rejeu du protocole TP3.</p>
 *
 * @see com.example.auth.entity.AuthNonce
 * @see com.example.auth.service.AuthService
 * @version 3.0
 */
public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {

    /**
     * Recherche un nonce existant pour un couple utilisateur/nonce donné.
     *
     * <p>Si un résultat est retourné, le nonce a déjà été utilisé :
     * la requête de login doit être rejetée (protection anti-rejeu).</p>
     *
     * @param user  utilisateur émetteur du nonce
     * @param nonce valeur UUID du nonce à vérifier
     * @return un {@link Optional} contenant le nonce si déjà consommé, vide sinon
     */
    Optional<AuthNonce> findByUserAndNonce(User user, String nonce);

    /**
     * Supprime en base tous les nonces dont la date d'expiration est antérieure à {@code now}.
     *
     * <p>Requête JPQL transactionnelle de nettoyage périodique.
     * Les nonces expirés ne peuvent de toute façon plus être utilisés
     * (le timestamp de la requête serait hors fenêtre).</p>
     *
     * @param now date/heure de référence pour la purge
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM AuthNonce n WHERE n.expiresAt < :now")
    void deleteExpired(LocalDateTime now);
}