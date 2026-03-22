package com.example.auth.repository;

import com.example.auth.entity.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository JPA pour les tokens d'accès SSO.
 */
public interface AccessTokenRepository extends JpaRepository<AccessToken, Long> {

    Optional<AccessToken> findByToken(String token);

    @Modifying
    @Transactional
    @Query("DELETE FROM AccessToken t WHERE t.expiresAt < :now")
    void deleteExpired(LocalDateTime now);
}