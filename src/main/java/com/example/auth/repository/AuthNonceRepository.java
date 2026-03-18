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
 * Repository JPA pour les nonces d'authentification.
 */
public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {

    Optional<AuthNonce> findByUserAndNonce(User user, String nonce);

    @Modifying
    @Transactional
    @Query("DELETE FROM AuthNonce n WHERE n.expiresAt < :now")
    void deleteExpired(LocalDateTime now);
}