package com.example.auth.service;

import com.example.auth.entity.AccessToken;
import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.repository.AccessTokenRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service de gestion des tokens d'accès SSO.
 */
@Service
public class TokenService {

    private final AccessTokenRepository accessTokenRepository;

    public TokenService(AccessTokenRepository accessTokenRepository) {
        this.accessTokenRepository = accessTokenRepository;
    }

    /**
     * Génère et persiste un nouveau token d'accès pour l'utilisateur.
     *
     * @param user utilisateur authentifié
     * @return le token créé
     */
    public AccessToken generate(User user) {
        AccessToken token = new AccessToken(user, UUID.randomUUID().toString());
        return accessTokenRepository.save(token);
    }

    /**
     * Retrouve l'utilisateur associé à un token valide.
     *
     * @param tokenValue valeur du token
     * @return l'utilisateur propriétaire
     * @throws AuthenticationFailedException si token inexistant ou expiré
     */
    public User getUserByToken(String tokenValue) {
        AccessToken token = accessTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new AuthenticationFailedException("Token invalide"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AuthenticationFailedException("Token expiré");
        }
        return token.getUser();
    }
}