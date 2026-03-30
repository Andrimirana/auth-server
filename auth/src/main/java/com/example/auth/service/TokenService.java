package com.example.auth.service;

import com.example.auth.entity.AccessToken;
import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.repository.AccessTokenRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service de gestion des tokens d'accès SSO (Single Sign-On).
 *
 * <p>Après une authentification HMAC réussie (TP3), ce service génère
 * un token UUID valable {@link AccessToken#EXPIRY_MINUTES} minutes.
 * Ce token doit être inclus dans le header {@code Authorization: Bearer <token>}
 * pour accéder aux routes protégées.</p>
 *
 * <h2>Cycle de vie</h2>
 * <ol>
 *   <li>{@link #generate(User)} — crée et persiste le token après login réussi.</li>
 *   <li>{@link #getUserByToken(String)} — vérifie et retourne le propriétaire du token.</li>
 * </ol>
 *
 * @see com.example.auth.entity.AccessToken
 * @see com.example.auth.repository.AccessTokenRepository
 * @version 3.0
 */
@Service
public class TokenService {

    private final AccessTokenRepository accessTokenRepository;

    /**
     * Injecte le repository des tokens via le constructeur.
     *
     * @param accessTokenRepository repository JPA des tokens d'accès
     */
    public TokenService(AccessTokenRepository accessTokenRepository) {
        this.accessTokenRepository = accessTokenRepository;
    }

    /**
     * Génère et persiste un nouveau token d'accès pour l'utilisateur authentifié.
     *
     * <p>Le token est un UUID aléatoire. Sa date d'expiration est fixée à
     * {@code now + }{@link AccessToken#EXPIRY_MINUTES} minutes.</p>
     *
     * @param user utilisateur authentifié pour lequel émettre le token
     * @return le token créé et sauvegardé en base
     */
    public AccessToken generate(User user) {
        AccessToken token = new AccessToken(user, UUID.randomUUID().toString());
        return accessTokenRepository.save(token);
    }

    /**
     * Retrouve et valide l'utilisateur associé à un token Bearer.
     *
     * <p>Vérifications effectuées dans l'ordre :</p>
     * <ol>
     *   <li>Le token existe en base.</li>
     *   <li>Le token n'est pas expiré.</li>
     * </ol>
     *
     * @param tokenValue valeur UUID du token Bearer transmis dans le header Authorization
     * @return l'utilisateur propriétaire du token valide
     * @throws AuthenticationFailedException si le token est inexistant ou expiré
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