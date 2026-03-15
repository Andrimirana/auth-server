package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Service principal d'authentification pour TP2.
 *
 * <p>Améliorations par rapport au TP1 :
 * <ul>
 *   <li>Hachage BCrypt — mot de passe jamais stocké en clair</li>
 *   <li>Politique de mot de passe stricte (12 caractères minimum)</li>
 *   <li>Anti brute-force : blocage après 5 échecs pendant 2 minutes</li>
 * </ul>
 * </p>
 *
 * <p><b>AVERTISSEMENT :</b> TP2 améliore le stockage mais ne protège
 * pas encore contre le rejeu. Si un attaquant capture la requête de
 * login, il peut tenter de la rejouer. Corrigé au TP3 avec HMAC + nonce.</p>
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 2;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyValidator passwordPolicyValidator;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       PasswordPolicyValidator passwordPolicyValidator) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyValidator = passwordPolicyValidator;
    }

    /**
     * Inscrit un nouvel utilisateur après validation stricte du mot de passe.
     *
     * @param email    l'email de l'utilisateur
     * @param password le mot de passe en clair (sera haché avant stockage)
     * @return l'utilisateur créé
     * @throws InvalidInputException     si email ou mot de passe invalide
     * @throws ResourceConflictException si l'email est déjà utilisé
     */
    public User register(String email, String password) {
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("Email ne peut pas être vide");
        }
        if (!email.contains("@")) {
            throw new InvalidInputException("Format email invalide");
        }

        // Validation politique TP2
        passwordPolicyValidator.validate(password);

        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription échouée - email déjà existant : {}", email);
            throw new ResourceConflictException("Email déjà utilisé");
        }

        // Hachage BCrypt avant stockage
        String hash = passwordEncoder.encode(password);
        User user = new User(email, hash);
        userRepository.save(user);

        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie un utilisateur avec protection anti brute-force.
     *
     * @param email    l'email
     * @param password le mot de passe en clair
     * @return un token de session UUID
     * @throws AuthenticationFailedException si identifiants incorrects ou compte bloqué
     */
    public String login(String email, String password) {
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            throw new InvalidInputException("Email et mot de passe requis");
        }

        Optional<User> optUser = userRepository.findByEmail(email);

        // Même message pour email inconnu ou mauvais mot de passe
        // -> évite de divulguer si un email existe en base
        if (optUser.isEmpty()) {
            logger.warn("Connexion échouée - email inconnu : {}", email);
            throw new AuthenticationFailedException("Identifiants incorrects");
        }

        User user = optUser.get();

        // Vérifier si compte bloqué
        if (user.getLockUntil() != null
                && user.getLockUntil().isAfter(LocalDateTime.now())) {
            logger.warn("Connexion bloquée brute-force pour : {}", email);
            throw new AuthenticationFailedException(
                    "Compte bloqué suite à trop de tentatives. Réessayez dans 2 minutes."
            );
        }

        // Vérifier le mot de passe avec BCrypt
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);

            if (attempts >= MAX_ATTEMPTS) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));
                logger.warn("Compte bloqué après {} échecs pour : {}", attempts, email);
            }

            userRepository.save(user);
            logger.warn("Connexion échouée - mauvais mot de passe pour : {}", email);
            throw new AuthenticationFailedException("Identifiants incorrects");
        }

        // Succès — réinitialiser le compteur
        user.setFailedAttempts(0);
        user.setLockUntil(null);
        userRepository.save(user);

        String token = UUID.randomUUID().toString();
        logger.info("Connexion réussie pour : {}", email);
        return token;
    }
    /**
     * Délègue l'évaluation de force au validateur.
     *
     * @param password le mot de passe à évaluer
     * @return "WEAK", "MEDIUM" ou "STRONG"
     */
    public String evaluatePasswordStrength(String password) {
        return passwordPolicyValidator.evaluateStrength(password);
    }
}