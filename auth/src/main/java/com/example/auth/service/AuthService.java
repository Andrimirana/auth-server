package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.LoginResponse;
import com.example.auth.entity.AccessToken;
import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service principal d'authentification TP3.
 *
 * <p>Le mot de passe ne circule jamais sur le réseau.
 * Le client envoie une preuve HMAC-SHA256 avec nonce et timestamp.</p>
 *
 * <p>À l'inscription : le mot de passe est stocké en clair dans la base
 * (champ {@code password_encrypted}) pour permettre le recalcul HMAC au login.</p>
 *
 * <p><b>Note pédagogique TP3 :</b> Le stockage en clair est accepté ici pour
 * permettre le protocole HMAC. Le chiffrement via Master Key sera ajouté au TP4.</p>
 *
 * @version 3.0
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final int  MAX_ATTEMPTS             = 5;
    private static final int  LOCK_MINUTES             = 2;
    private static final long TIMESTAMP_WINDOW_SECONDS = 60L;

    private final UserRepository          userRepository;
    private final AuthNonceRepository     nonceRepository;
    private final HmacService             hmacService;
    private final TokenService            tokenService;
    private final PasswordPolicyValidator passwordPolicyValidator;

    public AuthService(UserRepository userRepository,
                       AuthNonceRepository nonceRepository,
                       HmacService hmacService,
                       TokenService tokenService,
                       PasswordPolicyValidator passwordPolicyValidator) {
        this.userRepository          = userRepository;
        this.nonceRepository         = nonceRepository;
        this.hmacService             = hmacService;
        this.tokenService            = tokenService;
        this.passwordPolicyValidator = passwordPolicyValidator;
    }

    /**
     * Inscrit un nouvel utilisateur.
     *
     * <p>Le mot de passe est stocké en clair pour permettre le protocole HMAC au login.</p>
     *
     * @param email           email de l'utilisateur
     * @param password        mot de passe en clair
     * @param passwordConfirm confirmation du mot de passe
     * @return l'utilisateur créé
     * @throws InvalidInputException     si données invalides
     * @throws ResourceConflictException si email déjà utilisé
     */
    public User register(String email, String password, String passwordConfirm) {
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("Email ne peut pas être vide");
        }
        if (!email.contains("@")) {
            throw new InvalidInputException("Format email invalide");
        }
        if (!password.equals(passwordConfirm)) {
            throw new InvalidInputException("Les mots de passe ne correspondent pas");
        }

        passwordPolicyValidator.validate(password);

        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription échouée - email déjà existant : {}", email);
            throw new ResourceConflictException("Email déjà utilisé");
        }

        // TP3 : stockage en clair pour permettre le recalcul HMAC au login
        User user = new User(email, password);
        userRepository.save(user);

        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie via le protocole HMAC-SHA256 avec nonce et timestamp.
     *
     * <p>Vérifications dans l'ordre :</p>
     * <ol>
     *   <li>Email existe</li>
     *   <li>Compte non verrouillé (anti brute-force)</li>
     *   <li>Timestamp dans la fenêtre ±60 secondes</li>
     *   <li>Nonce non déjà utilisé (anti-rejeu)</li>
     *   <li>Recalcul HMAC avec le mot de passe stocké</li>
     *   <li>Comparaison HMAC en temps constant</li>
     * </ol>
     *
     * @param request requête contenant email, nonce, timestamp, hmac
     * @return LoginResponse avec accessToken et expiresAt
     * @throws AuthenticationFailedException si une vérification échoue
     */
    public LoginResponse login(LoginRequest request) {
        if (request.getEmail() == null || request.getEmail().isBlank()) {
            throw new InvalidInputException("Email requis");
        }

        // 1. Vérifier que l'email existe
        Optional<User> optUser = userRepository.findByEmail(request.getEmail());
        if (optUser.isEmpty()) {
            logger.warn("Connexion échouée - email inconnu : {}", request.getEmail());
            throw new AuthenticationFailedException("Identifiants incorrects");
        }

        User user = optUser.get();

        // 2. Vérifier si compte verrouillé (anti brute-force)
        if (user.getLockUntil() != null && user.getLockUntil().isAfter(LocalDateTime.now())) {
            logger.warn("Connexion bloquée brute-force pour : {}", request.getEmail());
            throw new AuthenticationFailedException("Compte bloqué. Réessayez dans 2 minutes.");
        }

        // 3. Vérifier le timestamp (fenêtre ±60 secondes)
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - request.getTimestamp()) > TIMESTAMP_WINDOW_SECONDS) {
            logger.warn("Connexion échouée - timestamp invalide pour : {}", request.getEmail());
            throw new AuthenticationFailedException("Identifiants incorrects");
        }

        // 4. Vérifier le nonce (anti-rejeu)
        Optional<AuthNonce> existingNonce = nonceRepository.findByUserAndNonce(user, request.getNonce());
        if (existingNonce.isPresent()) {
            logger.warn("Connexion échouée - nonce déjà utilisé pour : {}", request.getEmail());
            throw new AuthenticationFailedException("Identifiants incorrects");
        }

        // Enregistrer le nonce immédiatement pour bloquer tout rejeu concurrent
        nonceRepository.save(new AuthNonce(user, request.getNonce()));

        // 5. Recalculer le HMAC avec le mot de passe stocké en clair
        String passwordPlain = user.getPasswordEncrypted(); // TP3 : stocké en clair
        String message       = request.getEmail() + ":" + request.getNonce() + ":" + request.getTimestamp();
        String expectedHmac;
        try {
            expectedHmac = hmacService.compute(passwordPlain, message);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            logger.error("Erreur calcul HMAC pour : {}", request.getEmail());
            throw new AuthenticationFailedException("Identifiants incorrects");
        }

        // 6. Comparer en temps constant (protection timing attack)
        if (!hmacService.compare(expectedHmac, request.getHmac())) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);
            if (attempts >= MAX_ATTEMPTS) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));
                logger.warn("Compte bloqué après {} échecs pour : {}", attempts, request.getEmail());
            }
            userRepository.save(user);
            logger.warn("Connexion échouée - HMAC invalide pour : {}", request.getEmail());
            throw new AuthenticationFailedException("Identifiants incorrects");
        }

        // Succès — réinitialiser le compteur
        user.setFailedAttempts(0);
        user.setLockUntil(null);
        userRepository.save(user);

        AccessToken token = tokenService.generate(user);
        logger.info("Connexion réussie pour : {}", request.getEmail());

        return new LoginResponse(token.getToken(), token.getExpiresAt());
    }

    /**
     * Retrouve l'utilisateur associé à un token valide.
     *
     * @param tokenValue valeur du token Bearer
     * @return l'utilisateur propriétaire
     * @throws AuthenticationFailedException si token invalide ou expiré
     */
    public User getUserByToken(String tokenValue) {
        return tokenService.getUserByToken(tokenValue);
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