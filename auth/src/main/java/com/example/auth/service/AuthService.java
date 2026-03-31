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
 * Service principal d'authentification — protocole HMAC-SHA256 avec nonce et timestamp (TP3).
 *
 * <h2>Principe du protocole</h2>
 * <p>Le mot de passe ne circule <b>jamais</b> sur le réseau.
 * Le client prouve qu'il connaît le secret en calculant :</p>
 * <pre>
 *   hmac = HMAC_SHA256(key = password, data = email:nonce:timestamp)
 * </pre>
 * <p>Le serveur recalcule la même signature et compare en <b>temps constant</b>
 * pour éviter les attaques temporelles.</p>
 *
 * <h2>Évolution par TP</h2>
 * <ul>
 *   <li><b>TP1</b> : mot de passe en clair, authentification basique. Cette implémentation
 *       est volontairement dangereuse et ne doit jamais être utilisée en production.</li>
 *   <li><b>TP2</b> : BCrypt + politique de mot de passe + anti brute-force.
 *       TP2 améliore le stockage mais ne protège pas encore contre le rejeu.</li>
 *   <li><b>TP3</b> : protocole HMAC + nonce + timestamp. Le mot de passe est stocké
 *       en clair pour permettre le recalcul HMAC (accepté à des fins pédagogiques).</li>
 *   <li><b>TP4</b> : les mots de passe sont désormais chiffrés en base via AES-256-GCM
 *       grâce à une Master Key injectée par variable d'environnement ({@code APP_MASTER_KEY}).
 *       Le champ {@code password_encrypted} contient la valeur au format
 *       {@code v1:Base64(iv):Base64(ciphertext)}. La clé ne doit jamais être dans le code.</li>
 * </ul>
 *
 * @see HmacService
 * @see TokenService
 * @see PasswordPolicyValidator
 * @see MasterKeyService
 * @version 4.0
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    /** Nombre maximal de tentatives échouées avant verrouillage du compte. */
    private static final int  MAX_ATTEMPTS             = 5;

    /** Durée de verrouillage en minutes après dépassement du seuil d'échecs. */
    private static final int  LOCK_MINUTES             = 2;

    /** Fenêtre de tolérance en secondes pour le timestamp de la requête (±60 s). */
    private static final long TIMESTAMP_WINDOW_SECONDS = 60L;

    private final UserRepository          userRepository;
    private final AuthNonceRepository     nonceRepository;
    private final HmacService             hmacService;
    private final TokenService            tokenService;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final MasterKeyService        masterKeyService;

    /**
     * Injecte toutes les dépendances via le constructeur (injection recommandée Spring).
     *
     * @param userRepository          repository des utilisateurs
     * @param nonceRepository         repository des nonces anti-rejeu
     * @param hmacService             service de calcul et vérification HMAC
     * @param tokenService            service de gestion des tokens SSO
     * @param passwordPolicyValidator validateur de la politique de mot de passe
     * @param masterKeyService        service de chiffrement AES-256-GCM (TP4)
     */
    public AuthService(UserRepository userRepository,
                       AuthNonceRepository nonceRepository,
                       HmacService hmacService,
                       TokenService tokenService,
                       PasswordPolicyValidator passwordPolicyValidator,
                       MasterKeyService masterKeyService) {
        this.userRepository          = userRepository;
        this.nonceRepository         = nonceRepository;
        this.hmacService             = hmacService;
        this.tokenService            = tokenService;
        this.passwordPolicyValidator = passwordPolicyValidator;
        this.masterKeyService        = masterKeyService;
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

        // TP4 : chiffrement AES-256-GCM du mot de passe avant stockage
        User user = new User(email, masterKeyService.encrypt(password));
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
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    logger.warn("Connexion échouée - email inconnu : {}", request.getEmail());
                    return new AuthenticationFailedException("Identifiants incorrects");
                });

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

        // 5. Déchiffrer le mot de passe et recalculer le HMAC (TP4 : AES-GCM)
        String passwordPlain = masterKeyService.decrypt(user.getPasswordEncrypted());
        String message       = request.getEmail() + ":" + request.getNonce() + ":" + request.getTimestamp();
        String expectedHmac;
        try {
            expectedHmac = hmacService.compute(passwordPlain, message);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            logger.error("Erreur calcul HMAC pour : {}", request.getEmail(), e);
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

    /**
     * Change le mot de passe d'un utilisateur authentifié (TP5).
     *
     * <h2>Étapes de vérification dans l'ordre</h2>
     * <ol>
     *   <li>Token Bearer valide → identification de l'utilisateur.</li>
     *   <li>Déchiffrement AES-GCM du mot de passe stocké + comparaison avec {@code oldPassword}.</li>
     *   <li>{@code newPassword} == {@code confirmPassword}.</li>
     *   <li>Politique de sécurité sur {@code newPassword} (12 car., maj., min., chiffre, spécial).</li>
     *   <li>Chiffrement AES-256-GCM du nouveau mot de passe et mise à jour en base.</li>
     * </ol>
     *
     * @param tokenValue      valeur du Bearer token de l'utilisateur authentifié
     * @param oldPassword     ancien mot de passe en clair, pour vérification
     * @param newPassword     nouveau mot de passe en clair
     * @param confirmPassword confirmation du nouveau mot de passe
     * @throws AuthenticationFailedException si le token est invalide ou l'ancien MDP est incorrect
     * @throws InvalidInputException         si la confirmation diffère ou la politique n'est pas respectée
     */
    public void changePassword(String tokenValue, String oldPassword,
                               String newPassword, String confirmPassword) {
        // 1. Identifier l'utilisateur via son token (lève AuthenticationFailedException si invalide)
        User user = tokenService.getUserByToken(tokenValue);

        // 2. Déchiffrer le mot de passe stocké et vérifier l'ancien mot de passe
        String storedPlain = masterKeyService.decrypt(user.getPasswordEncrypted());
        if (!storedPlain.equals(oldPassword)) {
            logger.warn("Changement MDP échoué - ancien mot de passe incorrect pour : {}", user.getEmail());
            throw new AuthenticationFailedException("Ancien mot de passe incorrect");
        }

        // 3. Vérifier la confirmation
        if (!newPassword.equals(confirmPassword)) {
            throw new InvalidInputException("Les mots de passe ne correspondent pas");
        }

        // 4. Valider la politique de sécurité
        passwordPolicyValidator.validate(newPassword);

        // 5. Chiffrer et sauvegarder
        user.setPasswordEncrypted(masterKeyService.encrypt(newPassword));
        userRepository.save(user);

        logger.info("Mot de passe changé avec succès pour : {}", user.getEmail());
    }
}

