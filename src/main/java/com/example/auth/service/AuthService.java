package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service principal gérant l'inscription et la connexion des utilisateurs.
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * Les mots de passe sont stockés en clair, ce qui est inacceptable en production.
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Inscrit un nouvel utilisateur.
     * @param email l'email de l'utilisateur
     * @param password le mot de passe en clair (dangereux)
     * @return l'utilisateur créé
     */
    public User register(String email, String password) {
        // Validation email
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("Email ne peut pas être vide");
        }
        if (!email.contains("@")) {
            throw new InvalidInputException("Format email invalide");
        }
        // Validation mot de passe (volontairement faible pour TP1)
        if (password == null || password.length() < 4) {
            throw new InvalidInputException("Mot de passe trop court (minimum 4 caractères)");
        }
        // Vérifier si email déjà utilisé
        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription échouée - email déjà existant : {}", email);
            throw new ResourceConflictException("Email déjà utilisé");
        }

        User user = new User(email, password);
        userRepository.save(user);
        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie un utilisateur.
     * @param email l'email de l'utilisateur
     * @param password le mot de passe en clair (dangereux)
     * @return l'utilisateur si authentifié
     */
    public User login(String email, String password) {
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            throw new InvalidInputException("Email et mot de passe requis");
        }

        User user = userRepository.findByEmail(email).orElseThrow(() -> {
            logger.warn("Connexion échouée - email inconnu : {}", email);
            return new AuthenticationFailedException("Email ou mot de passe incorrect");
        });

        if (!user.getPasswordClear().equals(password)) {
            logger.warn("Connexion échouée - mauvais mot de passe pour : {}", email);
            throw new AuthenticationFailedException("Email ou mot de passe incorrect");
        }

        logger.info("Connexion réussie pour : {}", email);
        return user;
    }
}