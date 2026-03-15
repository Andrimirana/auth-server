package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;
import org.springframework.stereotype.Component;

/**
 * Validateur de politique de mot de passe pour TP2.
 *
 * <p>Règles imposées :
 * <ul>
 *   <li>Minimum 12 caractères</li>
 *   <li>Au moins 1 majuscule</li>
 *   <li>Au moins 1 minuscule</li>
 *   <li>Au moins 1 chiffre</li>
 *   <li>Au moins 1 caractère spécial</li>
 * </ul>
 * </p>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement
 * fragile et ne doit jamais être utilisée seule en production.</p>
 */
@Component
public class PasswordPolicyValidator {

    private static final int MIN_LENGTH = 12;

    /**
     * Valide le mot de passe selon la politique TP2.
     *
     * @param password le mot de passe à valider
     * @throws InvalidInputException si le mot de passe ne respecte pas la politique
     */
    public void validate(String password) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw new InvalidInputException(
                    "Mot de passe trop court (minimum " + MIN_LENGTH + " caractères)"
            );
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une majuscule"
            );
        }
        if (!password.matches(".*[a-z].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une minuscule"
            );
        }
        if (!password.matches(".*[0-9].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un chiffre"
            );
        }
        if (!password.matches(".*[^a-zA-Z0-9].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un caractère spécial"
            );
        }
    }

    /**
     * Évalue la force du mot de passe.
     *
     * @param password le mot de passe
     * @return "WEAK", "MEDIUM" ou "STRONG"
     */
    public String evaluateStrength(String password) {
        if (password == null || password.length() < MIN_LENGTH) return "WEAK";

        int score = 0;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*[0-9].*")) score++;
        if (password.matches(".*[^a-zA-Z0-9].*")) score++;
        if (password.length() >= 16) score++;

        if (score <= 2) return "WEAK";
        if (score <= 3) return "MEDIUM";
        return "STRONG";
    }
}