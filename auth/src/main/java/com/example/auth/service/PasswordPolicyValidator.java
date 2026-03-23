package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

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

    private static final int     MIN_LENGTH    = 12;
    private static final int     STRONG_LENGTH = 16;

    // Patterns pré-compilés pour éviter la recompilation à chaque appel (ReDoS, performance)
    private static final Pattern HAS_UPPER   = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWER   = Pattern.compile("[a-z]");
    private static final Pattern HAS_DIGIT   = Pattern.compile("[0-9]");
    private static final Pattern HAS_SPECIAL = Pattern.compile("[^a-zA-Z0-9]");

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
        if (!HAS_UPPER.matcher(password).find()) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une majuscule"
            );
        }
        if (!HAS_LOWER.matcher(password).find()) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une minuscule"
            );
        }
        if (!HAS_DIGIT.matcher(password).find()) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un chiffre"
            );
        }
        if (!HAS_SPECIAL.matcher(password).find()) {
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
        if (HAS_UPPER.matcher(password).find())   score++;
        if (HAS_LOWER.matcher(password).find())   score++;
        if (HAS_DIGIT.matcher(password).find())   score++;
        if (HAS_SPECIAL.matcher(password).find()) score++;
        if (password.length() >= STRONG_LENGTH)   score++;

        if (score <= 2) return "WEAK";
        if (score <= 3) return "MEDIUM";
        return "STRONG";
    }
}
