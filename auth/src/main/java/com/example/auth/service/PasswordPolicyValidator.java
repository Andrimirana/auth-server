package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Validateur de la politique de mot de passe — introduit en TP2.
 *
 * <h2>Règles imposées</h2>
 * <ul>
 *   <li>Minimum {@value #MIN_LENGTH} caractères.</li>
 *   <li>Au moins 1 lettre majuscule.</li>
 *   <li>Au moins 1 lettre minuscule.</li>
 *   <li>Au moins 1 chiffre.</li>
 *   <li>Au moins 1 caractère spécial (tout caractère non alphanumérique).</li>
 * </ul>
 *
 * <h2>Niveaux de force</h2>
 * <ul>
 *   <li><b>WEAK</b> — longueur insuffisante ou ≤ 2 critères satisfaits.</li>
 *   <li><b>MEDIUM</b> — 3 critères satisfaits.</li>
 *   <li><b>STRONG</b> — 4 critères + longueur ≥ {@value #STRONG_LENGTH}.</li>
 * </ul>
 *
 * <p><b>Note technique :</b> Les {@link Pattern} sont pré-compilés en constantes
 * statiques pour éviter une recompilation à chaque appel (performance et protection ReDoS).</p>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement fragile
 * et ne doit jamais être utilisée seule en production.
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.</p>
 *
 * @see com.example.auth.service.AuthService
 * @see com.example.auth.exception.InvalidInputException
 * @version 2.0
 */
@Component
public class PasswordPolicyValidator {

    /** Longueur minimale requise pour un mot de passe valide. */
    private static final int MIN_LENGTH = 12;

    /** Longueur à partir de laquelle un mot de passe est considéré fort. */
    private static final int STRONG_LENGTH = 16;

    /** Pattern de détection d'au moins une lettre majuscule. */
    private static final Pattern HAS_UPPER = Pattern.compile("[A-Z]");

    /** Pattern de détection d'au moins une lettre minuscule. */
    private static final Pattern HAS_LOWER = Pattern.compile("[a-z]");

    /** Pattern de détection d'au moins un chiffre. */
    private static final Pattern HAS_DIGIT = Pattern.compile("\\d");

    /** Pattern de détection d'au moins un caractère spécial (non alphanumérique). */
    private static final Pattern HAS_SPECIAL = Pattern.compile("[^a-zA-Z0-9]");

    /**
     * Valide le mot de passe selon la politique TP2.
     *
     * <p>Lève une {@link InvalidInputException} dès la première règle non respectée.</p>
     *
     * @param password le mot de passe en clair à valider
     * @throws InvalidInputException si le mot de passe est {@code null}, trop court,
     *                               ou ne satisfait pas l'une des règles de composition
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
     * Évalue la force d'un mot de passe sans le valider.
     *
     * <p>Calcule un score en comptant le nombre de critères satisfaits
     * (majuscule, minuscule, chiffre, spécial, longueur ≥ {@value #STRONG_LENGTH}).
     * Utilisé côté serveur pour alimenter l'indicateur visuel client (rouge/orange/vert).</p>
     *
     * @param password le mot de passe à évaluer (peut ne pas respecter la politique)
     * @return {@code "WEAK"} si score ≤ 2 ou longueur insuffisante,
     *         {@code "MEDIUM"} si score = 3,
     *         {@code "STRONG"} si score ≥ 4
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
