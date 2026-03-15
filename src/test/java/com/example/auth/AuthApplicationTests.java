package com.example.auth;

import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import com.example.auth.service.PasswordPolicyValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour le serveur d'authentification TP2.
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement
 * fragile et ne doit jamais être utilisée en production.</p>
 */
@SpringBootTest
@Transactional
class AuthApplicationTests {

    @Autowired
    private AuthService authService;

    @Autowired
    private PasswordPolicyValidator passwordPolicyValidator;

    // Mot de passe valide pour TP2 : 12 car, maj, min, chiffre, spécial
    private static final String VALID_PASSWORD = "Password123!";

    // ========== TESTS INSCRIPTION ==========

    // Test 1 - Email vide
    @Test
    void testEmailVide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", VALID_PASSWORD)
        );
    }

    // Test 2 - Format email incorrect
    @Test
    void testEmailFormatIncorrect() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("pasunemail", VALID_PASSWORD)
        );
    }

    // Test 3 - Mot de passe trop court (moins de 12 caractères)
    @Test
    void testMotDePasseTropCourt() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "Ab1!")
        );
    }

    // Test 4 - Mot de passe sans majuscule
    @Test
    void testMotDePasseSansMajuscule() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "password123!")
        );
    }

    // Test 5 - Mot de passe sans caractère spécial
    @Test
    void testMotDePasseSansCaractereSpecial() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "Password1234")
        );
    }

    // Test 6 - Inscription OK
    @Test
    void testInscriptionOK() {
        assertDoesNotThrow(() ->
                authService.register("nouveau@example.com", VALID_PASSWORD)
        );
    }

    // Test 7 - Inscription refusée si email déjà existant
    @Test
    void testInscriptionEmailDejaExistant() {
        authService.register("doublon@example.com", VALID_PASSWORD);
        assertThrows(ResourceConflictException.class, () ->
                authService.register("doublon@example.com", VALID_PASSWORD)
        );
    }

    // ========== TESTS CONNEXION ==========

    // Test 8 - Login OK
    @Test
    void testLoginOK() {
        authService.register("login@example.com", VALID_PASSWORD);
        assertDoesNotThrow(() ->
                authService.login("login@example.com", VALID_PASSWORD)
        );
    }

    // Test 9 - Login KO mauvais mot de passe
    @Test
    void testLoginMauvaisMotDePasse() {
        authService.register("user@example.com", VALID_PASSWORD);
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("user@example.com", "MauvaisPass1!")
        );
    }

    // Test 10 - Login KO email inconnu
    @Test
    void testLoginEmailInconnu() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@example.com", VALID_PASSWORD)
        );
    }

    // Test 11 - Non-divulgation : même message pour email inconnu et mauvais mot de passe
    @Test
    void testNonDivulgationErreur() {
        authService.register("exist@example.com", VALID_PASSWORD);

        AuthenticationFailedException ex1 = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login("inconnu@example.com", VALID_PASSWORD)
        );
        AuthenticationFailedException ex2 = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login("exist@example.com", "MauvaisPass1!")
        );

        // Les deux messages doivent être identiques
        assertEquals(ex1.getMessage(), ex2.getMessage());
    }

    // Test 12 - Lockout après 5 échecs
    @Test
    void testLockoutApres5Echecs() {
        authService.register("brute@example.com", VALID_PASSWORD);

        // 5 tentatives échouées
        for (int i = 0; i < 5; i++) {
            assertThrows(AuthenticationFailedException.class, () ->
                    authService.login("brute@example.com", "MauvaisPass1!")
            );
        }

        // La 6ème tentative doit indiquer que le compte est bloqué
        AuthenticationFailedException ex = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login("brute@example.com", VALID_PASSWORD)
        );
        assertTrue(ex.getMessage().contains("bloqué"));
    }

    // ========== TESTS POLITIQUE MOT DE PASSE ==========

    // Test 13 - Évaluation force WEAK
    @Test
    void testPasswordStrengthWeak() {
        assertEquals("WEAK", passwordPolicyValidator.evaluateStrength("abc"));
    }

    // Test 14 - Évaluation force STRONG
    @Test
    void testPasswordStrengthStrong() {
        assertEquals("STRONG", passwordPolicyValidator.evaluateStrength("Password123!@#"));
    }
}