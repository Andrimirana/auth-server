package com.example.auth;

import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour le serveur d'authentification.
 * ATTENTION : Cette implementation est volontairement dangereuse
 * et ne doit jamais etre utilisee en production.
 */
@SpringBootTest
@Transactional
class AuthApplicationTests {

    @Autowired
    private AuthService authService;

    // Test 1 - Email vide
    @Test
    void testEmailVide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", "pwd1234")
        );
    }

    // Test 2 - Format email incorrect
    @Test
    void testEmailFormatIncorrect() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("pasunemail", "pwd1234")
        );
    }

    // Test 3 - Mot de passe trop court
    @Test
    void testMotDePasseTropCourt() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "abc")
        );
    }

    // Test 4 - Inscription OK
    @Test
    void testInscriptionOK() {
        assertDoesNotThrow(() ->
                authService.register("nouveau@example.com", "pwd1234")
        );
    }

    // Test 5 - Inscription refusee si email deja existant
    @Test
    void testInscriptionEmailDejaExistant() {
        authService.register("doublon@example.com", "pwd1234");
        assertThrows(ResourceConflictException.class, () ->
                authService.register("doublon@example.com", "pwd1234")
        );
    }

    // Test 6 - Login OK
    @Test
    void testLoginOK() {
        authService.register("login@example.com", "pwd1234");
        assertDoesNotThrow(() ->
                authService.login("login@example.com", "pwd1234")
        );
    }

    // Test 7 - Login KO mauvais mot de passe
    @Test
    void testLoginMauvaisMotDePasse() {
        authService.register("user@example.com", "pwd1234");
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("user@example.com", "mauvais")
        );
    }

    // Test 8 - Login KO email inconnu
    @Test
    void testLoginEmailInconnu() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@example.com", "pwd1234")
        );
    }
}