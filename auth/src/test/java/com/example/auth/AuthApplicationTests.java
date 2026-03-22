package com.example.auth;

import com.example.auth.dto.LoginRequest;
import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import com.example.auth.service.HmacService;
import com.example.auth.service.PasswordPolicyValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour le serveur d'authentification TP3.
 * Protocole HMAC-SHA256 avec nonce et timestamp.
 */
@SpringBootTest
@Transactional
class AuthApplicationTests {

    @Autowired
    private AuthService authService;

    @Autowired
    private HmacService hmacService;

    @Autowired
    private PasswordPolicyValidator passwordPolicyValidator;

    private static final String VALID_PASSWORD = "Password123!";
    private static final String VALID_EMAIL    = "test@example.com";

    // ========== MÉTHODE UTILITAIRE ==========

    /**
     * Construit une LoginRequest valide avec HMAC correct.
     */
    private LoginRequest buildValidRequest(String email, String password) throws Exception {
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond();
        String message   = email + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(password, message);

        LoginRequest req = new LoginRequest();
        req.setEmail(email);
        req.setNonce(nonce);
        req.setTimestamp(timestamp);
        req.setHmac(hmac);
        return req;
    }

    // ========== TESTS INSCRIPTION ==========

    // Test 1 - Email vide
    @Test
    void testEmailVide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", VALID_PASSWORD, VALID_PASSWORD)
        );
    }

    // Test 2 - Format email incorrect
    @Test
    void testEmailFormatIncorrect() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("pasunemail", VALID_PASSWORD, VALID_PASSWORD)
        );
    }

    // Test 3 - Mot de passe trop court
    @Test
    void testMotDePasseTropCourt() {
        assertThrows(InvalidInputException.class, () ->
                authService.register(VALID_EMAIL, "Ab1!", "Ab1!")
        );
    }

    // Test 4 - Mots de passe différents
    @Test
    void testMotsDePasseDifferents() {
        assertThrows(InvalidInputException.class, () ->
                authService.register(VALID_EMAIL, VALID_PASSWORD, "AutrePass1!")
        );
    }

    // Test 5 - Inscription OK
    @Test
    void testInscriptionOK() {
        assertDoesNotThrow(() ->
                authService.register("nouveau@example.com", VALID_PASSWORD, VALID_PASSWORD)
        );
    }

    // Test 6 - Inscription refusée si email déjà existant
    @Test
    void testInscriptionEmailDejaExistant() {
        authService.register("doublon@example.com", VALID_PASSWORD, VALID_PASSWORD);
        assertThrows(ResourceConflictException.class, () ->
                authService.register("doublon@example.com", VALID_PASSWORD, VALID_PASSWORD)
        );
    }

    // ========== TESTS LOGIN HMAC ==========

    // Test 7 - Login OK avec HMAC valide
    @Test
    void testLoginOkHmacValide() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);
        LoginRequest req = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);
        assertDoesNotThrow(() -> authService.login(req));
    }

    // Test 8 - Login KO HMAC invalide
    @Test
    void testLoginKoHmacInvalide() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);
        LoginRequest req = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);
        req.setHmac("hmac_completement_faux");
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(req)
        );
    }

    // Test 9 - Login KO timestamp expiré (trop vieux)
    @Test
    void testLoginKoTimestampExpire() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond() - 120; // 2 minutes dans le passé
        String message   = VALID_EMAIL + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(VALID_PASSWORD, message);

        LoginRequest req = new LoginRequest();
        req.setEmail(VALID_EMAIL);
        req.setNonce(nonce);
        req.setTimestamp(timestamp);
        req.setHmac(hmac);

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(req)
        );
    }

    // Test 10 - Login KO timestamp futur
    @Test
    void testLoginKoTimestampFutur() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);
        String nonce     = UUID.randomUUID().toString();
        long   timestamp = Instant.now().getEpochSecond() + 120; // 2 minutes dans le futur
        String message   = VALID_EMAIL + ":" + nonce + ":" + timestamp;
        String hmac      = hmacService.compute(VALID_PASSWORD, message);

        LoginRequest req = new LoginRequest();
        req.setEmail(VALID_EMAIL);
        req.setNonce(nonce);
        req.setTimestamp(timestamp);
        req.setHmac(hmac);

        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(req)
        );
    }

    // Test 11 - Login KO nonce déjà utilisé (anti-rejeu)
    @Test
    void testLoginKoNonceDejaUtilise() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);
        LoginRequest req = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);

        // Premier login réussi
        authService.login(req);

        // Deuxième login avec le même nonce = rejeté
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(req)
        );
    }

    // Test 12 - Login KO user inconnu
    @Test
    void testLoginKoUserInconnu() throws Exception {
        LoginRequest req = buildValidRequest("inconnu@example.com", VALID_PASSWORD);
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login(req)
        );
    }

    // Test 13 - Token émis et /api/me accessible
    @Test
    void testTokenEmisEtApiMeOk() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);
        LoginRequest req = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);

        var response = authService.login(req);
        assertNotNull(response.getAccessToken());
        assertNotNull(response.getExpiresAt());

        // Vérifier que le token donne accès à /api/me
        User user = authService.getUserByToken(response.getAccessToken());
        assertEquals(VALID_EMAIL, user.getEmail());
    }

    // Test 14 - Accès /api/me sans token KO
    @Test
    void testApiMeSansTokenKo() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.getUserByToken("token_inexistant")
        );
    }

    // Test 15 - Comparaison HMAC en temps constant
    @Test
    void testComparaisonTempsConstant() {
        assertTrue(hmacService.compare("abc", "abc"));
        assertFalse(hmacService.compare("abc", "xyz"));
        assertFalse(hmacService.compare(null, "abc"));
        assertFalse(hmacService.compare("abc", null));
    }

    // Test 16 - Non-divulgation : même message pour email inconnu et HMAC invalide
    @Test
    void testNonDivulgationErreur() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);

        LoginRequest req1 = buildValidRequest("inconnu@example.com", VALID_PASSWORD);
        LoginRequest req2 = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);
        req2.setHmac("hmac_faux");

        AuthenticationFailedException ex1 = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login(req1)
        );
        AuthenticationFailedException ex2 = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login(req2)
        );

        assertEquals(ex1.getMessage(), ex2.getMessage());
    }

    // Test 17 - Évaluation force mot de passe WEAK
    @Test
    void testPasswordStrengthWeak() {
        assertEquals("WEAK", passwordPolicyValidator.evaluateStrength("abc"));
    }

    // Test 18 - Évaluation force mot de passe STRONG
    @Test
    void testPasswordStrengthStrong() {
        assertEquals("STRONG", passwordPolicyValidator.evaluateStrength("Password123!@#"));
    }
}