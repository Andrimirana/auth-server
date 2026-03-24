package com.example.auth;

import com.example.auth.dto.LoginRequest;
import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.AuthService;
import com.example.auth.service.HmacService;
import com.example.auth.service.PasswordPolicyValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests d'intégration pour le serveur d'authentification TP3.
 * Protocole HMAC-SHA256 avec nonce et timestamp.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthApplicationTests {

    @Autowired
    private AuthService authService;

    @Autowired
    private HmacService hmacService;

    @Autowired
    private PasswordPolicyValidator passwordPolicyValidator;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MockMvc mockMvc;

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

    // Test 19 - Lockout expire correctement après la durée de blocage
    @Test
    void testLockoutExpireCorrectement() throws Exception {
        authService.register(VALID_EMAIL, VALID_PASSWORD, VALID_PASSWORD);

        // Provoquer 5 échecs consécutifs pour déclencher le blocage
        for (int i = 0; i < 5; i++) {
            LoginRequest bad = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);
            bad.setHmac("hmac_faux_" + i);
            try {
                authService.login(bad);
            } catch (AuthenticationFailedException ignored) {
                // Intentionnel : l'exception est attendue à chaque itération.
                // Son seul effet est d'incrémenter le compteur d'échecs côté serveur
                // afin de déclencher le blocage du compte après 5 tentatives.
            }
        }

        // Vérifier que le compte est bien bloqué
        LoginRequest blockedReq = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);
        AuthenticationFailedException locked = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login(blockedReq)
        );
        assertTrue(locked.getMessage().contains("bloqué"),
                "Le compte doit être bloqué après 5 échecs");

        // Simuler l'expiration : on remet lock_until dans le passé via UserRepository
        User user = userRepository.findByEmail(VALID_EMAIL).orElseThrow();
        user.setLockUntil(LocalDateTime.now().minusMinutes(5));
        user.setFailedAttempts(0);
        userRepository.save(user);

        // Après expiration, la connexion doit fonctionner
        LoginRequest validReq = buildValidRequest(VALID_EMAIL, VALID_PASSWORD);
        assertDoesNotThrow(() -> authService.login(validReq),
                "La connexion doit réussir après expiration du blocage");
    }

    // ========== TESTS CONTRÔLEUR AuthController ==========

    // Test 20 - POST /api/auth/register via HTTP → 200
    @Test
    void testRegisterEndpointOk() throws Exception {
        String json = "{\"email\":\"ctrl@example.com\","
                + "\"password\":\"Password123!\","
                + "\"passwordConfirm\":\"Password123!\"}";
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("ctrl@example.com"))
                .andExpect(jsonPath("$.message").value("Inscription réussie"));
    }

    // Test 21 - POST /api/auth/register doublon → 409
    @Test
    void testRegisterEndpointDoublon() throws Exception {
        String json = "{\"email\":\"ctrl2@example.com\","
                + "\"password\":\"Password123!\","
                + "\"passwordConfirm\":\"Password123!\"}";
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isConflict());
    }

    // Test 22 - POST /api/auth/password-strength → 200
    @Test
    void testPasswordStrengthEndpoint() throws Exception {
        mockMvc.perform(post("/api/auth/password-strength")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"Password123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.strength").value("STRONG"));
    }

    // Test 23 - POST /api/auth/login HMAC invalide → 401
    @Test
    void testLoginEndpointHmacInvalide() throws Exception {
        String regJson = "{\"email\":\"loginctrl@example.com\","
                + "\"password\":\"Password123!\","
                + "\"passwordConfirm\":\"Password123!\"}";
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regJson))
                .andExpect(status().isOk());

        long ts = Instant.now().getEpochSecond();
        String loginJson = "{\"email\":\"loginctrl@example.com\","
                + "\"nonce\":\"nonce-ctrl\","
                + "\"timestamp\":" + ts + ","
                + "\"hmac\":\"hmac_invalide\"}";
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isUnauthorized());
    }

    // ========== TESTS CONTRÔLEUR UserController ==========

    // Test 24 - GET /api/me sans header Authorization → 401
    @Test
    void testMeSansAuthorization() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized());
    }

    // Test 25 - GET /api/me avec header mal formé → 401
    @Test
    void testMeHeaderMalForme() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Basic not-bearer"))
                .andExpect(status().isUnauthorized());
    }

    // Test 26 - GET /api/me avec token invalide → 401
    @Test
    void testMeTokenInvalide() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer token-inexistant"))
                .andExpect(status().isUnauthorized());
    }

    // Test 27 - GET /api/me avec token valide → 200
    @Test
    void testMeTokenValide() throws Exception {
        // Inscription + login via HTTP pour obtenir un vrai token
        String regJson = "{\"email\":\"me@example.com\","
                + "\"password\":\"Password123!\","
                + "\"passwordConfirm\":\"Password123!\"}";
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regJson))
                .andExpect(status().isOk());

        String nonce = UUID.randomUUID().toString();
        long ts = Instant.now().getEpochSecond();
        String message = "me@example.com:" + nonce + ":" + ts;
        String hmac = hmacService.compute("Password123!", message);
        String loginJson = "{\"email\":\"me@example.com\","
                + "\"nonce\":\"" + nonce + "\","
                + "\"timestamp\":" + ts + ","
                + "\"hmac\":\"" + hmac + "\"}";

        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // Extraire le token du JSON retourné
        String token = body.split("\"accessToken\":\"")[1].split("\"")[0];

        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("me@example.com"));
    }

    // ========== TESTS BRANCHES MANQUANTES PasswordPolicyValidator ==========

    // Test 28 - evaluateStrength : force MEDIUM (score = 3)
    @Test
    void testPasswordStrengthMedium() {
        // Majuscule + minuscule + chiffre, pas de spécial, longueur < 16
        assertEquals("MEDIUM", passwordPolicyValidator.evaluateStrength("Password1234"));
    }

    // Test 29 - validate : mot de passe null
    @Test
    void testValidateNull() {
        assertThrows(InvalidInputException.class,
                () -> passwordPolicyValidator.validate(null));
    }

    // Test 30 - validate : pas de majuscule
    @Test
    void testValidateSansMajuscule() {
        assertThrows(InvalidInputException.class,
                () -> passwordPolicyValidator.validate("password123!abcdef"));
    }

    // Test 31 - validate : pas de minuscule
    @Test
    void testValidateSansMinuscule() {
        assertThrows(InvalidInputException.class,
                () -> passwordPolicyValidator.validate("PASSWORD123!ABCDEF"));
    }

    // Test 32 - validate : pas de chiffre
    @Test
    void testValidateSansChiffre() {
        assertThrows(InvalidInputException.class,
                () -> passwordPolicyValidator.validate("PasswordAbcDef!xyz"));
    }

    // Test 33 - validate : pas de caractère spécial
    @Test
    void testValidateSansSpecial() {
        assertThrows(InvalidInputException.class,
                () -> passwordPolicyValidator.validate("Password123AbcDef456"));
    }
}