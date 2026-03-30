package com.example.auth.controller;

import com.example.auth.dto.ChangePasswordRequest;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.LoginResponse;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.service.AuthService;
import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Contrôleur REST gérant les endpoints d'authentification (TP3 — protocole HMAC).
 *
 * <h2>Endpoints exposés</h2>
 * <ul>
 *   <li>{@code POST /api/auth/register} — inscription d'un nouvel utilisateur.</li>
 *   <li>{@code POST /api/auth/login} — connexion via preuve HMAC-SHA256.</li>
 *   <li>{@code POST /api/auth/password-strength} — évaluation de la force d'un mot de passe.</li>
 * </ul>
 *
 * <p>Le protocole TP3 garantit que le mot de passe ne circule jamais sur le réseau.
 * Le client envoie une preuve {@code HMAC_SHA256(key=password, data=email:nonce:timestamp)}.</p>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.</p>
 *
 * @see AuthService
 * @see com.example.auth.service.HmacService
 * @version 3.0
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    /**
     * Injecte le service d'authentification via le constructeur.
     *
     * @param authService service principal d'authentification
     */
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Inscrit un nouvel utilisateur.
     *
     * <pre>
     * POST /api/auth/register
     * Content-Type: application/json
     * {
     *   "email"           : "user@example.com",
     *   "password"        : "MonMotDePasse1!",
     *   "passwordConfirm" : "MonMotDePasse1!"
     * }
     * </pre>
     *
     * @param request corps JSON contenant email, password et passwordConfirm
     * @return HTTP 200 avec message de confirmation et email inscrit,
     *         HTTP 400 si données invalides,
     *         HTTP 409 si email déjà utilisé
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestBody RegisterRequest request) {

        User user = authService.register(
                request.getEmail(),
                request.getPassword(),
                request.getPasswordConfirm()
        );
        return ResponseEntity.ok(Map.of(
                "message", "Inscription réussie",
                "email", user.getEmail()
        ));
    }

    /**
     * Authentifie un utilisateur via le protocole HMAC-SHA256 (TP3).
     *
     * <pre>
     * POST /api/auth/login
     * Content-Type: application/json
     * {
     *   "email"     : "user@example.com",
     *   "nonce"     : "uuid-aléatoire",
     *   "timestamp" : 1711234567,
     *   "hmac"      : "Base64(HMAC_SHA256(key=password, data=email:nonce:timestamp))"
     * }
     * </pre>
     *
     * @param request corps JSON contenant email, nonce, timestamp et hmac
     * @return HTTP 200 avec {@link LoginResponse} (accessToken + expiresAt),
     *         HTTP 401 si authentification échouée,
     *         HTTP 429 si compte verrouillé
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Évalue la force d'un mot de passe sans le stocker.
     *
     * <pre>
     * POST /api/auth/password-strength
     * Content-Type: application/json
     * { "password": "MonMotDePasse1!" }
     * </pre>
     *
     * <p><b>Note :</b> POST est utilisé intentionnellement pour ne pas exposer
     * le mot de passe dans l'URL (éviter le logging dans les access logs).</p>
     *
     * @param body map JSON avec la clé {@code "password"}
     * @return HTTP 200 avec {@code {"strength": "WEAK"|"MEDIUM"|"STRONG"}}
     */
    @PostMapping("/password-strength")
    public ResponseEntity<Map<String, Object>> passwordStrength(
            @RequestBody Map<String, String> body) {
        String password = body.get("password");
        String strength = authService.evaluatePasswordStrength(password);
        return ResponseEntity.ok(Map.of("strength", strength));
    }

    /**
     * Change le mot de passe d'un utilisateur authentifié (TP5).
     *
     * <pre>
     * PUT /api/auth/change-password
     * Authorization: Bearer &lt;accessToken&gt;
     * Content-Type: application/json
     * {
     *   "oldPassword"     : "AncienMotDePasse1!",
     *   "newPassword"     : "NouveauMotDePasse2@",
     *   "confirmPassword" : "NouveauMotDePasse2@"
     * }
     * </pre>
     *
     * @param authHeader en-tête {@code Authorization: Bearer <token>}
     * @param request    corps JSON avec oldPassword, newPassword, confirmPassword
     * @return HTTP 200 si succès, 400 si données invalides,
     *         401 si token invalide ou ancien MDP incorrect
     */
    @PutMapping("/change-password")
    public ResponseEntity<Map<String, Object>> changePassword(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody ChangePasswordRequest request) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationFailedException("Token manquant ou invalide");
        }

        String tokenValue = authHeader.substring(7);
        authService.changePassword(
                tokenValue,
                request.getOldPassword(),
                request.getNewPassword(),
                request.getConfirmPassword()
        );

        return ResponseEntity.ok(Map.of("message", "Mot de passe changé avec succès"));
    }
}