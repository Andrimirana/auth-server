package com.example.auth.controller;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.LoginResponse;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller REST gérant les endpoints d'authentification TP3.
 *
 * <p>Protocole TP3 : le mot de passe ne circule plus sur le réseau.
 * Le client envoie une preuve HMAC avec nonce et timestamp.</p>
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint d'inscription.
     * POST /api/auth/register
     * Body JSON : { "email": "...", "password": "...", "passwordConfirm": "..." }
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
     * Endpoint de connexion TP3 — protocole HMAC.
     * POST /api/auth/login
     * Body JSON : { "email": "...", "nonce": "...", "timestamp": 123, "hmac": "..." }
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint pour évaluer la force d'un mot de passe.
     * POST /api/auth/password-strength
     * Body JSON : { "password": "xxx" }
     * Note: POST utilisé intentionnellement pour ne pas exposer le mot de passe dans l'URL.
     */
    @PostMapping("/password-strength")
    public ResponseEntity<Map<String, Object>> passwordStrength(
            @RequestBody Map<String, String> body) {
        String password = body.get("password");
        String strength = authService.evaluatePasswordStrength(password);
        return ResponseEntity.ok(Map.of("strength", strength));
    }
}