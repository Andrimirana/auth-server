package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpSession;
import java.util.Map;

/**
 * Controller REST gérant les endpoints d'authentification.
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement
 * fragile et ne doit jamais être utilisée en production.
 * TP2 améliore le stockage mais reste vulnérable au rejeu.</p>
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
     * @param email    l'email de l'utilisateur
     * @param password le mot de passe (doit respecter la politique TP2)
     * @return 200 avec email, 400 si invalide, 409 si email déjà existant
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestParam String email,
            @RequestParam String password) {

        User user = authService.register(email, password);
        return ResponseEntity.ok(Map.of(
                "message", "Inscription réussie",
                "email", user.getEmail()
        ));
    }

    /**
     * Endpoint de connexion.
     * POST /api/auth/login
     * @param email    l'email
     * @param password le mot de passe en clair
     * @param session  la session HTTP
     * @return 200 avec token, 401 si identifiants incorrects, 429 si compte bloqué
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestParam String email,
            @RequestParam String password,
            HttpSession session) {

        // login() retourne maintenant un token String (TP2)
        String token = authService.login(email, password);
        session.setAttribute("userEmail", email);
        session.setAttribute("token", token);

        return ResponseEntity.ok(Map.of(
                "message", "Connexion réussie",
                "email", email,
                "token", token
        ));
    }

    /**
     * Endpoint de déconnexion.
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpSession session) {
        session.invalidate();
        return ResponseEntity.ok(Map.of("message", "Déconnexion réussie"));
    }

    /**
     * Endpoint pour évaluer la force d'un mot de passe.
     * GET /api/auth/password-strength?password=xxx
     * @return WEAK, MEDIUM ou STRONG
     */
    @GetMapping("/password-strength")
    public ResponseEntity<Map<String, Object>> passwordStrength(
            @RequestParam String password) {

        String strength = authService.evaluatePasswordStrength(password);
        return ResponseEntity.ok(Map.of("strength", strength));
    }
}