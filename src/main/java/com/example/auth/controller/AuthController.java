package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpSession;
import java.util.Map;

/**
 * Controller REST gérant les endpoints d'authentification.
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
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
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestParam String email,
            @RequestParam String password,
            HttpSession session) {

        User user = authService.login(email, password);
        session.setAttribute("userEmail", user.getEmail());
        return ResponseEntity.ok(Map.of(
                "message", "Connexion réussie",
                "email", user.getEmail()
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
}