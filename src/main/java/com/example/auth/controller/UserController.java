package com.example.auth.controller;

import com.example.auth.exception.AuthenticationFailedException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpSession;
import java.util.Map;

/**
 * Controller REST pour les routes protégées.
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@RestController
@RequestMapping("/api")
public class UserController {

    /**
     * Route protégée accessible uniquement si authentifié.
     * GET /api/me
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(HttpSession session) {
        String email = (String) session.getAttribute("userEmail");
        if (email == null) {
            throw new AuthenticationFailedException("Vous devez être connecté");
        }
        return ResponseEntity.ok(Map.of(
                "message", "Accès autorisé",
                "email", email
        ));
    }
}