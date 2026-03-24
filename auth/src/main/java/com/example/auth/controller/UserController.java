package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Contrôleur REST gérant les routes protégées par token SSO Bearer.
 *
 * <h2>Endpoints exposés</h2>
 * <ul>
 *   <li>{@code GET /api/me} — retourne le profil de l'utilisateur authentifié.</li>
 * </ul>
 *
 * <p>L'authentification est vérifiée via le header HTTP :</p>
 * <pre>
 *   Authorization: Bearer &lt;accessToken&gt;
 * </pre>
 *
 * <p>Le token est obtenu après un login réussi ({@code POST /api/auth/login}).
 * Sa validité est de {@link com.example.auth.entity.AccessToken#EXPIRY_MINUTES} minutes.</p>
 *
 * @see AuthService#getUserByToken(String)
 * @see com.example.auth.service.TokenService
 * @version 3.0
 */
@RestController
@RequestMapping("/api")
public class UserController {

    private final AuthService authService;

    /**
     * Injecte le service d'authentification via le constructeur.
     *
     * @param authService service principal d'authentification
     */
    public UserController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Retourne le profil de l'utilisateur authentifié par token Bearer.
     *
     * <pre>
     * GET /api/me
     * Authorization: Bearer &lt;accessToken&gt;
     * </pre>
     *
     * @param authHeader valeur du header {@code Authorization}
     *                   (doit commencer par {@code "Bearer "})
     * @return HTTP 200 avec {@code {"message": "Accès autorisé", "email": "..."}}
     *         si le token est valide et non expiré ;
     *         HTTP 401 si le header est absent, mal formé, ou si le token est invalide/expiré
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationFailedException(
                    "Token manquant. Utilisez : Authorization: Bearer <token>"
            );
        }

        String tokenValue = authHeader.substring(7);
        User user = authService.getUserByToken(tokenValue);

        return ResponseEntity.ok(Map.of(
                "message", "Accès autorisé",
                "email", user.getEmail()
        ));
    }
}