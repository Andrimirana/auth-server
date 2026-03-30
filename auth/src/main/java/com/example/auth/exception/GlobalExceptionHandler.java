package com.example.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * Gestionnaire global des exceptions REST — retourne des réponses JSON cohérentes.
 *
 * <p>Centralise la gestion d'erreurs de l'application via l'annotation
 * {@link RestControllerAdvice}. Chaque exception métier est interceptée et
 * transformée en réponse JSON avec le format standardisé :</p>
 * <pre>
 * {
 *   "timestamp" : "2026-03-24T10:00:00",
 *   "status"    : 400,
 *   "error"     : "Bad Request",
 *   "message"   : "...",
 *   "path"      : "/api/auth/register"
 * }
 * </pre>
 *
 * <h2>Codes HTTP gérés</h2>
 * <ul>
 *   <li><b>400</b> Bad Request — données invalides ({@link InvalidInputException})</li>
 *   <li><b>401</b> Unauthorized — authentification échouée ({@link AuthenticationFailedException})</li>
 *   <li><b>409</b> Conflict — email déjà existant ({@link ResourceConflictException})</li>
 *   <li><b>429</b> Too Many Requests — compte verrouillé anti brute-force</li>
 * </ul>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement fragile
 * et ne doit jamais être utilisée en production.</p>
 *
 * @version 3.0
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Gère les erreurs de validation des données entrantes.
     * Retourne HTTP 400 Bad Request.
     *
     * @param ex      exception levée par la validation
     * @param request requête HTTP ayant provoqué l'erreur
     * @return réponse JSON avec status 400 et le message d'erreur
     */
    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidInput(
            InvalidInputException ex, HttpServletRequest request) {
        return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request.getRequestURI());
    }

    /**
     * Gère les échecs d'authentification.
     * Retourne HTTP 429 si le compte est verrouillé, HTTP 401 sinon.
     *
     * @param ex      exception levée lors de l'authentification
     * @param request requête HTTP ayant provoqué l'erreur
     * @return réponse JSON avec status 401 ou 429 selon le contexte
     */
    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<Map<String, Object>> handleAuthFailed(
            AuthenticationFailedException ex, HttpServletRequest request) {
        // HTTP 429 si compte bloqué, 401 sinon
        boolean isLocked = ex.getMessage().contains("bloqué");
        HttpStatus status = isLocked
                ? HttpStatus.TOO_MANY_REQUESTS
                : HttpStatus.UNAUTHORIZED;
        return buildResponse(status, ex.getMessage(), request.getRequestURI());
    }

    /**
     * Gère les conflits de ressources (ex. email déjà utilisé).
     * Retourne HTTP 409 Conflict.
     *
     * @param ex      exception levée lors du conflit
     * @param request requête HTTP ayant provoqué l'erreur
     * @return réponse JSON avec status 409 et le message d'erreur
     */
    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(
            ResourceConflictException ex, HttpServletRequest request) {
        return buildResponse(HttpStatus.CONFLICT, ex.getMessage(), request.getRequestURI());
    }

    /**
     * Construit le corps JSON standardisé de la réponse d'erreur.
     *
     * @param status  code HTTP de la réponse
     * @param message message d'erreur descriptif
     * @param path    chemin de la requête ayant échoué
     * @return {@link ResponseEntity} avec le corps JSON et le statut HTTP
     */
    private ResponseEntity<Map<String, Object>> buildResponse(
            HttpStatus status, String message, String path) {
        Map<String, Object> body = Map.of(
                "timestamp", LocalDateTime.now().toString(),
                "status", status.value(),
                "error", status.getReasonPhrase(),
                "message", message,
                "path", path
        );
        return ResponseEntity.status(status).body(body);
    }
}