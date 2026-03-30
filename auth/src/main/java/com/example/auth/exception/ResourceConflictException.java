package com.example.auth.exception;

/**
 * Exception levée lorsqu'une ressource entre en conflit avec une existante.
 *
 * <p>Cas d'utilisation principal : tentative d'inscription avec un email
 * déjà présent en base de données.</p>
 *
 * <p>Retourne un HTTP 409 Conflict via {@link GlobalExceptionHandler}.</p>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.</p>
 *
 * @see GlobalExceptionHandler
 * @see com.example.auth.service.AuthService#register(String, String, String)
 * @version 3.0
 */
public class ResourceConflictException extends RuntimeException {

    /**
     * Crée une exception de conflit avec le message d'erreur fourni.
     *
     * @param message description du conflit (ex. "Email déjà utilisé")
     */
    public ResourceConflictException(String message) {
        super(message);
    }
}