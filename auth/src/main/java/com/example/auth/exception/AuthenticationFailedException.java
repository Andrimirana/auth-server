package com.example.auth.exception;

/**
 * Exception levée lorsque l'authentification échoue.
 *
 * <p>Cette exception est utilisée pour tous les cas d'échec du protocole
 * HMAC (TP3) : email inconnu, HMAC invalide, timestamp hors fenêtre,
 * nonce déjà utilisé, token invalide ou expiré, compte verrouillé.</p>
 *
 * <p>Pour ne pas donner d'information à un attaquant, le message retourné
 * au client est toujours générique : {@code "Identifiants incorrects"}
 * (sauf en cas de verrouillage de compte).</p>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.</p>
 *
 * @see com.example.auth.exception.GlobalExceptionHandler
 * @see com.example.auth.service.AuthService
 * @version 3.0
 */
public class AuthenticationFailedException extends RuntimeException {

    /**
     * Crée une exception d'authentification avec le message fourni.
     *
     * @param message description de l'échec (message générique recommandé)
     */
    public AuthenticationFailedException(String message) {
        super(message);
    }
}