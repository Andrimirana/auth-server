package com.example.auth.exception;

/**
 * Exception levée lorsque les données envoyées par le client sont invalides.
 *
 * <p>Cas d'utilisation :</p>
 * <ul>
 *   <li>Email vide ou mal formaté.</li>
 *   <li>Mot de passe ne respectant pas la politique (TP2+).</li>
 *   <li>Confirmation de mot de passe non correspondante.</li>
 *   <li>Champs obligatoires manquants dans la requête.</li>
 * </ul>
 *
 * <p>Retourne un HTTP 400 Bad Request via {@link GlobalExceptionHandler}.</p>
 *
 * <p><b>AVERTISSEMENT :</b> Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.</p>
 *
 * @see GlobalExceptionHandler
 * @see com.example.auth.service.AuthService
 * @version 3.0
 */
public class InvalidInputException extends RuntimeException {

    /**
     * Crée une exception de validation avec le message d'erreur fourni.
     *
     * @param message description de l'erreur de validation
     */
    public InvalidInputException(String message) {
        super(message);
    }
}