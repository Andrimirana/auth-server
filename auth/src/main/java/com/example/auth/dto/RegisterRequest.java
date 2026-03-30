package com.example.auth.dto;

/**
 * DTO (Data Transfer Object) de la requête d'inscription.
 *
 * <p>La double saisie du mot de passe ({@code password} + {@code passwordConfirm})
 * est exigée depuis TP2 afin d'éviter les erreurs de saisie côté client.
 * La correspondance est vérifiée côté serveur dans
 * {@link com.example.auth.service.AuthService#register(String, String, String)}.</p>
 *
 * @see com.example.auth.service.AuthService
 * @see com.example.auth.controller.AuthController
 * @version 3.0
 */
public class RegisterRequest {

    /** Adresse email de l'utilisateur à inscrire. Doit être unique en base. */
    private String email;

    /**
     * Mot de passe en clair saisi par l'utilisateur.
     * Soumis à la politique TP2 : 12 caractères min, majuscule, minuscule, chiffre, spécial.
     * <p><b>AVERTISSEMENT :</b> Ne jamais logger ce champ.</p>
     */
    private String password;

    /**
     * Confirmation du mot de passe — doit être identique à {@code password}.
     * Vérification effectuée côté serveur.
     */
    private String passwordConfirm;

    /**
     * Constructeur par défaut requis pour la désérialisation JSON.
     */
    public RegisterRequest() {}

    /**
     * Retourne l'adresse email.
     *
     * @return email de l'utilisateur
     */
    public String getEmail() { return email; }

    /**
     * Définit l'adresse email.
     *
     * @param email adresse email
     */
    public void setEmail(String email) { this.email = email; }

    /**
     * Retourne le mot de passe saisi.
     *
     * @return mot de passe en clair
     */
    public String getPassword() { return password; }

    /**
     * Définit le mot de passe.
     *
     * @param password mot de passe en clair
     */
    public void setPassword(String password) { this.password = password; }

    /**
     * Retourne la confirmation du mot de passe.
     *
     * @return confirmation du mot de passe
     */
    public String getPasswordConfirm() { return passwordConfirm; }

    /**
     * Définit la confirmation du mot de passe.
     *
     * @param passwordConfirm confirmation du mot de passe
     */
    public void setPasswordConfirm(String passwordConfirm) { this.passwordConfirm = passwordConfirm; }
}