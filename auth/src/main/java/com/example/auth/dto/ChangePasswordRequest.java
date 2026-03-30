package com.example.auth.dto;

/**
 * DTO de la requête de changement de mot de passe (TP5).
 *
 * <p>Reçu dans le corps JSON du {@code PUT /api/auth/change-password}.
 * Le Bearer token d'authentification est transmis dans le header
 * {@code Authorization}, pas dans ce DTO.</p>
 *
 * <h2>Règles d'application</h2>
 * <ul>
 *   <li>L'utilisateur doit être authentifié (token valide).</li>
 *   <li>{@code oldPassword} doit correspondre au mot de passe actuel stocké chiffré.</li>
 *   <li>{@code newPassword} et {@code confirmPassword} doivent être identiques.</li>
 *   <li>{@code newPassword} doit respecter la politique : 12 caractères min,
 *       majuscule, minuscule, chiffre, caractère spécial.</li>
 * </ul>
 *
 * @version 5.0
 */
public class ChangePasswordRequest {

    /** Ancien mot de passe en clair, pour vérification avant modification. */
    private String oldPassword;

    /** Nouveau mot de passe en clair, soumis à la politique de sécurité. */
    private String newPassword;

    /** Confirmation du nouveau mot de passe — doit être identique à {@link #newPassword}. */
    private String confirmPassword;

    /** Constructeur par défaut requis par Jackson. */
    public ChangePasswordRequest() {}

    /**
     * Retourne l'ancien mot de passe.
     *
     * @return ancien mot de passe en clair
     */
    public String getOldPassword() { return oldPassword; }

    /**
     * Définit l'ancien mot de passe.
     *
     * @param oldPassword ancien mot de passe
     */
    public void setOldPassword(String oldPassword) { this.oldPassword = oldPassword; }

    /**
     * Retourne le nouveau mot de passe.
     *
     * @return nouveau mot de passe en clair
     */
    public String getNewPassword() { return newPassword; }

    /**
     * Définit le nouveau mot de passe.
     *
     * @param newPassword nouveau mot de passe
     */
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }

    /**
     * Retourne la confirmation du nouveau mot de passe.
     *
     * @return confirmation du nouveau mot de passe
     */
    public String getConfirmPassword() { return confirmPassword; }

    /**
     * Définit la confirmation du nouveau mot de passe.
     *
     * @param confirmPassword confirmation
     */
    public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }
}

