package org.example;

import javax.swing.SwingUtilities;

/**
 * Point d'entrée principal de l'application cliente d'authentification.
 */
public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new AuthClientApp().setVisible(true));
    }
}