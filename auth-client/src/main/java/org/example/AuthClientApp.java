package org.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Client Swing TP3 — Authentification via protocole HMAC-SHA256.
 * Le mot de passe ne circule JAMAIS sur le réseau lors du login.
 * Le client calcule une signature HMAC et envoie : email, nonce, timestamp, hmac.
 */
public class AuthClientApp extends JFrame {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final String BASE_URL = "http://localhost:8080";

    /** Token SSO reçu après login réussi — utilisé pour /api/me */
    private String accessToken = null;

    // Couleurs
    private final Color BG_COLOR      = new Color(18, 18, 28);
    private final Color CARD_COLOR    = new Color(28, 28, 42);
    private final Color ACCENT_COLOR  = new Color(99, 102, 241);
    private final Color ACCENT_HOVER  = new Color(79, 82, 221);
    private final Color TEXT_COLOR    = new Color(240, 240, 255);
    private final Color SUBTLE_COLOR  = new Color(140, 140, 170);
    private final Color INPUT_BG      = new Color(38, 38, 58);
    private final Color SUCCESS_COLOR = new Color(52, 211, 153);
    private final Color ERROR_COLOR   = new Color(248, 113, 113);
    private final Color WARNING_COLOR = new Color(251, 191, 36);

    // Champs login
    private JTextField     loginEmailField;
    private JPasswordField loginPasswordField;
    private JLabel         tokenLabel;

    // Champs inscription
    private JTextField     regEmailField;
    private JPasswordField regPasswordField;
    private JPasswordField regPasswordConfirmField;
    private JLabel         strengthLabel;

    // Status
    private JLabel statusLabel;

    public AuthClientApp() {
        setTitle("Auth Client — TP3 HMAC");
        setSize(460, 680);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(false);
        initUI();
    }

    private void initUI() {
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG_COLOR);
        root.add(buildHeader(), BorderLayout.NORTH);
        root.add(buildTabbedPane(), BorderLayout.CENTER);

        statusLabel = new JLabel("Prêt", SwingConstants.CENTER);
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        statusLabel.setForeground(SUBTLE_COLOR);
        statusLabel.setBorder(new EmptyBorder(10, 20, 15, 20));
        statusLabel.setOpaque(true);
        statusLabel.setBackground(BG_COLOR);
        root.add(statusLabel, BorderLayout.SOUTH);

        setContentPane(root);
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(BG_COLOR);
        header.setBorder(new EmptyBorder(30, 30, 10, 30));

        JLabel title = new JLabel("Auth Server");
        title.setFont(new Font("Segoe UI", Font.BOLD, 24));
        title.setForeground(TEXT_COLOR);
        title.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subtitle = new JLabel("TP3 — Protocole HMAC-SHA256");
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        subtitle.setForeground(SUBTLE_COLOR);
        subtitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        header.add(title);
        header.add(Box.createVerticalStrut(4));
        header.add(subtitle);
        header.add(Box.createVerticalStrut(20));
        return header;
    }

    private JTabbedPane buildTabbedPane() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBackground(BG_COLOR);
        tabs.setForeground(TEXT_COLOR);
        tabs.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        tabs.addTab("  Connexion  ", buildLoginPanel());
        tabs.addTab("  Inscription  ", buildRegisterPanel());
        return tabs;
    }

    // ========== PANNEAU CONNEXION ==========
    private JPanel buildLoginPanel() {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(BG_COLOR);

        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(CARD_COLOR);
        card.setBorder(new CompoundBorder(
                new EmptyBorder(15, 25, 15, 25),
                new EmptyBorder(20, 20, 20, 20)));

        loginEmailField    = styledTextField("email@exemple.com");
        loginPasswordField = styledPasswordField("mot de passe");

        tokenLabel = new JLabel(": ");
        tokenLabel.setFont(new Font("Monospaced", Font.PLAIN, 10));
        tokenLabel.setForeground(SUBTLE_COLOR);
        tokenLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        card.add(fieldLabel("Adresse email"));
        card.add(Box.createVerticalStrut(6));
        card.add(loginEmailField);
        card.add(Box.createVerticalStrut(16));
        card.add(fieldLabel("Mot de passe"));
        card.add(Box.createVerticalStrut(6));
        card.add(loginPasswordField);
        card.add(Box.createVerticalStrut(24));

        JButton loginBtn = styledButton("Se connecter");
        loginBtn.addActionListener(e -> doLogin());
        card.add(loginBtn);
        card.add(Box.createVerticalStrut(8));
        card.add(tokenLabel);
        card.add(Box.createVerticalStrut(12));



        wrapper.add(card, BorderLayout.CENTER);
        return wrapper;
    }

    // ========== PANNEAU INSCRIPTION ==========
    private JPanel buildRegisterPanel() {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(BG_COLOR);

        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(CARD_COLOR);
        card.setBorder(new CompoundBorder(
                new EmptyBorder(15, 25, 15, 25),
                new EmptyBorder(20, 20, 20, 20)));

        regEmailField           = styledTextField("email@exemple.com");
        regPasswordField        = styledPasswordField("min. 12 caractères");
        regPasswordConfirmField = styledPasswordField("confirmer le mot de passe");

        strengthLabel = new JLabel("Entrez un mot de passe");
        strengthLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        strengthLabel.setForeground(SUBTLE_COLOR);
        strengthLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        regPasswordField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { updateStrength(); }
            public void removeUpdate(DocumentEvent e)  { updateStrength(); }
            public void changedUpdate(DocumentEvent e) { updateStrength(); }
        });

        card.add(fieldLabel("Adresse email"));
        card.add(Box.createVerticalStrut(6));
        card.add(regEmailField);
        card.add(Box.createVerticalStrut(16));
        card.add(fieldLabel("Mot de passe"));
        card.add(Box.createVerticalStrut(6));
        card.add(regPasswordField);
        card.add(Box.createVerticalStrut(6));
        card.add(strengthLabel);
        card.add(Box.createVerticalStrut(12));
        card.add(fieldLabel("Confirmer le mot de passe"));
        card.add(Box.createVerticalStrut(6));
        card.add(regPasswordConfirmField);
        card.add(Box.createVerticalStrut(20));

        JButton registerBtn = styledButton("Créer un compte");
        registerBtn.addActionListener(e -> doRegister());
        card.add(registerBtn);

        wrapper.add(card, BorderLayout.CENTER);
        return wrapper;
    }

    // ========== INDICATEUR DE FORCE ==========
    private void updateStrength() {
        String pwd = new String(regPasswordField.getPassword());
        String strength = evaluateStrength(pwd);
        switch (strength) {
            case "WEAK"   -> { strengthLabel.setText("● Faible — non conforme");  strengthLabel.setForeground(ERROR_COLOR);   }
            case "MEDIUM" -> { strengthLabel.setText("● Moyen — conforme");       strengthLabel.setForeground(WARNING_COLOR); }
            case "STRONG" -> { strengthLabel.setText("● Fort — excellent");       strengthLabel.setForeground(SUCCESS_COLOR); }
        }
    }

    private String evaluateStrength(String password) {
        if (password == null || password.length() < 12) return "WEAK";
        int score = 0;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*[0-9].*")) score++;
        if (password.matches(".*[^a-zA-Z0-9].*")) score++;
        if (password.length() >= 16) score++;
        if (score <= 2) return "WEAK";
        if (score <= 3) return "MEDIUM";
        return "STRONG";
    }

    // ========== ACTIONS RÉSEAU ==========

    /**
     * Login TP3 — calcule HMAC-SHA256 et envoie la preuve au serveur.
     * Le mot de passe ne circule JAMAIS sur le réseau.
     */
    private void doLogin() {
        String email    = loginEmailField.getText().trim();
        String password = new String(loginPasswordField.getPassword());

        if (email.isBlank() || !email.contains("@")) {
            setStatus("Email invalide", ERROR_COLOR);
            return;
        }

        new Thread(() -> {
            try {
                // 1. Générer nonce aléatoire et timestamp
                String nonce     = UUID.randomUUID().toString();
                long   timestamp = Instant.now().getEpochSecond();

                // 2. Construire le message à signer
                String message = email + ":" + nonce + ":" + timestamp;

                // 3. Calculer HMAC-SHA256 avec le mot de passe comme clé
                String hmac = computeHmac(password, message);

                // 4. JSON sans mot de passe !
                String json = String.format(
                        "{\"email\":\"%s\",\"nonce\":\"%s\",\"timestamp\":%d,\"hmac\":\"%s\"}",
                        email, nonce, timestamp, hmac
                );

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + "/api/auth/login"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json))
                        .build();

                HttpResponse<String> response = httpClient.send(
                        request, HttpResponse.BodyHandlers.ofString()
                );

                if (response.statusCode() == 200) {
                    accessToken = extractJsonValue(response.body(), "accessToken");
                    SwingUtilities.invokeLater(() -> {
                        tokenLabel.setText(": " + accessToken);
                        tokenLabel.setForeground(SUCCESS_COLOR);
                    });
                    setStatus("Connexion réussie !", SUCCESS_COLOR);
                } else if (response.statusCode() == 429) {
                    setStatus("Compte bloqué — trop de tentatives", ERROR_COLOR);
                } else {
                    setStatus("Identifiants incorrects", ERROR_COLOR);
                }

            } catch (Exception ex) {
                setStatus("Erreur réseau : " + ex.getMessage(), ERROR_COLOR);
            }
        }).start();
    }

    /**
     * Inscription — envoie email + password en JSON.
     */
    private void doRegister() {
        String email    = regEmailField.getText().trim();
        String password = new String(regPasswordField.getPassword());
        String confirm  = new String(regPasswordConfirmField.getPassword());

        if (email.isBlank() || !email.contains("@")) {
            setStatus("Email invalide", ERROR_COLOR);
            return;
        }
        if (!password.equals(confirm)) {
            setStatus("Les mots de passe ne correspondent pas", ERROR_COLOR);
            return;
        }
        if (evaluateStrength(password).equals("WEAK")) {
            setStatus("Mot de passe non conforme", ERROR_COLOR);
            return;
        }

        new Thread(() -> {
            try {
                String json = String.format(
                        "{\"email\":\"%s\",\"password\":\"%s\",\"passwordConfirm\":\"%s\"}",
                        email, password, confirm
                );

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + "/api/auth/register"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json))
                        .build();

                HttpResponse<String> response = httpClient.send(
                        request, HttpResponse.BodyHandlers.ofString()
                );

                if (response.statusCode() == 200) {
                    setStatus("Compte créé avec succès !", SUCCESS_COLOR);
                } else if (response.statusCode() == 409) {
                    setStatus("Email déjà utilisé", ERROR_COLOR);
                } else if (response.statusCode() == 400) {
                    String msg = extractJsonValue(response.body(), "message");
                    setStatus(msg != null ? msg : "Données invalides", ERROR_COLOR);
                } else {
                    String msg = extractJsonValue(response.body(), "message");
                    setStatus(msg != null ? msg : "Erreur serveur (" + response.statusCode() + ")", ERROR_COLOR);
                }
            } catch (IOException | InterruptedException ex) {
                setStatus("Serveur inaccessible", ERROR_COLOR);
            }
        }).start();
    }

    /**
     * Accès à /api/me avec le token Bearer SSO.
     */
    private void doMe() {
        if (accessToken == null) {
            setStatus("Connectez-vous d'abord !", ERROR_COLOR);
            return;
        }

        new Thread(() -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + "/api/me"))
                        .header("Authorization", "Bearer " + accessToken)
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(
                        request, HttpResponse.BodyHandlers.ofString()
                );

                if (response.statusCode() == 200) {
                    setStatus("Accès autorisé : " + response.body(), SUCCESS_COLOR);
                } else {
                    setStatus("Accès refusé — token invalide ou expiré", ERROR_COLOR);
                }
            } catch (IOException | InterruptedException ex) {
                setStatus("Serveur inaccessible", ERROR_COLOR);
            }
        }).start();
    }

    // ========== UTILITAIRES CRYPTO ==========

    /**
     * Calcule HMAC-SHA256 encodé en Base64.
     * @param key  clé = mot de passe utilisateur
     * @param data message = email:nonce:timestamp
     */
    private String computeHmac(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"
        );
        mac.init(secretKey);
        byte[] result = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(result);
    }

    /** Extraction simple d'une valeur depuis un JSON. */
    private String extractJsonValue(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }

    // ========== HELPERS UI ==========
    private JTextField styledTextField(String placeholder) {
        JTextField field = new JTextField();
        field.setBackground(INPUT_BG);
        field.setForeground(TEXT_COLOR);
        field.setCaretColor(TEXT_COLOR);
        field.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        field.setBorder(new CompoundBorder(
                new LineBorder(new Color(60, 60, 90), 1, true),
                new EmptyBorder(10, 14, 10, 14)));
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        return field;
    }

    private JPasswordField styledPasswordField(String placeholder) {
        JPasswordField field = new JPasswordField();
        field.setBackground(INPUT_BG);
        field.setForeground(TEXT_COLOR);
        field.setCaretColor(TEXT_COLOR);
        field.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        field.setBorder(new CompoundBorder(
                new LineBorder(new Color(60, 60, 90), 1, true),
                new EmptyBorder(10, 14, 10, 14)));
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        return field;
    }

    private JLabel fieldLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.BOLD, 12));
        label.setForeground(SUBTLE_COLOR);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private JButton styledButton(String text) {
        JButton btn = new JButton(text);
        btn.setBackground(ACCENT_COLOR);
        btn.setForeground(Color.WHITE);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        btn.setBorder(new EmptyBorder(12, 20, 12, 20));
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 46));
        btn.setAlignmentX(Component.LEFT_ALIGNMENT);
        btn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) { btn.setBackground(ACCENT_HOVER); }
            public void mouseExited(MouseEvent e)  { btn.setBackground(ACCENT_COLOR); }
        });
        return btn;
    }

    private JButton styledOutlineButton(String text) {
        JButton btn = new JButton(text);
        btn.setBackground(INPUT_BG);
        btn.setForeground(SUBTLE_COLOR);
        btn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        btn.setBorder(new CompoundBorder(
                new LineBorder(new Color(60, 60, 90), 1, true),
                new EmptyBorder(10, 20, 10, 20)));
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        btn.setAlignmentX(Component.LEFT_ALIGNMENT);
        return btn;
    }

    private void setStatus(String message, Color color) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(message);
            statusLabel.setForeground(color);
        });
    }
}