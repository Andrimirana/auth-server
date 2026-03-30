package org.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
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
 *
 * <p>Le mot de passe ne circule <b>jamais</b> sur le réseau lors du login.
 * Le client calcule une signature HMAC et envoie : email, nonce, timestamp, hmac.</p>
 *
 * @version 4.0
 */
public class AuthClientApp extends JFrame {

    // ─── Infrastructure ──────────────────────────────────────────────────────
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private static final String BASE_URL = "http://localhost:8080";

    // ─── Palette (thème sombre) ──────────────────────────────────────────────
    private static final Color BG         = new Color(10,  10,  18);
    private static final Color SURFACE    = new Color(17,  17,  27);
    private static final Color SURFACE2   = new Color(24,  24,  38);
    private static final Color BORDER_CLR = new Color(38,  38,  58);
    private static final Color ACCENT     = new Color(99,  179, 237);
    private static final Color ACCENT_H   = new Color(130, 200, 255);
    private static final Color TEXT       = new Color(235, 235, 245);
    private static final Color TEXT_DIM   = new Color(115, 115, 140);
    private static final Color SUCCESS    = new Color(52,  211, 153);
    private static final Color ERROR      = new Color(252, 129, 129);
    private static final Color WARNING    = new Color(251, 191,  36);
    private static final Color INPUT_BG   = new Color(13,  13,  21);

    // ─── Typographie ────────────────────────────────────────────────────────
    private static final Font F_SUBTITLE = new Font("Segoe UI", Font.PLAIN, 11);
    private static final Font F_LABEL    = new Font("Segoe UI", Font.BOLD,  10);
    private static final Font F_INPUT    = new Font("Segoe UI", Font.PLAIN, 13);
    private static final Font F_BTN      = new Font("Segoe UI", Font.BOLD,  13);
    private static final Font F_STATUS   = new Font("Segoe UI", Font.PLAIN, 12);
    private static final Font F_BADGE    = new Font("Segoe UI", Font.BOLD,  10);

    // ─── Champs de formulaire ────────────────────────────────────────────────
    private JTextField     loginEmailField;
    private JPasswordField loginPasswordField;
    private JTextField     regEmailField;
    private JPasswordField regPasswordField;
    private JPasswordField regPasswordConfirmField;

    // ─── Composants UI partagés ─────────────────────────────────────────────
    private JProgressBar strengthBar;
    private JLabel       strengthLabel;
    private JLabel       matchLabel;
    private JLabel       statusLabel;
    private JButton      loginBtn;
    private JButton      registerBtn;

    // ─── Navigation ─────────────────────────────────────────────────────────
    private CardLayout mainLayout;
    private JPanel     mainPanel;

    // ─── Confirmation post-connexion ─────────────────────────────────────────
    private JLabel confirmEmailLabel;

    // ══════════════════════════════════════════════════════════════════════
    //  CONSTRUCTEUR
    // ══════════════════════════════════════════════════════════════════════

    public AuthClientApp() {
        setTitle("TP Authentification");
        setSize(480, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(false);
        setBackground(BG);
        buildUI();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  CONSTRUCTION DE L'UI
    // ══════════════════════════════════════════════════════════════════════

    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG);

        mainLayout = new CardLayout();
        mainPanel  = new JPanel(mainLayout);
        mainPanel.setBackground(BG);
        mainPanel.add(buildAuthView(),    "auth");
        mainPanel.add(buildConfirmView(), "confirm");

        root.add(mainPanel,        BorderLayout.CENTER);
        root.add(buildStatusBar(), BorderLayout.SOUTH);
        setContentPane(root);
    }

    // ─── Vue Authentification (onglets Login / Inscription) ──────────────────

    private JComponent buildAuthView() {
        UIManager.put("TabbedPane.selected",           SURFACE2);
        UIManager.put("TabbedPane.background",         BG);
        UIManager.put("TabbedPane.tabAreaBackground",  BG);
        UIManager.put("TabbedPane.foreground",         TEXT_DIM);
        UIManager.put("TabbedPane.selectedForeground", ACCENT);
        UIManager.put("TabbedPane.focus",              new Color(0, 0, 0, 0));

        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(F_INPUT);
        tabs.setFocusable(false);
        SwingUtilities.updateComponentTreeUI(tabs);
        tabs.addTab("  Connexion  ",   buildLoginPanel());
        tabs.addTab("  Inscription  ", buildRegisterPanel());
        return tabs;
    }

    // ─── Barre de statut ────────────────────────────────────────────────────

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(SURFACE);
        bar.setBorder(new CompoundBorder(
                new MatteBorder(1, 0, 0, 0, BORDER_CLR),
                new EmptyBorder(10, 22, 11, 22)));
        statusLabel = new JLabel("Prêt");
        statusLabel.setFont(F_STATUS);
        statusLabel.setForeground(TEXT_DIM);

        JLabel badge = new JLabel("TP3");
        badge.setFont(F_BADGE);
        badge.setForeground(new Color(55, 55, 80));

        bar.add(statusLabel, BorderLayout.WEST);
        bar.add(badge,       BorderLayout.EAST);
        return bar;
    }

    // ─── Panneau Connexion ───────────────────────────────────────────────────

    private JPanel buildLoginPanel() {
        JPanel outer = new JPanel(new GridBagLayout());
        outer.setBackground(BG);
        outer.setBorder(new EmptyBorder(20, 28, 16, 28));

        JPanel card = createCard();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(new EmptyBorder(26, 26, 26, 26));

        loginEmailField    = createTextField();
        loginPasswordField = createPasswordField();

        loginBtn = createButton("Se connecter", ACCENT, ACCENT_H);
        loginBtn.addActionListener(e -> doLogin());

        card.add(inputGroup("ADRESSE EMAIL", loginEmailField, null));
        card.add(Box.createVerticalStrut(16));
        card.add(inputGroup("MOT DE PASSE",  loginPasswordField, loginPasswordField));
        card.add(Box.createVerticalStrut(24));
        card.add(loginBtn);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill    = GridBagConstraints.HORIZONTAL;
        gbc.anchor  = GridBagConstraints.CENTER;
        gbc.weightx = 1;
        outer.add(card, gbc);
        return outer;
    }

    // ─── Panneau Inscription ─────────────────────────────────────────────────

    private JPanel buildRegisterPanel() {
        JPanel outer = new JPanel(new GridBagLayout());
        outer.setBackground(BG);
        outer.setBorder(new EmptyBorder(16, 28, 12, 28));

        JPanel card = createCard();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(new EmptyBorder(18, 26, 18, 26));

        regEmailField           = createTextField();
        regPasswordField        = createPasswordField();
        regPasswordConfirmField = createPasswordField();

        strengthBar = new JProgressBar(0, 100);
        strengthBar.setValue(0);
        strengthBar.setStringPainted(false);
        strengthBar.setBackground(BORDER_CLR);
        strengthBar.setForeground(ERROR);
        strengthBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 3));
        strengthBar.setPreferredSize(new Dimension(0, 3));
        strengthBar.setBorderPainted(false);
        strengthBar.setAlignmentX(Component.LEFT_ALIGNMENT);

        strengthLabel = new JLabel("Entrez un mot de passe");
        strengthLabel.setFont(F_SUBTITLE);
        strengthLabel.setForeground(TEXT_DIM);
        strengthLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Indicateur de correspondance des mots de passe
        matchLabel = new JLabel(" ");
        matchLabel.setFont(F_SUBTITLE);
        matchLabel.setForeground(TEXT_DIM);
        matchLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        regPasswordField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { updateStrength(); updateMatch(); }
            public void removeUpdate(DocumentEvent e)  { updateStrength(); updateMatch(); }
            public void changedUpdate(DocumentEvent e) { updateStrength(); updateMatch(); }
        });

        regPasswordConfirmField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { updateMatch(); }
            public void removeUpdate(DocumentEvent e)  { updateMatch(); }
            public void changedUpdate(DocumentEvent e) { updateMatch(); }
        });

        registerBtn = createButton("Creer un compte", ACCENT, ACCENT_H);
        registerBtn.addActionListener(e -> doRegister());

        JPanel strengthInfo = new JPanel();
        strengthInfo.setLayout(new BoxLayout(strengthInfo, BoxLayout.Y_AXIS));
        strengthInfo.setOpaque(false);
        strengthInfo.setAlignmentX(Component.LEFT_ALIGNMENT);
        strengthInfo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        strengthInfo.add(Box.createVerticalStrut(6));
        strengthInfo.add(strengthBar);
        strengthInfo.add(Box.createVerticalStrut(5));
        strengthInfo.add(strengthLabel);

        JPanel matchInfo = new JPanel();
        matchInfo.setLayout(new BoxLayout(matchInfo, BoxLayout.Y_AXIS));
        matchInfo.setOpaque(false);
        matchInfo.setAlignmentX(Component.LEFT_ALIGNMENT);
        matchInfo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
        matchInfo.add(Box.createVerticalStrut(5));
        matchInfo.add(matchLabel);

        card.add(inputGroup("ADRESSE EMAIL",             regEmailField,           null));
        card.add(Box.createVerticalStrut(10));
        card.add(inputGroup("MOT DE PASSE",              regPasswordField,        regPasswordField));
        card.add(strengthInfo);
        card.add(Box.createVerticalStrut(8));
        card.add(inputGroup("CONFIRMER LE MOT DE PASSE", regPasswordConfirmField, regPasswordConfirmField));
        card.add(matchInfo);
        card.add(Box.createVerticalStrut(12));
        card.add(registerBtn);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill    = GridBagConstraints.HORIZONTAL;
        gbc.anchor  = GridBagConstraints.CENTER;
        gbc.weightx = 1;
        outer.add(card, gbc);
        return outer;
    }

    // ─── Vue confirmation post-connexion ─────────────────────────────────────

    private JPanel buildConfirmView() {
        JPanel outer = new JPanel(new GridBagLayout());
        outer.setBackground(BG);
        outer.setBorder(new EmptyBorder(20, 28, 16, 28));

        JPanel card = createCard();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(new EmptyBorder(36, 30, 36, 30));

        // Barre verte de succes
        JPanel line = new JPanel();
        line.setBackground(SUCCESS);
        line.setMaximumSize(new Dimension(40, 3));
        line.setPreferredSize(new Dimension(40, 3));
        line.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel titleLabel = new JLabel("Connexion reussie");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 17));
        titleLabel.setForeground(SUCCESS);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel subLabel = new JLabel("Vous etes authentifie en tant que :");
        subLabel.setFont(F_SUBTITLE);
        subLabel.setForeground(TEXT_DIM);
        subLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        confirmEmailLabel = new JLabel("—");
        confirmEmailLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        confirmEmailLabel.setForeground(TEXT);
        confirmEmailLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel sep = new JPanel() {
            @Override protected void paintComponent(Graphics g) {
                g.setColor(BORDER_CLR);
                g.fillRect(0, 0, getWidth(), 1);
            }
        };
        sep.setOpaque(false);
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep.setPreferredSize(new Dimension(0, 1));
        sep.setAlignmentX(Component.CENTER_ALIGNMENT);

        JButton logoutBtn = createButton("Se deconnecter", new Color(50, 20, 20), new Color(70, 25, 25));
        logoutBtn.setForeground(ERROR);
        logoutBtn.addActionListener(e -> doLogout());

        card.add(line);
        card.add(Box.createVerticalStrut(18));
        card.add(titleLabel);
        card.add(Box.createVerticalStrut(12));
        card.add(subLabel);
        card.add(Box.createVerticalStrut(6));
        card.add(confirmEmailLabel);
        card.add(Box.createVerticalStrut(24));
        card.add(sep);
        card.add(Box.createVerticalStrut(24));
        card.add(logoutBtn);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1; gbc.weighty = 1;
        outer.add(card, gbc);
        return outer;
    }


    //  NAVIGATION


    private void showConfirm(String email) {
        confirmEmailLabel.setText(email);
        mainLayout.show(mainPanel, "confirm");
        setStatus("Connexion reussi", SUCCESS);
    }

    private void doLogout() {
        loginPasswordField.setText("");
        mainLayout.show(mainPanel, "auth");
        setStatus("Deconnecte", TEXT_DIM);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  INDICATEUR DE FORCE ET CORRESPONDANCE
    // ══════════════════════════════════════════════════════════════════════

    private void updateStrength() {
        String pwd      = new String(regPasswordField.getPassword());
        String strength = evaluateStrength(pwd);
        SwingUtilities.invokeLater(() -> {
            switch (strength) {
                case "WEAK"   -> { strengthBar.setValue(28);  strengthBar.setForeground(ERROR);
                                   strengthLabel.setText("Faible");  strengthLabel.setForeground(ERROR); }
                case "MEDIUM" -> { strengthBar.setValue(62);  strengthBar.setForeground(WARNING);
                                   strengthLabel.setText("Moyen");   strengthLabel.setForeground(WARNING); }
                case "STRONG" -> { strengthBar.setValue(100); strengthBar.setForeground(SUCCESS);
                                   strengthLabel.setText("Fort");    strengthLabel.setForeground(SUCCESS); }
            }
        });
    }

    private void updateMatch() {
        String pwd     = new String(regPasswordField.getPassword());
        String confirm = new String(regPasswordConfirmField.getPassword());
        SwingUtilities.invokeLater(() -> {
            if (confirm.isEmpty()) {
                matchLabel.setText(" ");
                matchLabel.setForeground(TEXT_DIM);
            } else if (pwd.equals(confirm)) {
                matchLabel.setText("Les mots de passe correspondent");
                matchLabel.setForeground(SUCCESS);
            } else {
                matchLabel.setText("Les mots de passe ne correspondent pas");
                matchLabel.setForeground(ERROR);
            }
        });
    }

    private String evaluateStrength(String password) {
        if (password == null || password.length() < 12) return "WEAK";
        int score = 0;
        if (password.matches(".*[A-Z].*"))        score++;
        if (password.matches(".*[a-z].*"))        score++;
        if (password.matches(".*[0-9].*"))        score++;
        if (password.matches(".*[^a-zA-Z0-9].*")) score++;
        if (password.length() >= 16)              score++;
        if (score <= 2) return "WEAK";
        if (score <= 3) return "MEDIUM";
        return "STRONG";
    }

    // ══════════════════════════════════════════════════════════════════════
    //  ACTIONS RÉSEAU
    // ══════════════════════════════════════════════════════════════════════

    /** Protocole HMAC-SHA256 TP3 : le mot de passe ne circule jamais sur le réseau. */
    private void doLogin() {
        String email    = loginEmailField.getText().trim();
        String password = new String(loginPasswordField.getPassword());

        if (email.isBlank() || !email.contains("@")) { setStatus("Email invalide", ERROR);       return; }
        if (password.isBlank())                       { setStatus("Mot de passe requis", ERROR); return; }

        setLoading(loginBtn, true);
        setStatus("Authentification en cours...", TEXT_DIM);

        new Thread(() -> {
            try {
                String nonce     = UUID.randomUUID().toString();
                long   timestamp = Instant.now().getEpochSecond();
                String message   = email + ":" + nonce + ":" + timestamp;
                String hmac      = computeHmac(password, message);

                String json = String.format(
                        "{\"email\":\"%s\",\"nonce\":\"%s\",\"timestamp\":%d,\"hmac\":\"%s\"}",
                        email, nonce, timestamp, hmac);

                HttpResponse<String> res = httpClient.send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(BASE_URL + "/api/auth/login"))
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofString(json))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

                SwingUtilities.invokeLater(() -> {
                    setLoading(loginBtn, false);
                    if (res.statusCode() == 200) {
                        showConfirm(email);
                    } else if (res.statusCode() == 429) {
                        setStatus("Compte bloque — trop de tentatives", ERROR);
                    } else {
                        setStatus("Identifiants incorrects", ERROR);
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    setLoading(loginBtn, false);
                    setStatus("Serveur inaccessible", ERROR);
                });
            }
        }).start();
    }

    /** Inscription — envoie email + password en JSON. */
    private void doRegister() {
        String email    = regEmailField.getText().trim();
        String password = new String(regPasswordField.getPassword());
        String confirm  = new String(regPasswordConfirmField.getPassword());

        if (email.isBlank() || !email.contains("@"))  { setStatus("Email invalide", ERROR); return; }
        if (!password.equals(confirm))                 { setStatus("Les mots de passe ne correspondent pas", ERROR); return; }
        if (evaluateStrength(password).equals("WEAK")) { setStatus("Mot de passe non conforme (12 car., maj., chiffre, special)", ERROR); return; }

        setLoading(registerBtn, true);
        setStatus("Creation du compte en cours...", TEXT_DIM);

        new Thread(() -> {
            try {
                String json = String.format(
                        "{\"email\":\"%s\",\"password\":\"%s\",\"passwordConfirm\":\"%s\"}",
                        email, escapeJson(password), escapeJson(confirm));

                HttpResponse<String> res = httpClient.send(
                        HttpRequest.newBuilder()
                                .uri(URI.create(BASE_URL + "/api/auth/register"))
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofString(json))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

                SwingUtilities.invokeLater(() -> {
                    setLoading(registerBtn, false);
                    if (res.statusCode() == 200) {
                        setStatus("Compte cree avec succes", SUCCESS);
                        regEmailField.setText("");
                        regPasswordField.setText("");
                        regPasswordConfirmField.setText("");
                        strengthBar.setValue(0);
                        strengthLabel.setText("Entrez un mot de passe");
                        strengthLabel.setForeground(TEXT_DIM);
                        matchLabel.setText(" ");
                        matchLabel.setForeground(TEXT_DIM);
                    } else if (res.statusCode() == 409) {
                        setStatus("Email deja utilise", ERROR);
                    } else {
                        String msg = extractJsonValue(res.body(), "message");
                        setStatus(msg != null ? msg : "Erreur " + res.statusCode(), ERROR);
                    }
                });
            } catch (IOException | InterruptedException ex) {
                SwingUtilities.invokeLater(() -> {
                    setLoading(registerBtn, false);
                    setStatus("Serveur inaccessible", ERROR);
                });
            }
        }).start();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  UTILITAIRES CRYPTO
    // ══════════════════════════════════════════════════════════════════════

    private String computeHmac(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(
                mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private String extractJsonValue(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        return end == -1 ? null : json.substring(start, end);
    }

    /** Échappe les caractères spéciaux JSON dans une chaîne. */
    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ══════════════════════════════════════════════════════════════════════
    //  HELPERS UI
    // ══════════════════════════════════════════════════════════════════════

    /** Carte avec coins arrondis et bordure subtile. */
    private JPanel createCard() {
        JPanel card = new JPanel() {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(SURFACE);
                g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(),     getHeight(),     14, 14));
                g2.setColor(BORDER_CLR);
                g2.draw(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, 14, 14));
                g2.dispose();
            }
        };
        card.setOpaque(false);
        return card;
    }

    /**
     * Groupe label + champ (optionnel : toggle afficher/masquer si pwField != null).
     */
    private JPanel inputGroup(String label, JComponent field, JPasswordField pwField) {
        JPanel group = new JPanel();
        group.setLayout(new BoxLayout(group, BoxLayout.Y_AXIS));
        group.setOpaque(false);
        group.setAlignmentX(Component.LEFT_ALIGNMENT);
        group.setMaximumSize(new Dimension(Integer.MAX_VALUE, 66));

        JLabel lbl = new JLabel(label);
        lbl.setFont(F_LABEL);
        lbl.setForeground(TEXT_DIM);
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        group.add(lbl);
        group.add(Box.createVerticalStrut(6));

        if (pwField != null) {
            // Wrapper champ + bouton œil
            JPanel row = new JPanel(new BorderLayout(0, 0));
            row.setOpaque(false);
            row.setAlignmentX(Component.LEFT_ALIGNMENT);
            row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));

            JButton eye = new JButton("voir");
            eye.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            eye.setForeground(TEXT_DIM);
            eye.setBackground(INPUT_BG);
            eye.setBorder(new CompoundBorder(
                    new MatteBorder(0, 1, 0, 0, BORDER_CLR),
                    new EmptyBorder(0, 10, 0, 10)));
            eye.setFocusPainted(false);
            eye.setCursor(new Cursor(Cursor.HAND_CURSOR));
            eye.addActionListener(e -> {
                if (pwField.getEchoChar() == (char) 0) {
                    pwField.setEchoChar('*');
                    eye.setText("voir");
                    eye.setForeground(TEXT_DIM);
                } else {
                    pwField.setEchoChar((char) 0);
                    eye.setText("cacher");
                    eye.setForeground(ACCENT);
                }
            });

            row.add(field, BorderLayout.CENTER);
            row.add(eye,   BorderLayout.EAST);
            group.add(row);
        } else {
            field.setAlignmentX(Component.LEFT_ALIGNMENT);
            group.add(field);
        }
        return group;
    }

    private JTextField createTextField() {
        JTextField f = new JTextField();
        applyFieldStyle(f);
        return f;
    }

    private JPasswordField createPasswordField() {
        JPasswordField f = new JPasswordField();
        f.setEchoChar('*');
        applyFieldStyle(f);
        return f;
    }

    private void applyFieldStyle(JTextField f) {
        f.setBackground(INPUT_BG);
        f.setForeground(TEXT);
        f.setCaretColor(ACCENT);
        f.setFont(F_INPUT);
        f.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        setFieldBorder(f, false);
        f.addFocusListener(new FocusAdapter() {
            public void focusGained(FocusEvent e) { setFieldBorder(f, true);  }
            public void focusLost(FocusEvent e)   { setFieldBorder(f, false); }
        });
    }

    private void setFieldBorder(JTextField f, boolean focused) {
        f.setBorder(new CompoundBorder(
                new LineBorder(focused ? ACCENT : BORDER_CLR, 1, false),
                new EmptyBorder(9, 12, 9, 12)));
    }

    private JButton createButton(String text, Color bg, Color hover) {
        JButton btn = new JButton(text) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(getBackground());
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        btn.setBackground(bg);
        btn.setForeground(Color.WHITE);
        btn.setFont(F_BTN);
        btn.setBorder(new EmptyBorder(11, 20, 11, 20));
        btn.setFocusPainted(false);
        btn.setContentAreaFilled(false);
        btn.setOpaque(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        btn.setAlignmentX(Component.LEFT_ALIGNMENT);
        btn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) { if (btn.isEnabled()) btn.setBackground(hover); }
            public void mouseExited(MouseEvent e)  { btn.setBackground(bg); }
        });
        return btn;
    }

    private void setLoading(JButton btn, boolean loading) {
        SwingUtilities.invokeLater(() -> {
            btn.setEnabled(!loading);
            if (loading) {
                btn.putClientProperty("orig", btn.getText());
                btn.setText("Chargement...");
            } else {
                Object orig = btn.getClientProperty("orig");
                if (orig != null) btn.setText((String) orig);
            }
        });
    }

    private void setStatus(String msg, Color color) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(msg);
            statusLabel.setForeground(color);
        });
    }
}

