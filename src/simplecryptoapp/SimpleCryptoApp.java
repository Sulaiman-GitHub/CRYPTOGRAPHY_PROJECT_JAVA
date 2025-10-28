import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import java.awt.*;
import java.util.Base64;

public class SimpleCryptoApp extends JFrame {
    private JComboBox<String> algorithmCombo;
    private JTextArea inputText, outputText;
    private JTextField keyField;
    private JButton encryptBtn, decryptBtn;
    
    public SimpleCryptoApp() {
        setupGUI();
    }
    
    private void setupGUI() {
        setTitle("Simple Crypto App");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);
        
        // Main panel
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Algorithm selection
        JPanel topPanel = new JPanel(new FlowLayout());
        topPanel.add(new JLabel("Algorithm:"));
        algorithmCombo = new JComboBox<>(new String[]{"AES", "DES", "3DES", "Blowfish"});
        topPanel.add(algorithmCombo);
        
        // Text areas
        inputText = new JTextArea(5, 40);
        outputText = new JTextArea(5, 40);
        outputText.setEditable(false);
        
        JPanel textPanel = new JPanel(new GridLayout(1, 2, 10, 10));
        textPanel.add(new JScrollPane(inputText));
        textPanel.add(new JScrollPane(outputText));
        
        // Key and buttons
        JPanel bottomPanel = new JPanel(new FlowLayout());
        bottomPanel.add(new JLabel("Key:"));
        keyField = new JTextField(20);
        bottomPanel.add(keyField);
        
        encryptBtn = new JButton("Encrypt");
        decryptBtn = new JButton("Decrypt");
        bottomPanel.add(encryptBtn);
        bottomPanel.add(decryptBtn);
        
        // Add action listeners
        encryptBtn.addActionListener(e -> encrypt());
        decryptBtn.addActionListener(e -> decrypt());
        
        // Layout
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(textPanel, BorderLayout.CENTER);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        add(mainPanel);
    }
    
    private void encrypt() {
        try {
            String algorithm = (String) algorithmCombo.getSelectedItem();
            String input = inputText.getText();
            String key = keyField.getText();
            
            if (input.isEmpty() || key.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter both text and key");
                return;
            }
            
            String encrypted = encryptText(algorithm, input, key);
            outputText.setText(encrypted);
            
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Encryption failed: " + ex.getMessage());
        }
    }
    
    private void decrypt() {
        try {
            String algorithm = (String) algorithmCombo.getSelectedItem();
            String input = inputText.getText();
            String key = keyField.getText();
            
            if (input.isEmpty() || key.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter both text and key");
                return;
            }
            
            String decrypted = decryptText(algorithm, input, key);
            outputText.setText(decrypted);
            
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Decryption failed: " + ex.getMessage());
        }
    }
    
    private String encryptText(String algorithm, String data, String key) throws Exception {
        switch (algorithm) {
            case "AES": return encryptAES(data, key);
            case "DES": return encryptDES(data, key);
            case "3DES": return encrypt3DES(data, key);
            case "Blowfish": return encryptBlowfish(data, key);
            default: throw new IllegalArgumentException("Unknown algorithm");
        }
    }
    
    private String decryptText(String algorithm, String encryptedData, String key) throws Exception {
        switch (algorithm) {
            case "AES": return decryptAES(encryptedData, key);
            case "DES": return decryptDES(encryptedData, key);
            case "3DES": return decrypt3DES(encryptedData, key);
            case "Blowfish": return decryptBlowfish(encryptedData, key);
            default: throw new IllegalArgumentException("Unknown algorithm");
        }
    }
    
    // AES Encryption (128-bit)
    private String encryptAES(String data, String key) throws Exception {
        byte[] keyBytes = getKeyBytes(key, 16);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    private String decryptAES(String encryptedData, String key) throws Exception {
        byte[] keyBytes = getKeyBytes(key, 16);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
    
    // DES Encryption
    private String encryptDES(String data, String key) throws Exception {
        byte[] keyBytes = getKeyBytes(key, 8);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    private String decryptDES(String encryptedData, String key) throws Exception {
        byte[] keyBytes = getKeyBytes(key, 8);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
    
    // 3DES Encryption
    private String encrypt3DES(String data, String key) throws Exception {
        byte[] keyBytes = getKeyBytes(key, 24);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    private String decrypt3DES(String encryptedData, String key) throws Exception {
        byte[] keyBytes = getKeyBytes(key, 24);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
    
    // Blowfish Encryption
    private String encryptBlowfish(String data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    private String decryptBlowfish(String encryptedData, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
    
    // Helper method to generate key bytes of required length
    private byte[] getKeyBytes(String key, int length) {
        byte[] keyBytes = new byte[length];
        byte[] original = key.getBytes();
        System.arraycopy(original, 0, keyBytes, 0, Math.min(original.length, keyBytes.length));
        return keyBytes;
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new SimpleCryptoApp().setVisible(true);
        });
    }
}