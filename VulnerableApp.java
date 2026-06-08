/**
 * ============================================================
 *  VulnerableApp.java
 *  *** FOR SECURITY PLATFORM TESTING ONLY ***
 *  This file is intentionally written with known vulnerabilities
 *  to validate SAST / vulnerability-detection tooling.
 *  DO NOT deploy this code in any production environment.
 * ============================================================
 *
 *  Vulnerabilities present:
 *  [CWE-259]  Use of Hard-coded Password
 *  [CWE-89]   SQL Injection
 *  [CWE-79]   Cross-Site Scripting (XSS) via servlet response
 *  [CWE-502]  Deserialization of Untrusted Data
 *  [CWE-22]   Path Traversal
 *  [CWE-326]  Inadequate Encryption Strength (MD5)
 *  [CWE-798]  Use of Hard-coded Credentials
 *  [CWE-209]  Information Exposure Through Error Messages
 *  [CWE-601]  Open Redirect
 */

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Base64;
import javax.servlet.http.*;

public class VulnerableApp extends HttpServlet {

    // ----------------------------------------------------------------
    // [CWE-259 / CWE-798] Hard-coded Passwords & Credentials
    // ----------------------------------------------------------------

    /** Hard-coded database password – never do this in real code. */
    private static final String DB_PASSWORD  = "SuperSecret@123";

    /** Hard-coded admin credential used for a back-door login. */
    private static final String ADMIN_PASSWORD = "Admin@Pass#2024";

    /** Hard-coded API key for a third-party service. */
    private static final String API_SECRET_KEY = "FAKE_KEY_9aB3cD7eF2gH5iJ8kL1mN4oP_TEST_ONLY"; // CWE-798: hardcoded API credential

    /** Hard-coded encryption passphrase. */
    private static final String ENCRYPTION_PASS = "Encr@pt10nK3y!";

    // Database connection details (also hard-coded)
    private static final String DB_URL  = "jdbc:mysql://localhost:3306/productiondb";
    private static final String DB_USER = "root";

    // ----------------------------------------------------------------
    // Servlet entry point
    // ----------------------------------------------------------------

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String action = req.getParameter("action");

        if ("login".equals(action)) {
            handleLogin(req, res);
        } else if ("search".equals(action)) {
            handleSearch(req, res);
        } else if ("file".equals(action)) {
            handleFileDownload(req, res);
        } else if ("redirect".equals(action)) {
            handleRedirect(req, res);
        } else if ("deserialize".equals(action)) {
            handleDeserialize(req, res);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws IOException {
        doGet(req, res);
    }

    // ----------------------------------------------------------------
    // [CWE-89] SQL Injection
    // User-supplied input is concatenated directly into the SQL query.
    // ----------------------------------------------------------------

    private void handleLogin(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String username = req.getParameter("username");
        String password = req.getParameter("password");

        // VULNERABILITY: hard-coded back-door + SQL injection
        if ("admin".equals(username) && ADMIN_PASSWORD.equals(password)) {
            res.getWriter().write("Admin back-door login successful!");
            return;
        }

        try {
            // VULNERABILITY: [CWE-259] hard-coded DB credentials
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // VULNERABILITY: [CWE-89] SQL injection — input not sanitised
            String query = "SELECT * FROM users WHERE username='" + username
                         + "' AND password='" + password + "'";

            Statement stmt = conn.createStatement();
            ResultSet rs   = stmt.executeQuery(query);

            if (rs.next()) {
                res.getWriter().write("Login successful for: " + username);
            } else {
                res.getWriter().write("Login failed.");
            }

        } catch (SQLException e) {
            // VULNERABILITY: [CWE-209] full stack trace exposed to client
            res.getWriter().write("Database error: " + e.getMessage() + "\n" + e);
        }
    }

    // ----------------------------------------------------------------
    // [CWE-79] Reflected Cross-Site Scripting (XSS)
    // Unsanitised user input reflected directly in HTML response.
    // ----------------------------------------------------------------

    private void handleSearch(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String query = req.getParameter("query");

        res.setContentType("text/html");
        PrintWriter out = res.getWriter();

        // VULNERABILITY: [CWE-79] user input written to HTML without escaping
        out.println("<html><body>");
        out.println("<h2>Search results for: " + query + "</h2>");

        try {
            Connection conn  = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            // VULNERABILITY: [CWE-89] second SQL injection point
            String sql       = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";
            Statement stmt   = conn.createStatement();
            ResultSet rs     = stmt.executeQuery(sql);

            while (rs.next()) {
                out.println("<p>" + rs.getString("name") + "</p>");
            }
        } catch (SQLException e) {
            out.println("<p>Error: " + e.getMessage() + "</p>");
        }

        out.println("</body></html>");
    }

    // ----------------------------------------------------------------
    // [CWE-22] Path Traversal
    // Attacker can supply "../../../etc/passwd" as the filename.
    // ----------------------------------------------------------------

    private void handleFileDownload(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String filename = req.getParameter("filename");

        // VULNERABILITY: [CWE-22] no canonicalisation / allowlist check
        File file = new File("/var/app/uploads/" + filename);

        if (file.exists()) {
            byte[] data = new FileInputStream(file).readAllBytes();
            res.getOutputStream().write(data);
        } else {
            res.getWriter().write("File not found: " + filename);
        }
    }

    // ----------------------------------------------------------------
    // [CWE-601] Open Redirect
    // Attacker can redirect users to a phishing site.
    // ----------------------------------------------------------------

    private void handleRedirect(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String target = req.getParameter("url");

        // VULNERABILITY: [CWE-601] redirect destination not validated
        res.sendRedirect(target);
    }

    // ----------------------------------------------------------------
    // [CWE-502] Deserialization of Untrusted Data
    // Deserialising raw bytes from user request body.
    // ----------------------------------------------------------------

    private void handleDeserialize(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        // VULNERABILITY: [CWE-502] ObjectInputStream accepts any class
        try (ObjectInputStream ois = new ObjectInputStream(req.getInputStream())) {
            Object obj = ois.readObject();
            res.getWriter().write("Received object: " + obj.toString());
        } catch (ClassNotFoundException e) {
            res.getWriter().write("Deserialization error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------
    // [CWE-326] Inadequate Encryption Strength — MD5 used for passwords
    // ----------------------------------------------------------------

    public static String hashPassword(String password) {
        try {
            // VULNERABILITY: [CWE-326] MD5 is cryptographically broken
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return password; // returning plaintext on failure — even worse!
        }
    }

    // ----------------------------------------------------------------
    // [CWE-798] Hard-coded credentials used for external API call
    // ----------------------------------------------------------------

    public static String callExternalApi(String endpoint) throws IOException {
        URL url = new URL("https://api.example.com/" + endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        // VULNERABILITY: [CWE-798] API key embedded in source code
        conn.setRequestProperty("Authorization", "Bearer " + API_SECRET_KEY);

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }

    // ----------------------------------------------------------------
    // [CWE-259] Additional hard-coded credential usage example
    // ----------------------------------------------------------------

    public static boolean authenticateInternalService(String token) {
        // VULNERABILITY: constant-time comparison not used; hard-coded token
        return ENCRYPTION_PASS.equals(token);
    }

    // ----------------------------------------------------------------
    // Main — stand-alone demo (non-servlet path)
    // ----------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        System.out.println("=== Vulnerable App Demo ===");

        // Demonstrates hard-coded credential usage
        System.out.println("DB Password   : " + DB_PASSWORD);
        System.out.println("Admin Password: " + ADMIN_PASSWORD);
        System.out.println("API Key       : " + API_SECRET_KEY);
        System.out.println("Encrypt Pass  : " + ENCRYPTION_PASS);

        // Demonstrates weak hashing
        String hashed = hashPassword("mypassword");
        System.out.println("MD5 hash of 'mypassword': " + hashed);
    }
}
