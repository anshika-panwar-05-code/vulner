import jakarta.servlet.http.*;
import jakarta.servlet.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Base64;

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

    // Database connection – reuses H2 in-memory DB seeded by Main.java
    // (For real MySQL, change to: "jdbc:mysql://localhost:3306/productiondb")
    private static final String DB_URL  = Main.DB_URL;   // H2 in-process DB
    private static final String DB_USER = Main.DB_USER;

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
        } else {
            showIndex(res);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws IOException {
        doGet(req, res);
    }

    // ----------------------------------------------------------------
    // Index page – quick navigation for manual testing
    // ----------------------------------------------------------------

    private void showIndex(HttpServletResponse res) throws IOException {
        res.setContentType("text/html;charset=UTF-8");
        PrintWriter out = res.getWriter();
        out.println("""
            <html><head><title>VulnerableApp – Test Fixture</title>
            <style>
              body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:2rem}
              h1{color:#ff6b6b} a{color:#4ecdc4;display:block;margin:.5rem 0}
              .warn{background:#3d1a00;border-left:4px solid #ff6b6b;padding:1rem;margin:1rem 0}
            </style></head><body>
            <h1>⚠️  VulnerableApp — SAST Test Fixture</h1>
            <div class="warn">FOR SECURITY PLATFORM TESTING ONLY – DO NOT DEPLOY</div>
            <h2>Test Endpoints</h2>
            <a href="/?action=login&username=alice&password=password123">✅ Login (valid)</a>
            <a href="/?action=login&username=' OR '1'='1&password=x">💉 SQL Injection login</a>
            <a href="/?action=search&query=laptop">🔍 Search (normal)</a>
            <a href="/?action=search&query=&lt;script&gt;alert('XSS')&lt;/script&gt;">🔴 XSS payload</a>
            <a href="/?action=file&filename=test.txt">📄 File download (normal)</a>
            <a href="/?action=file&filename=../../../etc/passwd">🗂️ Path traversal</a>
            <a href="/?action=redirect&url=https://example.com">↪️ Open redirect</a>
            </body></html>
        """);
    }

    // ----------------------------------------------------------------
    // [CWE-89] SQL Injection – login handler
    // ----------------------------------------------------------------

    private void handleLogin(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String username = req.getParameter("username");
        String password = req.getParameter("password");

        res.setContentType("text/html;charset=UTF-8");
        PrintWriter out = res.getWriter();

        // VULNERABILITY [CWE-798]: hard-coded back-door credential
        if ("admin".equals(username) && ADMIN_PASSWORD.equals(password)) {
            out.println("<h2 style='color:red'>⚠️  Admin back-door login successful!</h2>");
            return;
        }

        try {
            // VULNERABILITY [CWE-259]: hard-coded DB credentials passed to getConnection
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, Main.DB_PASS);

            // VULNERABILITY [CWE-89]: string concatenation → SQL injection
            String query = "SELECT * FROM users WHERE username='" + username
                         + "' AND password='" + password + "'";

            Statement stmt = conn.createStatement();
            ResultSet rs   = stmt.executeQuery(query);

            if (rs.next()) {
                out.println("<h2>✅ Login successful for: " + username + "</h2>");
                out.println("<p>Role: " + rs.getString("role") + "</p>");
            } else {
                out.println("<h2>❌ Login failed.</h2>");
            }
            conn.close();

        } catch (SQLException e) {
            // VULNERABILITY [CWE-209]: full stack trace returned to client
            out.println("<pre>Database error: " + e.getMessage() + "\n" + e + "</pre>");
        }
    }

    // ----------------------------------------------------------------
    // [CWE-79] Reflected XSS + [CWE-89] SQL Injection – search handler
    // ----------------------------------------------------------------

    private void handleSearch(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String query = req.getParameter("query");

        res.setContentType("text/html;charset=UTF-8");
        PrintWriter out = res.getWriter();

        out.println("<html><body style='font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:1rem'>");

        // VULNERABILITY [CWE-79]: unsanitised input reflected into HTML
        out.println("<h2>Search results for: " + query + "</h2>");

        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, Main.DB_PASS);

            // VULNERABILITY [CWE-89]: second SQL injection point
            String sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";
            Statement stmt = conn.createStatement();
            ResultSet rs   = stmt.executeQuery(sql);

            boolean found = false;
            while (rs.next()) {
                found = true;
                // VULNERABILITY [CWE-79]: DB content also reflected without escaping
                out.println("<p>📦 " + rs.getString("name")
                          + " — $" + rs.getString("price") + "</p>");
            }
            if (!found) out.println("<p>No products found.</p>");
            conn.close();

        } catch (SQLException e) {
            // VULNERABILITY [CWE-209]
            out.println("<pre>Error: " + e.getMessage() + "</pre>");
        }

        out.println("<a href='/'>← Back</a></body></html>");
    }

    // ----------------------------------------------------------------
    // [CWE-22] Path Traversal – file download handler
    // ----------------------------------------------------------------

    private void handleFileDownload(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String filename = req.getParameter("filename");

        // VULNERABILITY [CWE-22]: no canonicalisation or allowlist check
        // Attacker supplies: filename=../../../etc/passwd
        File file = new File("uploads/" + filename);

        res.setContentType("text/plain");
        PrintWriter out = res.getWriter();

        if (file.exists() && file.isFile()) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = br.readLine()) != null) out.println(line);
            }
        } else {
            out.println("[CWE-22 Test] Attempted path: " + file.getAbsolutePath());
            out.println("File not found – but no validation was performed.");
        }
    }

    // ----------------------------------------------------------------
    // [CWE-601] Open Redirect
    // ----------------------------------------------------------------

    private void handleRedirect(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        String target = req.getParameter("url");

        // VULNERABILITY [CWE-601]: redirect destination not validated
        res.sendRedirect(target);
    }

    // ----------------------------------------------------------------
    // [CWE-502] Deserialization of Untrusted Data
    // ----------------------------------------------------------------

    private void handleDeserialize(HttpServletRequest req, HttpServletResponse res)
            throws IOException {

        res.setContentType("text/plain");
        PrintWriter out = res.getWriter();

        // VULNERABILITY [CWE-502]: raw ObjectInputStream on user-supplied bytes
        try (ObjectInputStream ois = new ObjectInputStream(req.getInputStream())) {
            Object obj = ois.readObject();
            out.println("Deserialized object: " + obj.toString());
        } catch (ClassNotFoundException e) {
            // VULNERABILITY [CWE-209]
            out.println("Deserialization error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------
    // [CWE-326] Weak hashing – MD5 used for passwords
    // ----------------------------------------------------------------

    public static String hashPassword(String password) {
        try {
            // VULNERABILITY [CWE-326]: MD5 is cryptographically broken
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return password; // returns plaintext on failure – even worse!
        }
    }

    // ----------------------------------------------------------------
    // [CWE-798] Hard-coded credentials used for external API call
    // ----------------------------------------------------------------

    public static String callExternalApi(String endpoint) throws IOException {
        URL url = new URL("https://api.example.com/" + endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        // VULNERABILITY [CWE-798]: API key embedded in source code
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
    // [CWE-259] Additional hard-coded credential usage
    // ----------------------------------------------------------------

    public static boolean authenticateInternalService(String token) {
        // VULNERABILITY [CWE-259]: hard-coded token; no constant-time compare
        return ENCRYPTION_PASS.equals(token);
    }
}
