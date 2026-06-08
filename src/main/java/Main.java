import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

/**
 * Embedded Jetty launcher for VulnerableApp.
 *
 * Starts an HTTP server on port 8080 and seeds a small H2 in-memory
 * database so the SQL injection / login endpoints actually execute.
 *
 * Start with:  mvn package -q && java -jar target/vulnerable-app-1.0-SNAPSHOT.jar
 * Or simply:   mvn compile exec:java -Dexec.mainClass=Main
 */
public class Main {

    /** H2 in-memory JDBC URL shared across the whole JVM process. */
    public static final String DB_URL  = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";
    public static final String DB_USER = "sa";
    public static final String DB_PASS = "";   // H2 default – no password needed

    public static void main(String[] args) throws Exception {
        seedDatabase();

        Server server = new Server(8080);

        ServletContextHandler ctx =
                new ServletContextHandler(ServletContextHandler.SESSIONS);
        ctx.setContextPath("/");
        ctx.addServlet(new ServletHolder(new VulnerableApp()), "/*");

        server.setHandler(ctx);
        server.start();

        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║   VulnerableApp is running on http://localhost:8080  ║");
        System.out.println("║   FOR SECURITY PLATFORM TESTING ONLY                ║");
        System.out.println("╠══════════════════════════════════════════════════════╣");
        System.out.println("║  Endpoints:                                          ║");
        System.out.println("║  GET  /?action=login&username=admin&password=...     ║");
        System.out.println("║  GET  /?action=search&query=laptop                  ║");
        System.out.println("║  GET  /?action=file&filename=test.txt               ║");
        System.out.println("║  GET  /?action=redirect&url=https://example.com     ║");
        System.out.println("║  POST /?action=deserialize  (raw object in body)    ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");

        server.join();
    }

    /**
     * Bootstraps the H2 in-memory database with sample tables and data.
     * The same JDBC URL (mem:testdb) is reused by VulnerableApp so every
     * query hits this pre-populated database.
     */
    private static void seedDatabase() throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement  stmt = conn.createStatement();

        // Users table
        stmt.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100),
                password VARCHAR(255),
                role     VARCHAR(50)
            )
        """);

        // Seed a couple of test accounts (plaintext passwords — intentionally insecure)
        stmt.execute("""
            MERGE INTO users (id, username, password, role)
            KEY(id)
            VALUES (1, 'alice', 'password123', 'user'),
                   (2, 'bob',   'qwerty',      'user'),
                   (3, 'admin', 'Admin@Pass#2024', 'admin')
        """);

        // Products table
        stmt.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id    INT PRIMARY KEY AUTO_INCREMENT,
                name  VARCHAR(255),
                price DECIMAL(10,2)
            )
        """);

        stmt.execute("""
            MERGE INTO products (id, name, price)
            KEY(id)
            VALUES (1, 'Laptop Pro',  1299.99),
                   (2, 'USB Hub',       29.99),
                   (3, 'Mechanical Keyboard', 89.99)
        """);

        stmt.close();
        conn.close();
        System.out.println("[DB] H2 in-memory database seeded successfully.");
    }
}
