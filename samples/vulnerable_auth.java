import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;

public class UserAuthService {
    // VULNERABILITY 1: Hardcoded Database Password
    private static final String DB_PASSWORD = "database_admin_password_123!";

    public boolean authenticate(String username, String password) throws Exception {
        // VULNERABILITY 2: Broken cryptographic hashing using MD5
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] digest = md.digest();

        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/users", "admin", DB_PASSWORD);
        Statement statement = conn.createStatement();

        // VULNERABILITY 3: SQL Injection via unparameterized statement execution
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet rs = statement.executeQuery(sql);

        return rs.next();
    }
}
