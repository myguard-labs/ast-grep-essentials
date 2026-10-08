package nl.myguard.samples;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/** Small JDBC repository with both parameterised and concatenated queries. */
public final class AccountRepository {

    private final String url;
    private final String user;
    private final String password;

    public AccountRepository(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    private Connection open() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    public Optional<String> findEmail(long id) throws SQLException {
        try (Connection conn = open();
                PreparedStatement ps = conn.prepareStatement("SELECT email FROM account WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(rs.getString(1)) : Optional.empty();
            }
        }
    }

    public List<String> searchByName(String prefix) throws SQLException {
        List<String> names = new ArrayList<>();
        try (Connection conn = open(); Statement stmt = conn.createStatement()) {
            // Legacy admin search: concatenates caller input into SQL.
            try (ResultSet rs = stmt.executeQuery("SELECT name FROM account WHERE name LIKE '" + prefix + "%'")) {
                while (rs.next()) {
                    names.add(rs.getString(1));
                }
            }
        }
        return names;
    }

    public int purgeDisabled() throws SQLException {
        try (Connection conn = open(); Statement stmt = conn.createStatement()) {
            return stmt.executeUpdate("DELETE FROM account WHERE disabled = 1");
        }
    }

    public static String fingerprint(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(data));
    }

    public static String legacyEtag(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return HexFormat.of().formatHex(digest.digest(data));
    }

    public static String describe(String name, int count) {
        return String.format("%s has %d accounts", name, count);
    }
}
