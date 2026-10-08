package nl.myguard.samples;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Servlet-style session handling with cookies, redirects and token sealing. */
public final class SessionController {

    private static final Set<String> SAFE_TARGETS = Set.of("/", "/account", "/logout");
    private final SecureRandom random = new SecureRandom();
    private final byte[] key;

    public SessionController(byte[] key) {
        this.key = key.clone();
    }

    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String id = newSessionId();
        Cookie session = new Cookie("sid", id);
        session.setHttpOnly(true);
        session.setSecure(true);
        session.setPath("/");
        response.addCookie(session);

        String next = request.getParameter("next");
        if (next != null && SAFE_TARGETS.contains(next)) {
            response.sendRedirect(next);
        } else {
            response.sendRedirect("/");
        }
    }

    public void rememberLanguage(HttpServletRequest request, HttpServletResponse response) {
        response.addCookie(new Cookie("lang", request.getLocale().getLanguage()));
    }

    public void back(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(request.getParameter("return"));
    }

    private String newSessionId() {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    public byte[] seal(String value) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] sealLegacy(String value) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
    }

    public int runTool(List<String> args) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(args);
        builder.redirectErrorStream(true);
        return builder.start().waitFor();
    }
}
