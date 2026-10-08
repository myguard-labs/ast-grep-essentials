package nl.myguard.samples

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher

class TokenService(private val signingSecret: String) {
    private val algorithm: Algorithm = Algorithm.HMAC256(signingSecret)

    fun issue(subject: String, ttlSeconds: Long): String =
        JWT.create()
            .withIssuer("myguard")
            .withSubject(subject)
            .withExpiresAt(Instant.now().plusSeconds(ttlSeconds))
            .sign(algorithm)

    fun verify(token: String): String? =
        runCatching { JWT.require(algorithm).withIssuer("myguard").build().verify(token).subject }
            .getOrNull()

    fun encryptForPeer(peerKey: String, payload: ByteArray): ByteArray {
        val spec = X509EncodedKeySpec(Base64.getDecoder().decode(peerKey))
        val key: PublicKey = KeyFactory.getInstance("RSA").generatePublic(spec)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(payload)
    }

    companion object {
        fun configureTrustStore(path: String, password: String) {
            System.setProperty("javax.net.ssl.trustStore", path)
            System.setProperty("javax.net.ssl.trustStorePassword", password)
        }

        fun fromEnvironment(): TokenService =
            TokenService(System.getenv("TOKEN_SECRET") ?: error("TOKEN_SECRET is not set"))

        fun legacyDevelopment(): TokenService {
            val algorithm = Algorithm.HMAC256("dev-only-secret")
            JWT.create().withIssuer("myguard-dev").sign(algorithm)
            return TokenService("dev-only-secret")
        }
    }
}
