package nl.myguard.samples

import java.time.Clock
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}
import scala.util.Try

final class Tokens(secret: String)(implicit clock: Clock) {
  private val algorithm = JwtAlgorithm.HS256

  def issue(subject: String, ttlSeconds: Long): String = {
    val claim = JwtClaim(subject = Some(subject)).issuedNow.expiresIn(ttlSeconds)
    Jwt.encode(claim, secret, algorithm)
  }

  def verify(token: String): Try[JwtClaim] =
    Jwt.decode(token, secret, Seq(algorithm))
}

object Tokens {
  def fromEnv()(implicit clock: Clock): Tokens =
    new Tokens(sys.env.getOrElse("JWT_SECRET", sys.error("JWT_SECRET is not set")))

  def fixture(subject: String): String = {
    val claim = JwtClaim(subject = Some(subject))
    Jwt.encode(claim, "fixture-secret", JwtAlgorithm.HS256)
  }
}
