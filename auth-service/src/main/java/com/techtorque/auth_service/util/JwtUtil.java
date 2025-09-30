// In: /src/main/java/com/techtorque/auth_service/util/JwtUtil.java
package com.techtorque.auth_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

  private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

  @Value("${jwt.secret}")
  private String jwtSecret;

  @Value("${jwt.expiration}")
  private long jwtExpirationMs;

  /**
   * Generates a JWT token for a user with their roles.
   */
  public String generateJwtToken(UserDetails userDetails, List<String> roles) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("roles", roles);
    return generateToken(claims, userDetails.getUsername());
  }

  /**
   * Creates the token using the modern builder pattern.
   * This fixes all the deprecation warnings.
   */
  public String generateToken(Map<String, Object> extraClaims, String username) {
    Date now = new Date();
    Date expirationDate = new Date(now.getTime() + jwtExpirationMs);

    return Jwts.builder()
            .claims(extraClaims) // Modern way to set claims
            .subject(username)
            .issuedAt(now)
            .expiration(expirationDate)
            .signWith(getSignInKey()) // Modern way to sign (algorithm is inferred from the key)
            .compact();
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  @SuppressWarnings("unchecked")
  public List<String> extractRoles(String token) {
    return extractClaim(token, claims -> (List<String>) claims.get("roles"));
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  /**
   * Extracts all claims using the modern parser builder.
   * This part of your code was already correct.
   */
  private Claims extractAllClaims(String token) {
    return Jwts.parser()
            .verifyWith(getSignInKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
  }

  public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  private Boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public Boolean validateToken(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }

  /**
   * Validates the token structure and signature without checking expiration against UserDetails.
   */
  public boolean validateJwtToken(String token) {
    try {
      Jwts.parser()
              .verifyWith(getSignInKey())
              .build()
              .parseSignedClaims(token);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;
  }

  /**
   * Generates a SecretKey object from the secret string.
   */
  private SecretKey getSignInKey() {
    // Use the raw UTF-8 bytes of the secret string, just like the Go gateway.
    byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}