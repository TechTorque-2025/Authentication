package com.techtorque.auth_service.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

  @Value("${jwt.secret}")
  private String secret;

  @Value("${jwt.expiration.time}")
  private long expirationTime;

  public String generateToken(String username) {
    SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

    return Jwts.builder()
            .subject(username)
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + expirationTime))
            .signWith(key)
            .compact();
  }

  public boolean validateToken(String token, String username) {
    try {
      SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
      String tokenUsername = Jwts.parser()
              .verifyWith(key)
              .build()
              .parseSignedClaims(token)
              .getPayload()
              .getSubject();

      return tokenUsername.equals(username);
    } catch (Exception e) {
      return false;
    }
  }

  public String extractUsername(String token) {
    try {
      SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
      return Jwts.parser()
              .verifyWith(key)
              .build()
              .parseSignedClaims(token)
              .getPayload()
              .getSubject();
    } catch (Exception e) {
      return null;
    }
  }
}