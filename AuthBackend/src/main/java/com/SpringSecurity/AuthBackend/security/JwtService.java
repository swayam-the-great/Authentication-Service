package com.SpringSecurity.AuthBackend.security;

import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.SpringSecurity.AuthBackend.entities.Role;
import com.SpringSecurity.AuthBackend.entities.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import lombok.Getter;
import lombok.Setter;



/* =========================================================
                        JWT SERVICE
   ---------------------------------------------------------
   Responsibilities:
   1. Generate Access Token
   2. Generate Refresh Token
   3. Parse JWT
   4. Extract claims from token
   ========================================================= */

@Service
@Getter
@Setter
public class JwtService {



    /* =========================================================
                        CONFIGURATION VALUES
       ========================================================= */

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;



    /* =========================================================
                        CONSTRUCTOR
       ---------------------------------------------------------
       Loads values from application.yml
       ========================================================= */

    public JwtService(

            @Value("${security.jwt.secret}")
            String secret,

            @Value("${security.jwt.access-ttl-seconds}")
            long accessTtlSeconds,

            @Value("${security.jwt.refresh-ttl-seconds}")
            long refreshTtlSeconds,

            @Value("${security.jwt.issuer}")
            String issuer
    ) {

        // Validate secret key length
        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException("Invalid secret");
        }

        // Create HMAC SHA key
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }



    /* =========================================================
                    ACCESS TOKEN GENERATION
       ========================================================= */

    public String generateAccessToken(User user) {

        Instant now = Instant.now();

        // Extract role names from user
        List<String> roles =
                user.getRoles() == null
                        ? List.of()
                        : user.getRoles()
                              .stream()
                              .map(Role::getName)
                              .toList();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())        // Unique token ID
                .subject(user.getId().toString())        // User ID
                .issuer(issuer)                          // Token issuer

                .issuedAt(Date.from(now))                // Issued time
                .expiration(Date.from(
                        now.plusSeconds(accessTtlSeconds)
                ))                                       // Expiry time

                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles", roles,
                        "typ", "access"
                ))

                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }



    /* =========================================================
                    REFRESH TOKEN GENERATION
       ========================================================= */

    public String generateRefreshToken(User user, String jti) {

        Instant now = Instant.now();

        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString())
                .issuer(issuer)

                .issuedAt(Date.from(now))
                .expiration(Date.from(
                        now.plusSeconds(refreshTtlSeconds)
                ))

                .claim("typ", "refresh")

                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }



    /* =========================================================
                        TOKEN PARSING
       ========================================================= */

    public Jws<Claims> parse(String token) {

        return Jwts
                .parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);
    }



    /* =========================================================
                    TOKEN TYPE CHECK
       ========================================================= */

    public boolean isAccessToken(String token) {

        Claims claims = parse(token).getPayload();
        return "access".equals(claims.get("typ"));
    }

    public boolean isRefreshToken(String token) {

        Claims claims = parse(token).getPayload();
        return "refresh".equals(claims.get("typ"));
    }



    /* =========================================================
                        CLAIM EXTRACTION
       ========================================================= */

    public UUID getUserId(String token) {

        Claims claims = parse(token).getPayload();
        return UUID.fromString(claims.getSubject());
    }

    public String getJti(String token) {

        return parse(token).getPayload().getId();
    }

    public List<String> getRoles(String token) {

        Claims claims = parse(token).getPayload();
        return (List<String>) claims.get("roles");
    }

    public String getEmail(String token) {

        Claims claims = parse(token).getPayload();
        return (String) claims.get("email");
    }

}