// ======================================================
// 1️⃣ PACKAGE
// ======================================================
package com.SpringSecurity.AuthBackend.security;

// ======================================================
// 2️⃣ IMPORTS
// ======================================================
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.SpringSecurity.AuthBackend.entities.RefreshToken;
import com.SpringSecurity.AuthBackend.entities.User;
import com.SpringSecurity.AuthBackend.enums.Provider;
import com.SpringSecurity.AuthBackend.repository.RefreshTokenRepository;
import com.SpringSecurity.AuthBackend.repository.UserRepository;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

// ======================================================
// 3️⃣ CLASS DECLARATION
// ======================================================

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    // ======================================================
    // 4️⃣ LOGGER
    // ======================================================

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    // ======================================================
    // 5️⃣ DEPENDENCIES (Injected by Spring)
    // ======================================================

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    // ======================================================
    // 6️⃣ FRONTEND REDIRECT URL
    // ======================================================

    @Value("${app.auth.frontend.success-redirect}")
    private String frontEndSuccessUrl;

    // ======================================================
    // 7️⃣ METHOD CALLED AFTER SUCCESSFUL OAUTH LOGIN
    // ======================================================

    @Override
    @Transactional
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        // ======================================================
        // 8️⃣ LOG SUCCESSFUL AUTHENTICATION
        // ======================================================

        logger.info("Successful authentication");
        logger.info(authentication.toString());

        // ======================================================
        // 9️⃣ GET OAUTH USER DETAILS
        // ======================================================

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // ======================================================
        // 🔟 IDENTIFY OAUTH PROVIDER (GOOGLE / GITHUB)
        // ======================================================

        String registrationId = "unknown";

        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("registrationId:" + registrationId);
        logger.info("user:" + oAuth2User.getAttributes().toString());

        // ======================================================
        // 1️⃣1️⃣ HANDLE USER BASED ON PROVIDER
        // ======================================================

        User user;

        switch (registrationId) {

            // ------------------------------------------------------
            // GOOGLE LOGIN
            // ------------------------------------------------------

            case "google" -> {

                String googleId = oAuth2User.getAttributes()
                        .getOrDefault("sub", "")
                        .toString();

                String email = oAuth2User.getAttributes()
                        .getOrDefault("email", "")
                        .toString();

                String name = oAuth2User.getAttributes()
                        .getOrDefault("name", "")
                        .toString();

                String picture = oAuth2User.getAttributes()
                        .getOrDefault("picture", "")
                        .toString();

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .enable(true)
                        .provider(Provider.GOOGLE)
                        .providerId(googleId)
                        .build();

                user = userRepository
                        .findByEmail(email)
                        .orElseGet(() -> userRepository.save(newUser));
            }

            // ------------------------------------------------------
            // GITHUB LOGIN
            // ------------------------------------------------------

            case "github" -> {

                String name = oAuth2User.getAttributes()
                        .getOrDefault("login", "")
                        .toString();

                String githubId = oAuth2User.getAttributes()
                        .getOrDefault("id", "")
                        .toString();

                String image = oAuth2User.getAttributes()
                        .getOrDefault("avatar_url", "")
                        .toString();

                String email = (String) oAuth2User.getAttributes().get("email");

                if (email == null) {
                    email = name + "@github.com";
                }

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(image)
                        .enable(true)
                        .provider(Provider.GITHUB)
                        .providerId(githubId)
                        .build();

                user = userRepository
                        .findByEmail(email)
                        .orElseGet(() -> userRepository.save(newUser));
            }

            // ------------------------------------------------------
            // INVALID PROVIDER
            // ------------------------------------------------------

            default -> {
                throw new RuntimeException("Invalid registration id");
            }

        }

        // ======================================================
        // 1️⃣2️⃣ CREATE REFRESH TOKEN
        // ======================================================

        String jti = UUID.randomUUID().toString();

        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now()
                        .plusSeconds(jwtService.getRefreshTtlSeconds()))
                .build();

        refreshTokenRepository.save(refreshTokenOb);

        // ======================================================
        // 1️⃣3️⃣ GENERATE JWT TOKENS
        // ======================================================

        String accessToken = jwtService.generateAccessToken(user);

        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());

        // ======================================================
        // 1️⃣4️⃣ ATTACH REFRESH TOKEN COOKIE
        // ======================================================

        cookieService.attachRefreshCookie(
                response,
                refreshToken,
                (int) jwtService.getRefreshTtlSeconds());

        // ======================================================
        // 1️⃣5️⃣ REDIRECT USER TO FRONTEND
        // ======================================================

        response.sendRedirect(frontEndSuccessUrl);

    }
}