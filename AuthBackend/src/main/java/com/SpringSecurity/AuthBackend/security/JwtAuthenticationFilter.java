package com.SpringSecurity.AuthBackend.security;

import io.jsonwebtoken.*;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import com.SpringSecurity.AuthBackend.helpers.UserHelper;
import com.SpringSecurity.AuthBackend.repository.UserRepository;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;


/* =========================================================
   JWT AUTHENTICATION FILTER
   ---------------------------------------------------------
   1. Extract JWT from Authorization header
   2. Validate token
   3. Extract userId
   4. Fetch user from database
   5. Set authentication in SecurityContext
   ========================================================= */

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /* ---------------- DEPENDENCIES ---------------- */

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private static final Logger logger =
            LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    /* ---------------- MAIN FILTER ---------------- */

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Step 1: Read Authorization header
        String header = request.getHeader("Authorization");
        logger.info("Authorization header : {}", header);

        // Step 2: Check Bearer token
        if (header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);

            try {

                // Step 3: Validate token type
                if (!jwtService.isAccessToken(token)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                // Step 4: Parse token
                Jws<Claims> parsedToken = jwtService.parse(token);
                Claims payload = parsedToken.getPayload();

                // Step 5: Extract userId
                String userId = payload.getSubject();
                UUID userUuid = UserHelper.parseUUID(userId);

                // Step 6: Fetch user
                userRepository.findById(userUuid).ifPresent(user -> {

                    if (user.isEnable()) {

                        // Step 7: Convert roles → authorities
                        List<GrantedAuthority> authorities =
                                user.getRoles() == null
                                        ? List.of()
                                        : user.getRoles().stream()
                                            .map(role -> new SimpleGrantedAuthority(role.getName()))
                                            .collect(Collectors.toList());

                        // Step 8: Create authentication object
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        user.getEmail(), null, authorities);

                        // Step 9: Attach request details
                        authentication.setDetails(
                                new WebAuthenticationDetailsSource()
                                        .buildDetails(request));

                        // Step 10: Set security context
                        if (SecurityContextHolder.getContext().getAuthentication() == null) {
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
                    }
                });

            } catch (ExpiredJwtException e) {

                // Token expired
                request.setAttribute("error", "Token Expired");

            } catch (Exception e) {

                // Invalid token
                request.setAttribute("error", "Invalid Token");
            }
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }


    /* ---------------- SKIP FILTER ---------------- */

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request)
            throws ServletException {

        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}