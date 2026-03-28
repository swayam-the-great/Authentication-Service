package com.SpringSecurity.AuthBackend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.SpringSecurity.AuthBackend.dtos.ApiError;
import com.SpringSecurity.AuthBackend.security.JwtAuthenticationFilter;

import tools.jackson.databind.ObjectMapper;

import java.util.Arrays;
import java.util.List;

/* =========================================================
                    SPRING SECURITY CONFIGURATION
   ---------------------------------------------------------
   Responsibilities:
   1. Configure HTTP security
   2. Add JWT authentication filter
   3. Configure stateless session policy
   4. Handle unauthorized access
   5. Provide password encoder bean
   ========================================================= */

@Configuration
@EnableWebSecurity

public class SecurityConfig {

        /*
         * =========================================================
         * DEPENDENCIES
         * =========================================================
         */

        private final JwtAuthenticationFilter jwtAuthenticationFilter;
        private final AuthenticationSuccessHandler successHandler;
        private final List<String> allowedOrigins;

        /*
         * =========================================================
         * CONSTRUCTOR
         * =========================================================
         */

        public SecurityConfig(
                        JwtAuthenticationFilter jwtAuthenticationFilter,
                        AuthenticationSuccessHandler successHandler,
                        @Value("${app.cors.allowed-origins:http://localhost:3000,http://localhost:5173}") String allowedOrigins) {
                this.jwtAuthenticationFilter = jwtAuthenticationFilter;
                this.successHandler = successHandler;
                this.allowedOrigins = Arrays.stream(allowedOrigins.split(","))
                                .map(String::trim)
                                .filter(origin -> !origin.isBlank())
                                .toList();
        }

        /*
         * =========================================================
         * SECURITY FILTER CHAIN
         * ---------------------------------------------------------
         * Main Spring Security configuration
         * =========================================================
         */

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

                http
                                /* ---------------- CSRF & CORS ---------------- */

                                .csrf(AbstractHttpConfigurer::disable)
                                .cors(Customizer.withDefaults())

                                /* ---------------- AUTHORIZATION RULES ---------------- */

                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                                .requestMatchers(AppConstants.AUTH_PUBLIC_URLS).permitAll()
                                                .anyRequest().authenticated())

                                /* ---------------- SESSION POLICY ---------------- */

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                /* ---------------- OAUTH2 LOGIN ---------------- */
                                .oauth2Login(oauth2 -> oauth2.successHandler(successHandler)
                                                .failureHandler(null))
                                .logout(AbstractHttpConfigurer::disable)
                                /* ---------------- EXCEPTION HANDLING ---------------- */

                                .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, e) -> {

                                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                                        response.setContentType("application/json");

                                        String message = e.getMessage();

                                        // Custom error set in JWT filter
                                        String error = (String) request.getAttribute("error");
                                        if (error != null) {
                                                message = error;
                                        }

                                        var apiError = ApiError.of(
                                                        HttpStatus.UNAUTHORIZED.value(),
                                                        "Unauthorized Access",
                                                        message,
                                                        request.getRequestURI(),
                                                        true);

                                        var objectMapper = new ObjectMapper();
                                        response.getWriter().write(
                                                        objectMapper.writeValueAsString(apiError));
                                }))

                                /* ---------------- ADD JWT FILTER ---------------- */

                                .addFilterBefore(
                                                jwtAuthenticationFilter,
                                                UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

        /*
         * =========================================================
         * PASSWORD ENCODER BEAN
         * =========================================================
         */

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        /*
         * =========================================================
         * AUTHENTICATION MANAGER BEAN
         * =========================================================
         */

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
                return configuration.getAuthenticationManager();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                var configuration = new CorsConfiguration();
                configuration.setAllowedOriginPatterns(allowedOrigins);
                configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(List.of("*"));
                configuration.setAllowCredentials(true);
                configuration.setExposedHeaders(List.of("Authorization"));

                var source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        /*
         * =========================================================
         * IN-MEMORY USERS (OPTIONAL)
         * ---------------------------------------------------------
         * Used for testing only
         * =========================================================
         */

        /*
         * @Bean
         * public UserDetailsService users() {
         * 
         * User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
         * 
         * UserDetails user1 =
         * userBuilder.username("ankit").password("abc").roles("ADMIN").build();
         * 
         * UserDetails user2 =
         * userBuilder.username("shiva").password("xyz").roles("ADMIN").build();
         * 
         * UserDetails user3 =
         * userBuilder.username("durgesh").password("").roles("USER").build();
         * 
         * return new InMemoryUserDetailsManager(user1, user2, user3);
         * }
         */

}

// .authorizeHttpRequests(auth -> auth
// .requestMatchers("/api/v1/auth/**").permitAll()
// .anyRequest().authenticated())
