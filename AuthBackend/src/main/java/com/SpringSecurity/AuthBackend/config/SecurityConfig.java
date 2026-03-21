package com.SpringSecurity.AuthBackend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpStatus;
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

import com.SpringSecurity.AuthBackend.dtos.ApiError;
import com.SpringSecurity.AuthBackend.security.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;
import tools.jackson.databind.ObjectMapper;

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
@RequiredArgsConstructor
public class SecurityConfig {

        /*
         * =========================================================
         * DEPENDENCIES
         * =========================================================
         */

        private final JwtAuthenticationFilter jwtAuthenticationFilter;
        // private final AuthenticationSuccessHandler successHandler;

        /*
         * =========================================================
         * CONSTRUCTOR
         * =========================================================
         */

        // public SecurityConfig(
        // JwtAuthenticationFilter jwtAuthenticationFilter,
        // AuthenticationSuccessHandler successHandler
        // ) {
        // this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        // this.successHandler = successHandler;
        // }

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
                                                .requestMatchers("/api/v1/auth/**").permitAll()
                                                .anyRequest().authenticated())

                                /* ---------------- SESSION POLICY ---------------- */

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

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