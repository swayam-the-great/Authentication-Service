package com.SpringSecurity.AuthBackend.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.stereotype.Service;

import com.SpringSecurity.AuthBackend.repository.UserRepository;

import lombok.RequiredArgsConstructor;



/* =========================================================
                CUSTOM USER DETAILS SERVICE
   ---------------------------------------------------------
   Purpose:
   1. Used by Spring Security to load user from database
   2. Fetch user using email (username)
   3. Return UserDetails implementation (User entity)
   ========================================================= */

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {



    /* =========================================================
                        DEPENDENCIES
       ========================================================= */

    private final UserRepository userRepository;



    /* =========================================================
                LOAD USER BY USERNAME (EMAIL)
       ---------------------------------------------------------
       This method is automatically called by Spring Security
       during authentication (login process).
       ========================================================= */

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        return userRepository
                .findByEmail(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                "User not found with email: " + username
                        )
                );
    }

}