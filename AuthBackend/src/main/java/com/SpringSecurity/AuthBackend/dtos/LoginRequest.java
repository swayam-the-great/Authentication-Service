package com.SpringSecurity.AuthBackend.dtos;

public record LoginRequest(
        String email,
        String password
) {
}