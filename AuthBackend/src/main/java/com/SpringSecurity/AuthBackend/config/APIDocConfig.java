package com.SpringSecurity.AuthBackend.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Secure Authentication API",
                version = "1.0",
                description = "Generic authentication service with JWT and OAuth2 support.",
                summary = "Reusable authentication backend for any application.",
                contact = @Contact(
                        name = "Swayam Gurnule",
                        email = "swayamgurunule12@gmail.com"
                )
        ),
        security = {
                @SecurityRequirement(name = "bearerAuth")
        }
)

@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'"
)
public class APIDocConfig {
}