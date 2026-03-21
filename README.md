#BACKEND


# Secure Authentication Service

A **production-grade authentication backend** built with Spring Boot and Spring Security.  
This service provides **secure, scalable, and stateless authentication** using JWT access tokens and refresh tokens with rotation.

The system is designed to follow **modern backend security practices** used in production environments.

---

## Features

- JWT-based stateless authentication
- Access Token for API authorization
- Refresh Token with secure rotation
- HTTP-only secure cookies for refresh tokens
- Token revocation and reuse detection
- Secure logout with token invalidation
- Password hashing using BCrypt
- OAuth2 social login
- Custom authentication filter
- Centralized security exception handling
- RESTful authentication APIs
- Scalable layered architecture

---

## Authentication Flow

1. User logs in with email and password
2. Credentials are verified using Spring Security
3. Access Token (short-lived) is generated
4. Refresh Token (long-lived) is stored in the database
5. Refresh Token is stored in a secure HTTP-only cookie
6. Client uses Access Token to access protected APIs
7. When Access Token expires, Refresh Token generates a new one
8. Refresh Token rotation prevents token reuse attacks

---

## Security Features

- Stateless authentication architecture
- Refresh token stored in database
- Refresh token rotation
- Token revocation support
- HTTP-only secure cookies
- BCrypt password encryption
- Protection against token theft
- Custom authentication filters
- Secure logout implementation

---

## OAuth2 Authentication

This service supports social login via:

- Google OAuth2
- GitHub OAuth2

Users can authenticate using their social accounts and receive JWT tokens for API access.

---

## Tech Stack

Backend Framework:
- Spring Boot

Security:
- Spring Security
- JWT (JSON Web Tokens)
- OAuth2 Authentication

Database:
- JPA / Hibernate

Utilities:
- ModelMapper
- Lombok

Build Tool:
- Maven

---

## Project Structure
