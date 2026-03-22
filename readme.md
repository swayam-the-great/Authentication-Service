# 🔐 Secure Authentication Service

A **production-grade authentication backend** built with **Spring Boot** and **Spring Security**.

This service provides **secure, scalable, and stateless authentication** using **JWT Access Tokens** and **Refresh Tokens with rotation**.
It follows **modern backend security practices used in real-world production systems**.

---

# 🚀 Features

✅ **JWT-based stateless authentication**
✅ **Access Token** for API authorization
✅ **Refresh Token with secure rotation**
✅ **HTTP-only secure cookies** for refresh tokens
✅ **Token revocation & reuse detection**
✅ **Secure logout with token invalidation**
✅ **Password hashing using BCrypt**
✅ **OAuth2 social login (Google & GitHub)**
✅ **Custom authentication filters**
✅ **Centralized security exception handling**
✅ **RESTful authentication APIs**
✅ **Scalable layered architecture**

---

# 🔑 Authentication Flow

The authentication system follows a **secure token lifecycle**:

1. User logs in with **email and password**
2. Credentials are verified using **Spring Security**
3. **Access Token (short-lived)** is generated
4. **Refresh Token (long-lived)** is stored in the database
5. Refresh Token is stored in a **secure HTTP-only cookie**
6. Client uses **Access Token** to access protected APIs
7. When the Access Token expires, the **Refresh Token generates a new Access Token**
8. **Refresh Token rotation** prevents token reuse attacks

---

# 🛡️ Security Features

🔒 **Stateless authentication architecture**
🔒 **Refresh tokens stored securely in database**
🔒 **Refresh token rotation for enhanced security**
🔒 **Token revocation support**
🔒 **HTTP-only secure cookies**
🔒 **BCrypt password encryption**
🔒 **Protection against token theft**
🔒 **Custom authentication filters**
🔒 **Secure logout implementation**

---

# 🌐 OAuth2 Authentication

This service supports **social login authentication**:

🔵 **Google OAuth2**
⚫ **GitHub OAuth2**

Users can authenticate using their **social accounts** and receive **JWT tokens for secure API access**.

---

# ⚙️ Tech Stack

### 🧩 Backend Framework

* ☕ **Spring Boot**

### 🔐 Security

* 🛡 **Spring Security**
* 🔑 **JWT (JSON Web Tokens)**
* 🌐 **OAuth2 Authentication**

### 🗄 Database

* 📦 **JPA / Hibernate**
* 🐬 **MySQL**

### 🧰 Utilities

* 🔧 **ModelMapper**
* ⚡ **Lombok**

### 📦 Build Tool

* 📦 **Maven**

---

# 📂 Project Structure

```
src/main/java/com/SpringSecurity/AuthBackend

├── config
│   └── Security configuration

├── controllers
│   └── Authentication REST APIs

├── entities
│   ├── User
│   └── RefreshToken

├── repositories
│   ├── UserRepository
│   └── RefreshTokenRepository

├── security
│   ├── JwtAuthenticationFilter
│   ├── OAuth2SuccessHandler
│   ├── CookieService
│   └── JwtService

├── services
│   ├── AuthService
│   ├── UserService
│   └── RefreshTokenService

└── utils
    └── Security utilities
```

---

# 🔌 API Endpoints

### Authentication APIs

| Method | Endpoint         | Description                 |
| ------ | ---------------- | --------------------------- |
| POST   | `/auth/register` | Register new user           |
| POST   | `/auth/login`    | Login with email & password |
| POST   | `/auth/refresh`  | Generate new access token   |
| POST   | `/auth/logout`   | Logout and revoke tokens    |

---

# 🔄 OAuth2 Login

Start OAuth login using:

```
http://localhost:8081/oauth2/authorization/google
```

or

```
http://localhost:8081/oauth2/authorization/github
```

After successful authentication, the backend:

1. Retrieves user information
2. Creates a user if not existing
3. Generates JWT access token
4. Generates refresh token
5. Stores refresh token in database
6. Sends refresh token as **HTTP-only cookie**

---

# 🏗️ Architecture

The application follows a **layered architecture**:

```
Controller Layer
        ↓
Service Layer
        ↓
Repository Layer
        ↓
Database
```

Security is handled using:

```
Spring Security Filters
        ↓
JWT Authentication
        ↓
OAuth2 Login
        ↓
Token Services
```

---

# 🔮 Future Improvements

🚀 Email verification
🚀 Two-Factor Authentication (2FA)
🚀 Rate limiting for authentication APIs
🚀 Account lock after multiple failed login attempts
🚀 Additional OAuth providers (Apple, LinkedIn)

---

# 👨‍💻 Author

**Swayam Gurnule**
Electronics & Telecommunication Engineering Student
Backend & Security Enthusiast 🚀

---

⭐ If you find this project useful, consider **starring the repository**!
