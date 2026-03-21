package com.SpringSecurity.AuthBackend.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.SpringSecurity.AuthBackend.dtos.ApiError;
import com.SpringSecurity.AuthBackend.dtos.ErrorResponse;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // ============================================================
    // RESOURCE NOT FOUND EXCEPTION
    // Handles cases when a requested resource is not found
    // Example: User not found with given ID or Email
    // ============================================================
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(
            ResourceNotFoundException exception) {

        ErrorResponse errorResponse = new ErrorResponse(
                exception.getMessage(),
                HttpStatus.NOT_FOUND,
                404
        );

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(errorResponse);
    }



    // ============================================================
    // ILLEGAL ARGUMENT EXCEPTION
    // Handles validation errors like:
    // - Invalid input
    // - Missing required fields
    // ============================================================
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(
            IllegalArgumentException exception) {

        ErrorResponse errorResponse = new ErrorResponse(
                exception.getMessage(),
                HttpStatus.BAD_REQUEST,
                400
        );

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorResponse);
    }



    // ============================================================
    // AUTHENTICATION EXCEPTION HANDLER
    // Can handle Spring Security authentication errors
    // ============================================================
    
    @ExceptionHandler({
            UsernameNotFoundException.class,
            BadCredentialsException.class,
            CredentialsExpiredException.class,
            DisabledException.class
    })
    public ResponseEntity<ApiError> handleAuthException(
            Exception exception,
            HttpServletRequest request) {

        var apiError = ApiError.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                exception.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.badRequest().body(apiError);
    }
    
}