package com.SpringSecurity.AuthBackend.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.SpringSecurity.AuthBackend.dtos.UserDto;
import com.SpringSecurity.AuthBackend.services.UserService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/v1/users")
@AllArgsConstructor
public class UserController {

    // Service layer dependency
    private final UserService userService;



    // ============================================================
    // CREATE USER
    // Endpoint: POST /api/v1/users
    // ============================================================
    @PostMapping
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto) {

        UserDto createdUser = userService.createUser(userDto);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(createdUser);
    }



    // ============================================================
    // GET ALL USERS
    // Endpoint: GET /api/v1/users
    // ============================================================
    @GetMapping
    public ResponseEntity<Iterable<UserDto>> getAllUsers() {

        Iterable<UserDto> users = userService.getAllUsers();

        return ResponseEntity.ok(users);
    }



    // ============================================================
    // GET USER BY EMAIL
    // Endpoint: GET /api/v1/users/email/{email}
    // ============================================================
    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> getUserByEmail(
            @PathVariable("email") String email) {

        UserDto user = userService.getUserByEmail(email);

        return ResponseEntity.ok(user);
    }



    // ============================================================
    // DELETE USER
    // Endpoint: DELETE /api/v1/users/{userId}
    // ============================================================
    @DeleteMapping("/{userId}")
    public void deleteUser(
            @PathVariable("userId") String userId) {

        userService.deleteUser(userId);
    }



    // ============================================================
    // UPDATE USER
    // Endpoint: PUT /api/v1/users/{userId}
    // ============================================================
    @PutMapping("/{userId}")
    public ResponseEntity<UserDto> updateUser(
            @RequestBody UserDto userDto,
            @PathVariable("userId") String userId) {

        UserDto updatedUser = userService.updateUser(userDto, userId);

        return ResponseEntity.ok(updatedUser);
    }



    // ============================================================
    // GET USER BY ID
    // Endpoint: GET /api/v1/users/{userId}
    // ============================================================
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserById(
            @PathVariable("userId") String userId) {

        UserDto user = userService.getUserById(userId);

        return ResponseEntity.ok(user);
    }

}