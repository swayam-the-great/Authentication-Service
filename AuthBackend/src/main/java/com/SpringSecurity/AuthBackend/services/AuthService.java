package com.SpringSecurity.AuthBackend.services;


import com.SpringSecurity.AuthBackend.dtos.UserDto;

public interface AuthService {

    UserDto registerUser(UserDto userDto);
} 