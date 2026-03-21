package com.SpringSecurity.AuthBackend.services.impls;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.SpringSecurity.AuthBackend.dtos.UserDto;
import com.SpringSecurity.AuthBackend.services.AuthService;
import com.SpringSecurity.AuthBackend.services.UserService;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDto registerUser(UserDto userDto) {
        // logic
        // verify email
        // verify password
        // default roles
         userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        return userService.createUser(userDto);
    }

}
