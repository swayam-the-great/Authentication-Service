package com.SpringSecurity.AuthBackend.services.impls;

import java.time.Instant;
import java.util.UUID;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import com.SpringSecurity.AuthBackend.dtos.UserDto;
import com.SpringSecurity.AuthBackend.entities.User;
import com.SpringSecurity.AuthBackend.enums.Provider;
import com.SpringSecurity.AuthBackend.exceptions.ResourceNotFoundException;
import com.SpringSecurity.AuthBackend.helpers.UserHelper;
import com.SpringSecurity.AuthBackend.repository.UserRepository;
import com.SpringSecurity.AuthBackend.services.UserService;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    // Repository to interact with database
    private final UserRepository userRepository;

    // ModelMapper used to convert Entity <-> DTO
    private final ModelMapper modelMapper;



    // ============================================================
    // CREATE USER
    // ============================================================
    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        // Validate email
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }

        // Check if user already exists
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("User with given email already exists");
        }

        // Convert DTO -> Entity
        User user = modelMapper.map(userDto, User.class);

        // Set provider (LOCAL if not provided)
        user.setProvider(
                userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL
        );

        // TODO: assign roles to user for authorization

        // Save user to database
        user = userRepository.save(user);

        // Convert Entity -> DTO
        return modelMapper.map(user, UserDto.class);
    }



    // ============================================================
    // GET USER BY EMAIL
    // ============================================================
    @Override
    public UserDto getUserByEmail(String email) {

        User user = userRepository
                .findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User with given email not found !!")
                );

        return modelMapper.map(user, UserDto.class);
    }



    // ============================================================
    // UPDATE USER
    // ============================================================
    @Override
    public UserDto updateUser(UserDto userDto, String userId) {

        // Convert String ID -> UUID
        UUID uId = UserHelper.parseUUID(userId);

        // Fetch existing user
        User existingUser = userRepository
                .findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with given id"));

        // Email is NOT updated in this project

        // Update fields if provided
        if (userDto.getName() != null) {
            existingUser.setName(userDto.getName());
        }

        if (userDto.getImage() != null) {
            existingUser.setImage(userDto.getImage());
        }

        if (userDto.getProvider() != null) {
            existingUser.setProvider(userDto.getProvider());
        }

        // TODO: implement proper password update logic
        if (userDto.getPassword() != null) {
            existingUser.setPassword(userDto.getPassword());
        }

        // Enable / Disable user
        existingUser.setEnable(userDto.isEnable());

        // Update modification time
        existingUser.setUpdatedAt(Instant.now());

        // Save updated user
        User updatedUser = userRepository.save(existingUser);

        return modelMapper.map(updatedUser, UserDto.class);
    }


    // ============================================================
    // DELETE USER
    // ============================================================
    @Override
    public void deleteUser(String userId) {

        UUID uId = UserHelper.parseUUID(userId);

        User user = userRepository
                .findById(uId)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with given id")
                );

        userRepository.delete(user);
    }



    // ============================================================
    // GET USER BY ID
    // ============================================================
    @Override
    public UserDto getUserById(String userId) {

        User user = userRepository
                .findById(UserHelper.parseUUID(userId))
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with given id")
                );

        return modelMapper.map(user, UserDto.class);
    }



    // ============================================================
    // GET ALL USERS
    // ============================================================
    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {

        return userRepository
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }
}