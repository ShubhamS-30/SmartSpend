package com.shubhamsahu.auth_service.service;

import com.shubhamsahu.auth_service.entity.User;
import com.shubhamsahu.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;

    /**
     * Find user by Google ID
     */
    public Optional<User> findByGoogleId(String googleId) {
        return userRepository.findByGoogleId(googleId);
    }

    /**
     * Find user by email
     */
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Create or update user from Google OAuth credentials
     */
    public User createOrUpdateUser(String googleId, String email, String name, String picture) {
        log.info(String.format("Creating or updating user with Google ID: %s", googleId));
        
        User user = userRepository.findByGoogleId(googleId)
                .orElseGet(() -> User.builder()
                        .googleId(googleId)
                        .email(email)
                        .build());
        
        user.setName(name);
        user.setPicture(picture);
        
        return userRepository.save(user);
    }

    /**
     * Find user by ID
     */
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    /**
     * Save user
     */
    public User saveUser(User user) {
        return userRepository.save(user);
    }
}


