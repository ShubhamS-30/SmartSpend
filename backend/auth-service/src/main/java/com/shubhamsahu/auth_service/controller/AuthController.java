package com.shubhamsahu.auth_service.controller;

import com.shubhamsahu.auth_service.dto.AuthResponse;
import com.shubhamsahu.auth_service.dto.UserInfo;
import com.shubhamsahu.auth_service.entity.User;
import com.shubhamsahu.auth_service.security.JwtTokenProvider;
import com.shubhamsahu.auth_service.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * OAuth2 Login Success Handler
     * This endpoint is called after successful Google OAuth login
     */
    @GetMapping("/success")
    public ResponseEntity<AuthResponse> loginSuccess(@AuthenticationPrincipal OAuth2User principal) {
        // principal may be null depending on how the request was forwarded. Try SecurityContextHolder as a fallback
        OAuth2User oauthUser = principal;
        if (oauthUser == null) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof OAuth2User) {
                oauthUser = (OAuth2User) auth.getPrincipal();
            }
        }

        if (oauthUser == null) {
            log.warn(String.format("OAuth2 login success called but no principal found"));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String email = (String) oauthUser.getAttribute("email");
        log.info(String.format("OAuth2 login successful for user: %s", email));

        // Extract user information from OAuth2Principal
        String googleId = oauthUser.getName();
        String name = (String) oauthUser.getAttribute("name");
        String picture = (String) oauthUser.getAttribute("picture");
        
        // Create or update user in database
        User user = userService.createOrUpdateUser(googleId, email, name, picture);
        
        // Generate JWT token
        String accessToken = jwtTokenProvider.generateToken(
            String.valueOf(user.getId()),
            user.getEmail(),
            user.getName()
        );
        
        long expiresIn = jwtTokenProvider.getJwtExpirationMs() / 1000L;
        
        // Build response
        UserInfo userInfo = UserInfo.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .picture(user.getPicture())
                .build();
        
        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .user(userInfo)
                .build();
        
        return ResponseEntity.ok(authResponse);
    }

    /**
     * OAuth2 Login Failure Handler
     */
    @GetMapping("/failure")
    public ResponseEntity<Map<String, String>> loginFailure() {
        log.error(String.format("OAuth2 login failed"));
        Map<String, String> response = new HashMap<>();
        response.put("error", "Login failed");
        response.put("message", "Failed to authenticate with Google");
        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Validate JWT Token
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestHeader("Authorization") String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            Map<String, Object> response = new HashMap<>();
            response.put("valid", false);
            response.put("message", "Invalid token format");
            return ResponseEntity.badRequest().body(response);
        }
        
        String jwtToken = token.substring(7);
        
        if (jwtTokenProvider.validateToken(jwtToken)) {
            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("userId", jwtTokenProvider.getUserIdFromToken(jwtToken));
            response.put("email", jwtTokenProvider.getEmailFromToken(jwtToken));
            response.put("name", jwtTokenProvider.getNameFromToken(jwtToken));
            return ResponseEntity.ok(response);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("valid", false);
        response.put("message", "Invalid or expired token");
        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Get Current User Info from JWT Token
     */
    @GetMapping("/me")
    public ResponseEntity<UserInfo> getCurrentUser(@RequestHeader("Authorization") String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().build();
        }
        
        String jwtToken = token.substring(7);
        
        if (!jwtTokenProvider.validateToken(jwtToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        String email = jwtTokenProvider.getEmailFromToken(jwtToken);
        String name = jwtTokenProvider.getNameFromToken(jwtToken);
        String userId = jwtTokenProvider.getUserIdFromToken(jwtToken);
        
        var user = userService.findByEmail(email);
        if (user.isPresent()) {
            UserInfo userInfo = UserInfo.builder()
                    .id(user.get().getId())
                    .email(user.get().getEmail())
                    .name(user.get().getName())
                    .picture(user.get().getPicture())
                    .build();
            return ResponseEntity.ok(userInfo);
        }
        
        return ResponseEntity.notFound().build();
    }

    /**
     * Logout endpoint
     * This is a simple endpoint that confirms logout on client side
     * Token invalidation is handled on the client by removing the token
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String token) {
        log.info(String.format("User logout"));
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Logout successful");
        response.put("status", "success");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Refresh Token
     * Generates a new token using user information from current token
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestHeader("Authorization") String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().build();
        }
        
        String jwtToken = token.substring(7);
        
        if (!jwtTokenProvider.validateToken(jwtToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        String userId = jwtTokenProvider.getUserIdFromToken(jwtToken);
        String email = jwtTokenProvider.getEmailFromToken(jwtToken);
        String name = jwtTokenProvider.getNameFromToken(jwtToken);
        
        // Generate new token
        String newAccessToken = jwtTokenProvider.generateToken(userId, email, name);
        
        var user = userService.findByEmail(email);
        if (user.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        UserInfo userInfo = UserInfo.builder()
                .id(user.get().getId())
                .email(user.get().getEmail())
                .name(user.get().getName())
                .picture(user.get().getPicture())
                .build();
        
        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(newAccessToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getJwtExpirationMs() / 1000L)
                .user(userInfo)
                .build();
        
        return ResponseEntity.ok(authResponse);
    }
}







