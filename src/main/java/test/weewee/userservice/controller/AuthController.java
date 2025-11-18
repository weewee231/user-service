package test.weewee.userservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import test.weewee.userservice.dto.*;
import test.weewee.userservice.model.User;
import test.weewee.userservice.security.JwtUtil;
import test.weewee.userservice.service.AuthService;
import test.weewee.userservice.service.UserService;

import java.util.Optional;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthService authService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Register attempt for email: {}", request.getEmail());

        if (request.getEmail() == null || request.getPassword() == null ||
                request.getFirstName() == null || request.getLastName() == null) {
            log.warn("Registration failed - required fields are missing");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        if (userService.existsByEmail(request.getEmail())) {
            log.warn("Registration failed - email already exists: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhone(request.getPhone());

        User savedUser = userService.createUser(user);
        log.info("User registered successfully with ID: {}", savedUser.getId());

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/auth/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletResponse response) {
        log.info("Login attempt for email: {}", request.getEmail());

        if (request.getEmail() == null || request.getPassword() == null) {
            log.warn("Login failed - email or password is null");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        User user = userService.findByEmail(request.getEmail())
                .orElse(null);

        // Правильная проверка пароля с PasswordEncoder
        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            log.warn("Login failed for email: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        authService.setRefreshTokenCookie(response, refreshToken);

        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken(accessToken);
        tokenResponse.setUser(mapToUserResponse(user));

        log.info("Login successful for user ID: {}", user.getId());
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.getUserEmailFromRequest(request).ifPresent(userEmail ->
                log.info("Logout for user email: {}", userEmail)
        );
        authService.clearRefreshTokenCookie(response);
        log.info("User logged out successfully");
        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<TokenResponse> refresh(HttpServletRequest request, HttpServletResponse response) {
        log.debug("Refresh token attempt");

        Optional<String> refreshTokenOpt = authService.getRefreshTokenFromCookies(request);

        if (refreshTokenOpt.isEmpty()) {
            log.warn("No refresh token in cookies");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String refreshToken = refreshTokenOpt.get();
        if (!jwtUtil.validateToken(refreshToken)) {
            log.warn("Refresh token validation failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        UUID userId = jwtUtil.getUserIdFromToken(refreshToken);
        User user = userService.findById(userId).orElse(null);

        if (user == null) {
            log.warn("User not found for ID: {}", userId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String newAccessToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getId());

        authService.setRefreshTokenCookie(response, newRefreshToken);

        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken(newAccessToken);
        tokenResponse.setUser(mapToUserResponse(user));

        log.info("Token refreshed for user ID: {}", userId);
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/auth/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
                                            HttpServletResponse response) { // ← ДОБАВЛЯЕМ response
        log.info("Password reset request for email: {}", request.getEmail());

        if (request.getEmail() == null || request.getNewPassword() == null) {
            log.warn("Password reset failed - email or new password is null");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        try {
            User user = userService.updatePassword(request.getEmail(), request.getNewPassword());

            authService.invalidateUserTokens(response);

            log.info("Password reset successful for email: {}. All tokens invalidated.", request.getEmail());
            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            log.error("Password reset failed for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    private UserResponse mapToUserResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId().toString());
        response.setEmail(user.getEmail());
        response.setFirstName(user.getFirstName());
        response.setLastName(user.getLastName());
        response.setPhone(user.getPhone());
        response.setRole(user.getRole().name());
        response.setCreatedAt(user.getCreatedAt().toString());
        response.setUpdatedAt(user.getUpdatedAt().toString());
        return response;
    }
}