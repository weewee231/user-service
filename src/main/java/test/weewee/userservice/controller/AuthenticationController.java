package test.weewee.userservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import test.weewee.userservice.dto.*;
import test.weewee.userservice.model.User;
import test.weewee.userservice.security.JwtUtil;
import test.weewee.userservice.service.AuthenticationService;
import test.weewee.userservice.service.CookieService;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final CookieService cookieService;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        log.info("POST /auth/register - registration attempt for: {}", request.getEmail());

        try {
            User registeredUser = authenticationService.signup(request);
            log.info("Registration successful for: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (Exception e) {
            log.error("Registration failed for: {}", request.getEmail(), e);

            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        log.info("POST /auth/login - login attempt for: {}", request.getEmail());

        try {
            AuthResponse authResponse = authenticationService.authenticate(request);

            // Устанавливаем refreshToken в cookie
            String refreshTokenCookie = cookieService.createCookie(
                    "refreshToken",
                    authResponse.getRefreshToken(),
                    Duration.ofDays(7)
            );

            // Создаем ответ без refreshToken в body (только в cookie)
            LoginResponse loginResponse = LoginResponse.builder()
                    .user(authResponse.getUser())
                    .accessToken(authResponse.getAccessToken())
                    .build();

            log.info("Login successful for: {}", request.getEmail());
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookie)
                    .body(loginResponse);
        } catch (Exception e) {
            log.error("Login failed for: {}", request.getEmail(), e);

            Map<String, String> errors = new HashMap<>();
            errors.put("error", e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errors);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        log.info("POST /auth/logout - logout attempt");

        try {
            String userEmail = extractUserEmailFromRequest(request);
            if (userEmail != null) {
                authenticationService.logout(userEmail);
            }

            // Удаляем refreshToken из cookie
            String logoutCookie = cookieService.deleteCookie("refreshToken");

            log.info("Logout successful for: {}", userEmail);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, logoutCookie)
                    .build();
        } catch (Exception e) {
            log.error("Logout failed", e);
            return ResponseEntity.badRequest().body("Ошибка при выходе: " + e.getMessage());
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(HttpServletRequest request) {
        log.info("POST /auth/refresh - refresh token attempt");

        try {
            // Получаем refreshToken из cookies
            String refreshToken = getRefreshTokenFromCookies(request);
            if (refreshToken == null) {
                log.warn("No refresh token in cookies");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            log.debug("Refresh token found in cookies, length: {}", refreshToken.length());

            AuthResponse authResponse = authenticationService.refreshToken(refreshToken);

            // Создаем ответ только с accessToken и user
            RefreshResponse refreshResponse = RefreshResponse.builder()
                    .accessToken(authResponse.getAccessToken())
                    .user(authResponse.getUser())
                    .build();

            log.info("Refresh successful for user: {}", authResponse.getUser().getEmail());
            return ResponseEntity.ok(refreshResponse);

        } catch (Exception e) {
            log.error("Refresh failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        log.info("POST /auth/forgot-password - password reset attempt for: {}", request.getEmail());

        try {
            authenticationService.updatePassword(request);
            log.info("Password reset successful for: {}", request.getEmail());
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Password reset failed for: {}", request.getEmail(), e);

            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    private String extractUserEmailFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtUtil.validateToken(token)) {
                return jwtUtil.getEmailFromToken(token);
            }
        }
        return null;
    }

    private String getRefreshTokenFromCookies(HttpServletRequest request) {
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            log.debug("No cookies in request");
            return null;
        }

        log.debug("Found {} cookies in request", cookies.length);
        for (jakarta.servlet.http.Cookie cookie : cookies) {
            log.debug("Cookie: {} = {}...", cookie.getName(),
                    cookie.getValue() != null && cookie.getValue().length() > 10 ?
                            cookie.getValue().substring(0, 10) + "..." : cookie.getValue());
            if ("refreshToken".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        log.debug("Refresh token cookie not found");
        return null;
    }
}