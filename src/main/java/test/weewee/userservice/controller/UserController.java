package test.weewee.userservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import test.weewee.userservice.dto.ErrorResponse;
import test.weewee.userservice.dto.UpdateUserRequest;
import test.weewee.userservice.dto.UserResponse;
import test.weewee.userservice.exception.AuthException;
import test.weewee.userservice.model.User;
import test.weewee.userservice.security.JwtUtil;
import test.weewee.userservice.service.AuthenticationService;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final AuthenticationService authenticationService;
    private final JwtUtil jwtUtil;

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(HttpServletRequest request) {
        log.debug("GET /users/me - get current user");

        String userEmail = extractUserEmailFromRequest(request);
        if (userEmail == null) {
            log.warn("Unauthorized access to /users/me");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            User user = authenticationService.getCurrentUser(userEmail);
            UserResponse userResponse = mapToUserResponse(user);
            log.debug("User found: {}", user.getEmail());
            return ResponseEntity.ok(userResponse);
        } catch (Exception e) {
            log.warn("User not found: {}", userEmail);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PutMapping("/me")
    public ResponseEntity<?> updateCurrentUser(
            HttpServletRequest request,
            @Valid @RequestBody UpdateUserRequest updateRequest) {
        log.debug("PUT /users/me - update current user");

        String userEmail = extractUserEmailFromRequest(request);
        if (userEmail == null) {
            log.warn("Unauthorized attempt to update user");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {

            User updatedUser = authenticationService.updateUser(userEmail, updateRequest);
            UserResponse userResponse = mapToUserResponse(updatedUser);

            log.info("User updated successfully: {}", updatedUser.getEmail());
            return ResponseEntity.ok(userResponse);
        } catch (AuthException e) {
            log.error("Update user failed - auth error: {}", userEmail, e);
            // ДЛЯ ОШИБОК ОБНОВЛЕНИЯ (дубликаты email/phone)
            if (e.getMessage().contains("email")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ErrorResponse.of("Ошибка обновления пользователя", Map.of("email", e.getMessage())));
            } else if (e.getMessage().contains("телефон")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ErrorResponse.of("Ошибка обновления пользователя", Map.of("phone", e.getMessage())));
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ErrorResponse.of("Ошибка обновления пользователя", "error", e.getMessage()));
            }
        } catch (Exception e) {
            log.error("Update user failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ErrorResponse.of("Ошибка обновления пользователя", "error", e.getMessage()));
        }
    }

    private String extractUserEmailFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            // ОЧИСТКА ТОКЕНА ОТ КАВЫЧЕК
            token = cleanToken(token);
            if (jwtUtil.validateToken(token)) {
                return jwtUtil.getEmailFromToken(token);
            }
        }
        return null;
    }

    /**
     * Очищает токен от кавычек и лишних символов
     */
    private String cleanToken(String token) {
        if (token == null) {
            return null;
        }

        String cleaned = token;

        // 1. Убираем ВСЕ кавычки (двойные и одинарные)
        cleaned = cleaned.replaceAll("[\"']", "");

        // 2. Убираем пробелы
        cleaned = cleaned.trim();

        // 3. Убираем слово "Bearer" если оно есть повторно
        cleaned = cleaned.replaceAll("(?i)bearer", "").trim();

        // 4. Убираем любые не-JWT символы в начале/конце
        cleaned = cleaned.replaceAll("^[^A-Za-z0-9]+|[^A-Za-z0-9]+$", "");

        return cleaned;
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