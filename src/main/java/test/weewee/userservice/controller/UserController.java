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
import test.weewee.userservice.model.User;
import test.weewee.userservice.security.JwtUtil;
import test.weewee.userservice.service.AuthenticationService;

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
            authenticationService.updateUser(userEmail, updateRequest);
            log.info("User updated successfully: {}", userEmail);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Update user failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ErrorResponse.of("error", e.getMessage()));
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