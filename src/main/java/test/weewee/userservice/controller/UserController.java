package test.weewee.userservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import test.weewee.userservice.dto.UpdateUserRequest;
import test.weewee.userservice.dto.UserResponse;
import test.weewee.userservice.model.User;
import test.weewee.userservice.service.AuthService;
import test.weewee.userservice.service.UserService;

import java.util.UUID;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;
    private final AuthService authService;

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(HttpServletRequest request) {
        log.debug("Get current user request");

        return authService.getUserEmailFromRequest(request)
                .flatMap(userService::findByEmail)
                .map(user -> {
                    log.debug("User found: {}", user.getEmail());
                    return mapToUserResponse(user);
                })
                .map(ResponseEntity::ok)
                .orElseGet(() -> {
                    log.warn("Unauthorized access to /users/me");
                    return ResponseEntity.status(401).build();
                });
    }

    @PutMapping("/me")
    public ResponseEntity<?> updateCurrentUser(@Valid @RequestBody UpdateUserRequest request,
                                               HttpServletRequest httpRequest) {
        log.debug("Update user request");

        return authService.getUserEmailFromRequest(httpRequest)
                .flatMap(userService::findByEmail)
                .map(user -> {
                    log.info("Updating user with email: {}", user.getEmail());

                    User updatedUser = new User();
                    updatedUser.setEmail(request.getEmail());
                    updatedUser.setPassword(request.getPassword());
                    updatedUser.setFirstName(request.getFirstName());
                    updatedUser.setLastName(request.getLastName());
                    updatedUser.setPhone(request.getPhone());

                    User result = userService.updateUser(user.getId(), updatedUser);
                    log.info("User updated successfully: {}", result.getEmail());

                    return ResponseEntity.ok().build();
                })
                .orElseGet(() -> {
                    log.warn("Unauthorized attempt to update user");
                    return ResponseEntity.status(401).build();
                });
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