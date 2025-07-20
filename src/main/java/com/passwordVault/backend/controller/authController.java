package com.passwordVault.backend.controller;

import com.passwordVault.backend.model.User;
import com.passwordVault.backend.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RequestMapping("/auth")
public class authController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user){
        return userService.register(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody User user){
        return userService.loginUser(user);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody User user){
        return userService.refreshToken(user);
    }

    @PostMapping("/resendOtp")
    public ResponseEntity<?> resendOtp(@RequestBody User user){
        return userService.resendOtp(user);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticateUser(@RequestBody User user){
        return userService.validateOtp(user);
    }

    @PostMapping("/forgotPassword")
    public ResponseEntity<?> forgotPassword(@RequestBody User user){
        return userService.forgotPassword(user);
    }

    @PostMapping("/resetPassword")
    public ResponseEntity<?> resetPassword(@RequestBody User user){
        return userService.resetPassword(user);
    }

}
