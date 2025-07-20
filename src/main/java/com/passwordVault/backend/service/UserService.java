package com.passwordVault.backend.service;

import com.passwordVault.backend.config.Jwt.JwtUtils;
import com.passwordVault.backend.model.User;
import com.passwordVault.backend.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private EmailService emailService;


    private static final Logger logger = LoggerFactory.getLogger(UserService.class);


    public ResponseEntity<?> register(User user) {
        if(userRepository.existsByEmail(user.getEmail())){
            logger.info("User Already Exists: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User Already Exists");
        }

        String rawPassword = user.getPassword();
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        logger.info("User Creation Started: {}", user.getEmail());

        user.setOtp(emailService.generateOTP());
        user.setAuthenticated(false);
        userRepository.save(user);

        user.setPassword(rawPassword);
        Thread emailThread = new Thread(() -> emailService.sendEmailOTP(user));
        emailThread.start();

        return loginUser(user);
    }

    public ResponseEntity<?> loginUser(User user){
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getEmail(),
                            user.getPassword()
                    )
            );

            logger.info("User Authentication Successful: {}", user.getEmail());

            String accessToken = jwtUtils.generateAccessToken(auth.getName());
            String refreshToken = jwtUtils.generateRefreshToken(auth.getName());

            User existingUser = userRepository.findByEmail(user.getEmail());
            existingUser.setRefreshToken(refreshToken);
            userRepository.save(existingUser);
            logger.info("Tokens Generated: {}", user.getEmail());


            return ResponseEntity.ok(Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken
            ));
        } catch (AuthenticationException ex) {
            logger.info("User Authentication Failed: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("AUTH_FAILED");
        }
    }

    public ResponseEntity<?> refreshToken(User user) {
        String refreshToken = user.getRefreshToken();
        User userFromDB = userRepository.findByRefreshToken(refreshToken);

        if (userFromDB == null) {
            logger.info("User not found or Invalid refresh token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        try {
            jwtUtils.validateJwtToken(refreshToken);
            logger.info("Refresh token Validated: {}", userFromDB.getEmail());
        } catch (ExpiredJwtException ex) {
            logger.info("Refresh token expired, but rotating anyway: {}", userFromDB.getEmail());
        } catch (JwtException ex) {
            logger.info("Invalid refresh token: {}", userFromDB.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "Invalid refresh token"
            ));
        }

        String newAccessToken = jwtUtils.generateAccessToken(userFromDB.getEmail());
        String newRefreshToken = jwtUtils.generateRefreshToken(userFromDB.getEmail());
        userFromDB.setRefreshToken(newRefreshToken);
        userRepository.save(userFromDB);
        logger.info("New tokens updated: {}", userFromDB.getEmail());
        return ResponseEntity.ok(Map.of(
                "refreshToken", newRefreshToken,
                "accessToken", newAccessToken
        ));
    }

    public ResponseEntity<?> resendOtp(User user) {
        User userFromDb = userRepository.findByEmail(user.getEmail());

        if(userFromDb == null){
            logger.info("User Not Found: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User Not Found");
        } else if (userFromDb.authenticated) {
            logger.info("User Already Authenticated: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User Already Authenticated");
        }

        userFromDb.setOtp(emailService.generateOTP());
        userRepository.save(userFromDb);
        logger.info("New OTP generated for User: {}", userFromDb.getEmail());

        Thread emailThread = new Thread(() -> emailService.sendEmailOTP(userFromDb));
        emailThread.start();

        return ResponseEntity.status(HttpStatus.OK).body("Resend OTP Successful");
    }

    public ResponseEntity<?> validateOtp(User user) {
        User userFromDb = userRepository.findByEmail(user.getEmail());

        if(userFromDb == null){
            logger.info("User Not Found: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User Not Found");
        } else if (userFromDb.authenticated) {
            logger.info("User Already Authenticated: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User Already Authenticated");
        } else if (userFromDb.getOtp() == user.getOtp()) {
            logger.info("Otp Matched: {}", user.getOtp());
            userFromDb.setAuthenticated(true);
            userRepository.save(userFromDb);
            logger.info("OTP Validation Successful: {}", userFromDb.getEmail());
            return ResponseEntity.status(HttpStatus.OK).body("OTP Validation Successful");
        } else {
            logger.info("Otp Mismatch: {}", user.getOtp());
            return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body("OTP Validation Failed");
        }
    }
}
