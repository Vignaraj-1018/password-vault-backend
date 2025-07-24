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
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("message","User Already Exists"));
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
                    "refreshToken", refreshToken,
                    "message", "User Authentication Successful"
            ));
        } catch (AuthenticationException ex) {
            logger.info("User Authentication Failed: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error","User Authentication Failed"));
        }
    }

    public ResponseEntity<?> refreshToken(User user) {
        String refreshToken = user.getRefreshToken();
        User userFromDB = userRepository.findByRefreshToken(refreshToken);

        if (userFromDB == null) {
            logger.info("User not found or Invalid refresh token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error","Invalid refresh token"));
        }

        try {
            jwtUtils.validateJwtToken(refreshToken);
            String newAccessToken = jwtUtils.generateAccessToken(userFromDB.getEmail());
            logger.info("Refresh token Validated: {}", userFromDB.getEmail());
            return ResponseEntity.ok(Map.of(
                    "accessToken", newAccessToken,
                    "message", "Refresh token Validated"
            ));
        } catch (ExpiredJwtException ex) {
            logger.info("Refresh token expired: {}", userFromDB.getEmail());
            userFromDB.setRefreshToken(null);
            userRepository.save(userFromDB);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error","Refresh token expired, Please Login Again"));
        } catch (JwtException ex) {
            logger.info("Invalid refresh token: {}", userFromDB.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error","Invalid refresh token"));
        }
    }

    public ResponseEntity<?> resendOtp(User user) {
        User userFromDb = userRepository.findByEmail(user.getEmail());

        if(userFromDb == null){
            logger.info("User Not Found: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error","User Not Found"));
        } else if (userFromDb.authenticated) {
            logger.info("User Already Authenticated: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error","User Already Authenticated"));
        }

        userFromDb.setOtp(emailService.generateOTP());
        userRepository.save(userFromDb);
        logger.info("New OTP generated for User: {}", userFromDb.getEmail());

        Thread emailThread = new Thread(() -> emailService.sendEmailOTP(userFromDb));
        emailThread.start();

        return ResponseEntity.status(HttpStatus.OK).body(Map.of("message","Resend OTP Successful"));
    }

    public ResponseEntity<?> validateOtp(User user) {
        User userFromDb = userRepository.findByEmail(user.getEmail());

        if(userFromDb == null){
            logger.info("User Not Found: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error","User Not Found"));
        } else if (userFromDb.authenticated) {
            logger.info("User Already Authenticated: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error","User Already Authenticated"));
        } else if (userFromDb.getOtp() == user.getOtp()) {
            logger.info("Otp Matched: {}", user.getOtp());
            userFromDb.setAuthenticated(true);
            userRepository.save(userFromDb);
            logger.info("OTP Validation Successful: {}", userFromDb.getEmail());
            return ResponseEntity.status(HttpStatus.OK).body(Map.of("message","OTP Validation Successful"));
        } else {
            logger.info("Otp Mismatch: {}", user.getOtp());
            return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(Map.of("error","OTP Validation Failed"));
        }
    }

    public ResponseEntity<?> forgotPassword(User user) {
        User userFromDb = userRepository.findByEmail(user.getEmail());

        if(userFromDb == null){
            logger.info("User Not Found: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error","User Not Found"));
        } else {
            userFromDb.setOtp(emailService.generateOTP());
            Thread thread = new Thread(() -> emailService.sendEmailOTP(userFromDb));
            thread.start();
            userFromDb.setAuthenticated(false);
            userRepository.save(userFromDb);
            logger.info("OTP Sent Successfully: {}", userFromDb.getEmail());
            return ResponseEntity.status(HttpStatus.OK).body(Map.of("message","OTP Sent Successfully, Validate Email to Continue"));
        }
    }

    public ResponseEntity<?> resetPassword(User user) {
        User userFromDb = userRepository.findByEmail(user.getEmail());

        if(userFromDb == null){
            logger.info("User Not Found: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error","User Not Found"));
        } else if (userFromDb.authenticated) {
            userFromDb.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepository.save(userFromDb);
            logger.info("Reset Password Successful: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.OK).body(Map.of("message","Reset Password Successful"));
        }
        else{
            logger.info("User is Not Authenticated: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(Map.of("error","User is not Authenticated"));
        }
    }
}
