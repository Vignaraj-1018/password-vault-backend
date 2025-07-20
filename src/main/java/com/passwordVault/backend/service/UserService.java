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


    private static final Logger logger = LoggerFactory.getLogger(UserService.class);


    public ResponseEntity<?> register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return new ResponseEntity<>(userRepository.save(user), HttpStatus.CREATED);
    }

    public ResponseEntity<?> loginUser(User user){
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getEmail(),
                            user.getPassword()
                    )
            );

            String accessToken = jwtUtils.generateAccessToken(auth.getName());
            String refreshToken = jwtUtils.generateRefreshToken(auth.getName());

            User existingUser = userRepository.findByEmail(user.getEmail());
            existingUser.setRefreshToken(refreshToken);
            userRepository.save(existingUser);


            return ResponseEntity.ok(Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken
            ));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("AUTH_FAILED");
        }
    }

    public ResponseEntity<?> refreshToken(User user) {
        String refreshToken = user.getRefreshToken();
        User userFromDB = userRepository.findByRefreshToken(refreshToken);

        if (userFromDB == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        try {
            jwtUtils.validateJwtToken(refreshToken);
        } catch (ExpiredJwtException ex) {
            logger.info("Refresh token expired, but rotating anyway");
        } catch (JwtException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "Invalid refresh token"
            ));
        }

        String newAccessToken = jwtUtils.generateAccessToken(userFromDB.getEmail());
        String newRefreshToken = jwtUtils.generateRefreshToken(userFromDB.getEmail());
        System.out.println(newAccessToken);
        System.out.println(newRefreshToken);
        userFromDB.setRefreshToken(newRefreshToken);
        userRepository.save(userFromDB);
        return ResponseEntity.ok(Map.of(
                "refreshToken", newRefreshToken,
                "accessToken", newAccessToken
        ));
    }
}
