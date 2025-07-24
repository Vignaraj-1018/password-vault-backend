package com.passwordVault.backend.model;

import com.passwordVault.backend.config.InputValidations.*;
import jakarta.validation.constraints.*;
import jakarta.validation.constraints.Email;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;


@Document(collection = "users")
@Data
public class User {
    @Id
    private String id;

    @NotBlank(message = "Username is Required", groups = {OnRegister.class})
    private String username;

    @NotBlank(message = "Email is Required", groups = {OnRegister.class, OnLogin.class, OnValidateOtp.class, OnForgotPassword.class, OnResetPassword.class, OnResendOtp.class})
    @Email(message = "Invalid Email", groups = {OnRegister.class, OnLogin.class, OnValidateOtp.class, OnForgotPassword.class, OnResetPassword.class, OnResendOtp.class})
    private String email;

    @NotBlank(message = "Password is Required", groups = {OnRegister.class, OnLogin.class, OnResetPassword.class})
    private String password;

    @NotBlank(message = "Refresh token is Required", groups = {OnRefreshToken.class})
    private String refreshToken;

    @NotNull(message = "OTP is Required", groups = {OnValidateOtp.class})
    @Min(value = 100000, groups = OnValidateOtp.class, message = "OTP must be 6 digits")
    @Max(value = 999999, groups = OnValidateOtp.class, message = "OTP must be 6 digits")
    private int otp;

    public boolean authenticated;
}