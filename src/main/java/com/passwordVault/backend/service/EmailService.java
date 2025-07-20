package com.passwordVault.backend.service;

import com.passwordVault.backend.model.Email;
import com.passwordVault.backend.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import jakarta.mail.internet.MimeMessage;
import org.springframework.stereotype.Service;

import java.util.Properties;
import java.util.Random;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Value("${spring.smtp.host}")
    private String mailHost;

    @Value("${spring.smtp.port}")
    private int mailPort;

    @Value("${spring.smtp.username}")
    private String mailUsername;

    @Value("${spring.smtp.password}")
    private String mailPassword;

    public JavaMailSender getJavaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(mailHost);
        mailSender.setPort(mailPort);

        mailSender.setUsername(mailUsername);
        mailSender.setPassword(mailPassword);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "false");

        return mailSender;
    }

    public void sendEmail(Email emailMsg){

        logger.info("Sending Email to {}", emailMsg.getMail());
        try{
            MimeMessage mimeMessage = getJavaMailSender().createMimeMessage();
            MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage, true, "utf-8");
            mimeMessage.setContent(emailMsg.getMessage(), "text/html;charset=utf-8");
            messageHelper.setFrom("noreply@baeldung.com");
            messageHelper.setSubject(emailMsg.getSubject());
            messageHelper.setTo(emailMsg.getMail());
            getJavaMailSender().send(mimeMessage);

            logger.info("Email Sent Successfully: {}", emailMsg.getMail());
        }
        catch (Exception e){
            logger.info("Exception in Sending Message: {}", e.getMessage());
        }
    }


    public int generateOTP() {
        int otpLength = 6;

        Random random = new Random();
        int otp = 0;

        for (int i = 0; i < otpLength; i++) {
            otp = otp * 10 + random.nextInt(10);
        }

        return otp;
    }

    public void sendEmailOTP(User user){

        Email emailMsg = Email.builder()
                .name(user.getUsername())
                .mail(user.getEmail())
                .subject("Welcome to Password Vault")
                .message("<div style='padding:20px;'><div><span style='font-size:20px;'> Hello, <span style='font-size:20px; font-weight: bold;'>"+user.getUsername()+"</span></span><h3 style='font-size:20px; font-weight: normal;'>Here's Your OTP Code for Email Validation: <span style='font-size:20px; font-weight: bold;' >"+user.getOtp()+"</span></h3><h2></h2></div><div style='font-size:10px; border-width:1px 0px 0px 0px;border-style: solid; padding:5px; width:100%; margin-top:100px;'><span>Regards,<br/> Admin Password Vault</span><br/><span><a href='mailto:passvault1018@gmail.com' style='color:#FF6E31;'>passvault1018@gmail.com</a></span></div></div>")
                .toOther(true)
                .build();
        sendEmail(emailMsg);

    }
}
