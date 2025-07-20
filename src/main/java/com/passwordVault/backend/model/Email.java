package com.passwordVault.backend.model;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class Email {
    public String name;
    public String mail;
    public String subject;
    public String message;
    public boolean toOther;
}
