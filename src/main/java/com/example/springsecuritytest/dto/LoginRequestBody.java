package com.example.springsecuritytest.dto;

import lombok.Data;
import org.springframework.lang.NonNull;

@Data
public class LoginRequestBody {

    private String username;

    private String password;
}
