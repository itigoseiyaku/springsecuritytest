package com.example.springsecuritytest.dto.login;

import lombok.Data;

/**
 * ログイン(/login)APIのRequestBody
 */
@Data
public class LoginRequestBody {

    private String username;

    private String password;
}
