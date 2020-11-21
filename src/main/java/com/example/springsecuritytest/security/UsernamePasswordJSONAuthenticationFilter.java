package com.example.springsecuritytest.security;

import com.example.springsecuritytest.dto.login.LoginRequestBody;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * パスワード認証を行うFilter
 */
public class UsernamePasswordJSONAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private boolean postOnly;

    /**
     * パスワード認証部分
     * 継承元ではForm認証だが、JSONでリクエストするように変更している
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        LoginRequestBody loginRequestBody = null;
        try {
            loginRequestBody = new ObjectMapper().readValue(request.getInputStream(), LoginRequestBody.class);
            if (loginRequestBody == null) {
                throw new IOException();
            }
        } catch (IOException e) {
            throw new AuthenticationServiceException("Authentication Parameter is not correct");
        }

        String username = loginRequestBody.getUsername() ;
        username = (username != null) ? username : "";
        username = username.trim();
        String password = loginRequestBody.getPassword();
        password = (password != null) ? password : "";
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }
}