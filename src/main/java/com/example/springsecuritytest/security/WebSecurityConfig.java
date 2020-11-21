package com.example.springsecuritytest.security;

import com.example.springsecuritytest.dto.LoginRequestBody;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .logout()
//                .defaultSuccessUrl("http://localhost:9090?result=ok")
//                .failureUrl("http://localhost:9090?result=ng")
                .and()
                .cors().configurationSource(this.corsConfigurationSource())
                .and()
                .csrf().disable();

                UsernamePasswordJSONAuthenticationFilter filter = new UsernamePasswordJSONAuthenticationFilter();
                filter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
                filter.setAuthenticationManager(authenticationManagerBean());
                filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/login?ok"));
                filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"));

                http.addFilterBefore(filter, UsernamePasswordJSONAuthenticationFilter.class);
    }
    
    private static class UsernamePasswordJSONAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
        private boolean postOnly;

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

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedMethod("GET");
        corsConfiguration.addAllowedMethod("POST");
        corsConfiguration.addAllowedOrigin("http://localhost:9090");
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource corsSource = new UrlBasedCorsConfigurationSource();
        corsSource.registerCorsConfiguration("/**", corsConfiguration);

        return corsSource;
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build();

        return new InMemoryUserDetailsManager(user);
    }
}
