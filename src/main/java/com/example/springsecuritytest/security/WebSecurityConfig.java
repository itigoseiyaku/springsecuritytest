package com.example.springsecuritytest.security;

import com.example.springsecuritytest.define.AppConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    protected AppConfig appConfig;

    @Autowired
    WebSecurityConfig(AppConfig appConfig) {
        super();
        this.appConfig = appConfig;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .logout()
                .and()
                .cors().configurationSource(this.corsConfigurationSource())
                .and()
                .csrf().disable();

                // ログイン用APIの設定
                UsernamePasswordJSONAuthenticationFilter filter = new UsernamePasswordJSONAuthenticationFilter();
                filter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
                filter.setAuthenticationManager(authenticationManagerBean());
                filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/login?ok"));
                filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"));

                http.addFilterBefore(filter, UsernamePasswordJSONAuthenticationFilter.class);
    }

    /**
     * SpringSecurity側のCORS設定
      */
    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedMethod("GET");
        corsConfiguration.addAllowedMethod("POST");
        corsConfiguration.addAllowedOrigin(this.appConfig.getFrontendUrl());
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource corsSource = new UrlBasedCorsConfigurationSource();
        corsSource.registerCorsConfiguration("/**", corsConfiguration);

        return corsSource;
    }

    /**
     * デバッグ用のログイン情報の定義
     * //FIXME: DBからユーザーの情報を取得するように変更する
     * @return
     */
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
