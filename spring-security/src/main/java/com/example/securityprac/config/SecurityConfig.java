package com.example.securityprac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // spring security 활성화 (웹 보안 활성화)
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated());
                // requestMatchers : 특정한 url 에 대해 경로 설정
                // + 보안 설정
                // anyRequest : 위에서 처리 하지 못한 나머지 경로 처리

        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/LoginProc")
                        .permitAll());

                // loginPage : login page 로 redirect
                // loginProcessingUrl : login 한 데이터를 특정한 경로로 보냄

        http
                .csrf((auth)->auth.disable());

        return http.build();
    }

}
