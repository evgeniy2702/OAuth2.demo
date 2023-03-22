package com.aouth2.OAuth2.demo.config;

import com.aouth2.OAuth2.demo.security.CustomAuthenticationSuccessHandler;
import com.aouth2.OAuth2.demo.security.CustomLogoutSuccessHandler;
import com.aouth2.OAuth2.demo.security.CustomAccessDeniedHandler;
import com.aouth2.OAuth2.demo.security.CustomAuthenticationFailureHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.security.SecureRandom;

@Configuration
public class SecurityBeans {

    @Bean(name = "passwordEncoder")
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        BCryptPasswordEncoder.BCryptVersion version =
                BCryptPasswordEncoder.BCryptVersion.$2Y;
        int strength = 12;
        return new BCryptPasswordEncoder(version, strength, new SecureRandom());
    }

    @Bean(name = "accessDeniedHandler")
    public AccessDeniedHandler accessDeniedHandler(){
        return new CustomAccessDeniedHandler();
    }

    @Bean(name = "authFailHandler")
    public CustomAuthenticationFailureHandler customAuthenticationFailureHandler(){
        return new CustomAuthenticationFailureHandler();
    }

    @Bean(name = "logoutSuccessHandler")
    public CustomLogoutSuccessHandler customLogoutSuccessHandler(){
        return new CustomLogoutSuccessHandler();
    }

    @Bean(name = "authSuccessHandler")
    public CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler(){
        return new CustomAuthenticationSuccessHandler();
    }
}
