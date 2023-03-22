package com.aouth2.OAuth2.demo.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private Logger logger = LogManager.getLogger(CustomAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();
        logger.info("Username for authentication : " + username);
        if(httpServletRequest.getCookies() != null) {
            for (Cookie cookie : httpServletRequest.getCookies())
                System.out.println(cookie.getName() + " : " + cookie.getValue());
        }
        if(authentication.getPrincipal() instanceof OAuth2User){
            httpServletResponse.sendRedirect("/user");
        }else {
            httpServletResponse.sendRedirect("/authentication");
        }
    }
}
