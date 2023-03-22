package com.aouth2.OAuth2.demo.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    private Logger logger = LogManager.getLogger(CustomLogoutSuccessHandler.class);

    @Override
    public void onLogoutSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        if(authentication != null) {
            if (authentication.getPrincipal() instanceof OAuth2User) {
                logger.info("User with username = " + ((OAuth2User) authentication.getPrincipal()).getAttribute("name") +
                        " is logout successful.");
                response.sendRedirect("/");
            } else {
                logger.info("User with username = " + ((User) authentication.getPrincipal()).getUsername() +
                        " is logout successful.");
                response.sendRedirect("/");
            }
        }else {
            response.sendRedirect("/");
        }
    }
}
