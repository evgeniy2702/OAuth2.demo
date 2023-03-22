package com.aouth2.OAuth2.demo.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private Logger logger = LogManager.getLogger(CustomAuthenticationFailureHandler.class);

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String message = "";
        String username = request.getParameter("username");
        String admin = "admin";
        String user = "user";
        if(!username.equals(admin) && !username.equals(user)){
            message = "Користувача з логіном " + username + " не існує";
            logger.warn(message);
        } else if(exception.getClass() == BadCredentialsException.class) {
            message = "Перевірте свій логін або пароль";
            logger.warn(message);
        }

        request.getRequestDispatcher(String.format("/authentication-fail?error=true&message=%s&un=%s", message,username))
                .forward(request, response);
    }
}
