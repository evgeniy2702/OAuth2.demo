package com.aouth2.OAuth2.demo.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static sun.security.ssl.SSLLogger.info;

@Component
public class CustomEntryPoint implements AuthenticationEntryPoint {

    private Logger logger = LogManager.getLogger(CustomEntryPoint.class);
    private HandlerExceptionResolver resolver;

    @Autowired
    @Qualifier("handlerExceptionResolver")
    public void setResolver (HandlerExceptionResolver resolver){
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse,
                         AuthenticationException e) throws IOException, ServletException {
        logger.info("Creat CustomEntryPoint bean");
        if(e != null){
            logger.info("Authentication exception in CustomEntryPoint bean");
            resolver.resolveException(httpServletRequest, httpServletResponse, null, e);
        }
        if(httpServletResponse.isCommitted()){
            return;
        }
        httpServletResponse.sendRedirect("/login");
    }
}
