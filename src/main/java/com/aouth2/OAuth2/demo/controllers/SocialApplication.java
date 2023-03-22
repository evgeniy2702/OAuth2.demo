package com.aouth2.OAuth2.demo.controllers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

@RestController
public class SocialApplication {

    private Logger logger = LogManager.getLogger(SocialApplication.class);

    @GetMapping("/")
    public ModelAndView start(@AuthenticationPrincipal OAuth2User principal, ModelAndView modelAndView){
        modelAndView.setViewName("index");
        logger.info("STARTS PAGE .");
        return modelAndView;
    }

    @GetMapping("/user")
    public ModelAndView user(@AuthenticationPrincipal OAuth2User principal, ModelAndView modelAndView) {
        modelAndView.setViewName("index");
        if (principal != null) {
            logger.info("OAuth2User principal : " + principal.getName());
            logger.info("OAuth2User principal attributes : ");
            for (String key : principal.getAttributes().keySet()) {
                System.out.println("key = " + key + "; value = " + principal.getAttribute(key));
            }
            logger.info("OAuth2User principal grandAuthorities : ");
            principal.getAuthorities().forEach(System.out::println);
            modelAndView.addObject("userName", principal.getAttribute("name"));

            return modelAndView;
        } else {
            return modelAndView;
        }
    }

    @GetMapping("/error-message")
    public String error(HttpServletRequest request) {
        String message = (String) request.getSession().getAttribute("error.message");
        request.getSession().removeAttribute("error.message");
        return message;
    }

    @PostMapping("/leave/authentication")
    public void logout(HttpServletRequest request) {
        if(request.getCookies() != null) {
            for(Cookie cookie : request.getCookies()) {
                logger.info(cookie.getName() + " : " + cookie.getValue());
            }
        }
    }

    @GetMapping("/authentication")
    public ModelAndView authentication(ModelAndView modelAndView) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logger.info("GrandAuthorities is : ");

        authentication.getAuthorities().forEach(System.out::println);

        modelAndView.addObject("userName", ((User)authentication.getPrincipal()).getUsername());
        modelAndView.setViewName("index");
        return modelAndView;
    }

    @GetMapping(value = {"/accessDenied"})
    public ModelAndView accessDenied(ArithmeticException authEx, ModelAndView modelAndView) throws IOException {
        logger.info("AuthEx : " + authEx);
        for(StackTraceElement el : authEx.getStackTrace()){
            System.out.println(el.toString());
        }
        modelAndView.addObject("message" , authEx);
        modelAndView.setViewName("index");
        return modelAndView;
    }

    @PostMapping("/authentication-fail")
    public ModelAndView authFail(@RequestParam(name = "error", required = false) Boolean error,
                                            @RequestParam(name = "message", required = false) String message,
                                            @RequestParam(name = "un", required = false) String username,
                                            ModelAndView modelAndView){
        logger.warn("For user " + username + " " + message);
        modelAndView.setViewName("index");
        if(Boolean.TRUE.equals(error)){
            modelAndView.addObject("message", message);
        }
        return modelAndView;
    }

}
