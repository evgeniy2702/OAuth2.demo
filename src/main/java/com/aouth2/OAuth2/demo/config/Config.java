package com.aouth2.OAuth2.demo.config;


import com.aouth2.OAuth2.demo.security.CustomAuthenticationFailureHandler;
import com.aouth2.OAuth2.demo.security.CustomAuthenticationSuccessHandler;
import com.aouth2.OAuth2.demo.security.CustomLogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@EnableWebSecurity
@Import(SecurityBeans.class)
public class Config extends WebSecurityConfigurerAdapter {

    private PasswordEncoder passwordEncoder;
    private AuthenticationEntryPoint entryPoint;
    private AccessDeniedHandler accessDeniedHandler;
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private CustomLogoutSuccessHandler customLogoutSuccessHandler;
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;

    public Config(@Qualifier("passwordEncoder") PasswordEncoder passwordEncoder,
                          AuthenticationEntryPoint entryPoint,
                          @Qualifier("accessDeniedHandler") AccessDeniedHandler accessDeniedHandler,
                          @Qualifier("authFailHandler") CustomAuthenticationFailureHandler customAuthenticationFailureHandler,
                          @Qualifier("logoutSuccessHandler") CustomLogoutSuccessHandler customLogoutSuccessHandler,
                          @Qualifier("authSuccessHandler") CustomAuthenticationSuccessHandler authenticationSuccessHandler)
    {
        this.passwordEncoder = passwordEncoder;
        this.entryPoint = entryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
        this.customLogoutSuccessHandler = customLogoutSuccessHandler;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(a -> a
                        .antMatchers("/","/**", "/webjars/**","/**/*.css", "/**/*.js",
                                "/static/**","/templates/**", "/login", "/authentication-fail" ).permitAll()
                        .antMatchers("/accessDenied", "/authentication", "/user",
                                "/error-message")
                        .hasAnyRole("USER","ADMIN")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .oauth2Login()
//                .defaultSuccessUrl("/user")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)

                .and()
                .formLogin()
                .failureHandler(customAuthenticationFailureHandler)
                .loginPage("/index")
                .loginProcessingUrl("/authentication")
                .usernameParameter("username")
                .successHandler(authenticationSuccessHandler)

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(entryPoint)
                .accessDeniedHandler(accessDeniedHandler)

                .and()
                .csrf(c -> c
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))


                .logout()
                .logoutUrl("/leave/authentication")
                .logoutSuccessHandler(customLogoutSuccessHandler)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID","XSRF-TOKEN")
                .permitAll()
                ;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
        String admin = "admin";
        String user = "user";

        auth.inMemoryAuthentication()
                .withUser(user)
                .password(passwordEncoder.encode(user))
                .roles(user.toUpperCase())
                .and()
                .withUser(admin)
                .password(passwordEncoder.encode(admin))
                .roles(admin.toUpperCase());
    }

}
