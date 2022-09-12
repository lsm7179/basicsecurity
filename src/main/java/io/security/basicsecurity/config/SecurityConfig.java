package io.security.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 이걸 넣어야 웹 보완이 활성화 된다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated(); // 어떤 요청에도 인증이 안되면 접근이 안 된다라고 설정함.

        http
                .formLogin()
                //.loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    System.out.printf("authentication" + authentication.getName());
                    httpServletResponse.sendRedirect("/");
                })
                .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                    System.out.println("exception" + e.getMessage());
                    httpServletResponse.sendRedirect("/login");
                })
                .permitAll();

        //logout
        http.logout()                                // 로그아웃 처리
                .logoutUrl("/logout")                // 로그아웃 처리 URL
                .logoutSuccessUrl("/login")            // 로그아웃 성공 후 이동페이지
                .deleteCookies("JSESSIONID", "remember-me")    // 로그아웃 후 쿠키 삭제
                .addLogoutHandler(logoutHandler())         // 로그아웃 핸들러
                .logoutSuccessHandler(logoutSuccessHandler())    // 로그아웃 성공 후 핸들러
        ;

        //remember
        http.rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // Default 는 14일
                .alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService)
        ;

        http.sessionManagement()
                .maximumSessions(1)
                //.maxSessionsPreventsLogin(true) //현재 인증을 시도하는 것을 로그인을 못하게하는 전략
                .maxSessionsPreventsLogin(false)
        ;

        http.sessionManagement() // 세션 고정 보호
                .sessionFixation()
                //.none()
                //.newSession()
                //.migrateSession()
                .changeSessionId() // 기본값
        ;
    }*/

    private LogoutSuccessHandler logoutSuccessHandler() {
        return (httpServletRequest, httpServletResponse, authentication) -> {
            httpServletResponse.sendRedirect("/login");
        };
    }

    private LogoutHandler logoutHandler() {
        return (httpServletRequest, httpServletResponse, authentication) -> {
            HttpSession session = httpServletRequest.getSession();
            session.invalidate();
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //패스워드 암호화 유형을 prefix에 적어줘야한다.(noop은 평문을 의미한다.)
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http
                .formLogin();
    }
}
