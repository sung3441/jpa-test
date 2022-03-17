package com.saml.config;

import com.saml.service.MemberService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration // 해당 클래스를 Configuration 으로 등록
@EnableWebSecurity // Spring Security 를 활성화 시킴
@EnableGlobalMethodSecurity(prePostEnabled = true) // Controller 에서 특정 페이지에 특정 권한이 있는 유저만 접근을 허용할 경우  @PreAuthorize 어노테이션을 사용하는데, 해당 어노테이션에 대한 설정을 활성화 시키는 어노테이션임 (필수 x)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private MemberService memberService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public SecurityConfig(MemberService memberService) {
        this.memberService = memberService;
    }

    /**
     * webSecurity 는 FilterChainProxy 를 생성하는 필터이다.
     * 다양한 Filter 설정을 적용할 수 있다.
     * 아래 설정을 통해 Spring Security 에서 해당 요청은 인증 대상에서 제외시킨다.
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        // static 디렉터리의 하위 파일 목록은 인증 무시 ( = 항상 통과)
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/**");
    }


    /**
     * HttpSecurity 를 통해 HTTP 요청에 대한 보안을 설정할 수 있음.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /**
         * http 요청에 대해서 모든 사용자가 /** 경로로 요청할 수 있지만, /member/**, /admin/** 경로는 인증된 사용자만 요청이 가능하다.
         *
         * authorizeRequests() : HttpServletRequest 요청 URL 에 따라 접근 권한을 설정한다.
         * antMatchers("pathPattern") : 요청 URL 경로 패턴을 지정한다.
         * authenticated() : 인증된 유저만 접근을 허용
         * permitAll() : 모든 유저에게 접근을 허용
         * anonymous() : 인증되지 않은 유저만 허용
         * denyAll() : 모든 유저에 대해 접근을 허용하지 않음
         */
        http.authorizeRequests()
                //  페이지 권한 설정
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/myinfo").hasRole("MEMBER")
                .antMatchers("/**").permitAll();

        /**
         * 로그인 설정을 진행
         *
         * formLogin() : form Login 설정을 진행
         * loginPage("path") : 커스텀 로그인 페이지 경로와 로그인 인증 경로를 등록
         * defaultSuccessUrl("path") : 로그인 인증을 성공하면 이동하는 페이지를 등록
         */
        http.formLogin()
                .loginPage("/user/login")
                .defaultSuccessUrl("/user/login/result")
                .permitAll();

        /**
         * 로그아웃 설정을 진행
         *
         * logout() : 로그아웃 설정을 진행
         * logoutRequestMatcher(new AntPathRequestMatcher("path")) : 로그아웃 경로를 지정
         * logoutSuccessUrl("path") : 로그아웃 성공 시 이동할 경로를 지정
         * invalidateHttpSession(true) : 로그아웃 성공 시 세션을 제거
         */
        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/user/logout"))
                .logoutSuccessUrl("/user/logout/result")
                .invalidateHttpSession(true);

        /**
         * 권한이 없는 사용자가 접근했을 경우 이동할 경로를 지정
         */
        http.exceptionHandling().accessDeniedPage("/user/denied");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(memberService).passwordEncoder(passwordEncoder());
    }
}
