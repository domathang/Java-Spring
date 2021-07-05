package com.ouu99.book.springboot.config.auth;

import com.ouu99.book.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 설정 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .headers().frameOptions().disable() // h2-colsole 화면을 사용하기 위해
                .and()
                    .authorizeRequests()            // URL별 권한 관리를 설정하는 옵션의 시작점
                    .antMatchers("/", "/css/**", "/images/**", "/js/**", "/h2-console/**", "/profile").permitAll()                // 지정된 URL은 permitAll() 옵션을 이용해 전체 열람 권한을 줌
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                    .anyRequest().authenticated()
                .and()
                    .logout()
                        .logoutSuccessUrl("/")      // Logout 성공 시 이동할 주소
                .and()
                    .oauth2Login()
                        .userInfoEndpoint()         // OAuth 2 로그인 성공 이후 사용자 정보를 가져올 때의 설정 담당
                            .userService(customOAuth2UserService);  // 소셜 로그인 성공 시 후속 조치를 진행할 UserService 인터페이스의 구현체를 등록
    }

}
