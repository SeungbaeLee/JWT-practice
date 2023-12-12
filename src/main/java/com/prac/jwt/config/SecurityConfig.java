package com.prac.jwt.config;

import com.prac.jwt.filter.MyFilter1;
import com.prac.jwt.filter.MyFilter3;
import com.prac.jwt.jwt.JwtAuthenticationFilter;
import com.prac.jwt.jwt.JwtAuthorizationFilter;
import com.prac.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

//    @Bean   // @Bean의 역할은 해당 메서드의 return 되는 Object를 IoC로 등록해줌
//    public BCryptPasswordEncoder encodePwd(){
//        return new BCryptPasswordEncoder();
//    }

    /*
    패스워드를 암호화해주는 메소드로, 8바이트 이상의 무작위로 생성된 솔트와 결합된 SHA-1 이상의 해시를 적용한다.
    java.lang.CharSequence 타입의 패스워드를 매개변수로 입력해주면 암호화 된 패스워드를 String 타입으로 반환해준다.
    해시시킬 때 무작위로 생성한 salt가 포함되므로 같은 비밀번호를 인코딩해도 매번 다른 결과값이 반환된다.
     */
    // Circular Dependency Injection 해결을 위해서 encodePwd() 생성자 코드를 Application.java로 옮김

    private final CorsFilter corsFilter;

    @Autowired
    private CorsConfig corsConfig;

    @Autowired
    private UserRepository userRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /*
        사용자가 임의로 지정한 Filter는 springSecurityFilterChain에 등록이 되지 않는다.(타입이 Filter이기 때문)
        따라서 해당 Filter를 사용하기 위해서는 addFilterAfter 또는 addFilterBefore를 통해서 연계를 시켜줘야 한다.
        http.csrf(CsrfConfigurer::disable);
        http.sessionManagement(httpSecuritySessionManagementConfigurer -> {
            httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS); // Session 사용 X
        }).addFilter(corsFilter)    // @CrossOrigin은 인증이 필요없을때 사용하지만, 그게 아니라면 필터에 등록을 해줘야 한다.
                .formLogin(formLogin -> formLogin.disable())
                .httpBasic(httpSecurityHttpBasicConfigurer ->httpSecurityHttpBasicConfigurer.disable()
                // httpBasic 방식은 headers의 Authorization의 값으로 ID와 PW를 포함해서 request를 보내는데
                // 이 방식대로 하면 ID와 PW가 노출되기 때문에 보안에 상당한 취약점을 들어낸다.
                // 따라서 ID와 PW 대신에 Token을 사용하는 방식인 httpBearer 방식을 사용하는 것이 그나마 보안에 덜 취약하다.
                // (httpBearer 방식을 사용한다고 해서 Token이 노출이 안된다는 것은 아님.)
                // 이러한 방식이 JWT 인증 방식이다.
                // 즉, httpBearer방식을 사용하기 위해서 Session, formLogin, HttpBasic을 다 비활성화 시킴.
        ).
         */

        http.csrf(cs-> cs.disable())
                .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Session 사용 안함
                .formLogin(f->f.disable())//FormLogin 사용 안함 -> 필터로 빼서 사용
                .httpBasic(h->h.disable())
                .apply(new MyCustomDs1());

        http.authorizeRequests(authorize-> {     // 권한 부여
            // authorizeRequests가 deprecated됨에 따라 authorizeHttpRequests 사용 권장
            authorize
                    .requestMatchers("/user/**").hasAnyRole("USER","MANAGER","ADMIN")
                    .requestMatchers("/manager/**").hasAnyRole("MANAGER","ADMIN")
                    .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                    // hasAnyRole() 메소드는 자동으로 앞에 ROLE_을 추가해서 체크해준다
                    .anyRequest().permitAll();  // 이외의 요청은 모두 허용함
        });

        /* Spring Security 사용 시
        http.formLogin(f->f{
            f.loginProcessingUrl("/login");     // 로그인 url 설정
        });
         */
        return http.build();
    }

    public class MyCustomDs1 extends AbstractHttpConfigurer<MyCustomDs1, HttpSecurity>{ // custom Filter
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager=http.getSharedObject(AuthenticationManager.class);
            http.addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))  // AuthenticationManager를 Parameter로 넘겨줘야 함(로그인을 진행하는 데이터이기 때문)
                    .addFilter(new JwtAuthorizationFilter(authenticationManager,userRepository));
            System.out.println("authenticationManager3 : " + authenticationManager);    // log
        }
    }
    /*
    기존: WebSecurityConfigurerAdapter를 상속하고 configure매소드를 오버라이딩하여 설정하는 방법
    //https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
                    || 기존 코드 예시
                    \/
    @Override
    protected void configure(HttpSecurity http) throws  Exception{
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin").access("\"hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }

    => 현재: SecurityFilterChain을 리턴하는 메소드를 빈에 등록하는 방식(컴포넌트 방식으로 컨테이너가 관리)
     */
}