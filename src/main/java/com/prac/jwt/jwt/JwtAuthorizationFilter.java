package com.prac.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.prac.jwt.auth.PrincipalDetails;
import com.prac.jwt.modil.User;
import com.prac.jwt.repository.UserRepository;
import io.jsonwebtoken.Jwt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

// Security가 가지고 있는 filter들 중 BasicAuthenticationFilter라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 filter를 무조건 타게 되어있음.
// 만약에 권한이 인증이 필요한 주소가 아니라면 이 filter를 타지 않는다.
// 인가

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository){
        super(authenticationManager);
        System.out.println("인증이나 권한이 필요한 주소가 요청됨");
        this.userRepository=userRepository;
    }


    // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //String header=request.getHeader("Authorization");
        String header=request.getHeader(JWtProperties.HEADER_STRING);
        System.out.println("JWTHeader : "+header);  // JWT Token

        // header가 있는지(유효한지) 확인
        if(header==null||!header.startsWith(JWtProperties.TOKEN_PREFIX)){
            System.out.println("Not Allowed User");
            chain.doFilter(request,response);
            return;
        }

        // JWT Token을 검증해서 정상적인 사용자인지 확인
        String token = request.getHeader(JWtProperties.HEADER_STRING).replace(JWtProperties.TOKEN_PREFIX, "");
        String username = JWT.require(Algorithm.HMAC512(JWtProperties.SECRET)).build().verify(token).getClaim("username").asString();  // verify()를 통해서 서명

        // 서명이 정상적으로 동작했을 경우
        if(username!=null){
            User userEntity = userRepository.findByUsername(username);
            System.out.println("UserEntity 정상 : "  +userEntity);
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            System.out.println("Username : "+userEntity.getUsername());

            // JWT Token 서명을 통해서 서명이 정상적이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            System.out.println("authentication"+authentication);
            // 강제로 Security의 Session에 접근하여서 Authentication 객체를 저장시킨다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("Successfully Saved Authentication" + authentication);

        }
        // super.doFilterInternal(request, response, chain);
        chain.doFilter(request,response);
    }
}