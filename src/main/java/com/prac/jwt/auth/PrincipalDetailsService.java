package com.prac.jwt.auth;

import com.prac.jwt.modil.User;
import com.prac.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login (Spring Security Default Route) => 여기서 동작을 안한다. -> formLogin().disable()때문
// --> Filter를 만들어줘서 작동시켜야함
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 loadUserByUsername()" + username);
        User userEntity = userRepository.findByUsername(username);
        System.out.println("Entity : "+userEntity);
        return new PrincipalDetails(userEntity);
    }
}
