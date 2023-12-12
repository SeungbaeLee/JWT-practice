package com.prac.jwt.controller;

import com.prac.jwt.auth.PrincipalDetails;
import com.prac.jwt.modil.User;
import com.prac.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class RestApiController{
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @PostMapping("home")
    public String home(){return "<h1>home</h1>";}

    @PostMapping("token")
    public String token(){return "<h1>token</h1>";}

    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_ADMIN");
        userRepository.save(user);
        return "회원가입 완료";
    }

    @PostMapping("user")
    public String user(Authentication authentication){
        PrincipalDetails principalDetails=(PrincipalDetails) authentication.getPrincipal();
        System.out.println("UserId : "+principalDetails.getUser().getId());
        System.out.println("Username : "+principalDetails.getUser().getUsername());
        System.out.println("Password : "+principalDetails.getUser().getPassword());
        return "<h1>user</h1>";
    }

    // 매니저 혹은 어드민이 접근 가능
    @GetMapping("manager/reports")
    public String reports() {
        return "<h1>reports</h1>";
    }

    // 어드민이 접근 가능
    @GetMapping("admin/users")
    public List<User> users() {
        return userRepository.findAll();
    }

}
