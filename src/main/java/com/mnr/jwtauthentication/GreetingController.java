package com.mnr.jwtauthentication;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @GetMapping("/hello")
    public String sayHello(){
        return "hello";
    }

    //restricted for user
    @PreAuthorize("hasRole('USER')") //work before execution of this method
    @GetMapping("/user")
    public String userEndpoint(){
        return "hello, user!";
    }

    //restricted for admin
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "hello, admin!";
    }


}
