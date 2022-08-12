package com.example.jwt;

import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGE"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "Minh Cuong", "Cuong", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Huynh Cuong", "Cuong1", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Minh Anh", "Anh", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Minh Nam", "Nam", "1234", new ArrayList<>()));

            userService.addRoleToUser("Cuong", "ROLE_USER");
            userService.addRoleToUser("Cuong1", "ROLE_MANAGE");
            userService.addRoleToUser("Anh", "ROLE_USER");
            userService.addRoleToUser("Nam", "ROLE_USER");
            userService.addRoleToUser("Nam", "ROLE_ADMIN");
            userService.addRoleToUser("Nam", "ROLE_SUPER_ADMIN");
        };
    }

}
