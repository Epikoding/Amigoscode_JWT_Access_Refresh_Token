package io.getarrays.userservice;

import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserserviceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) { //run 이후 아래 data insert
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "이동재", "dj", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "김민수", "kms", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "박민수", "bms", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "김민지", "kmj", "1234", new ArrayList<>()));

            userService.addRoleToUser("dj", "ROLE_USER");
            userService.addRoleToUser("dj", "ROLE_MANAGER");
            userService.addRoleToUser("kms", "ROLE_MANAGER");
            userService.addRoleToUser("bms", "ROLE_ADMIN");
            userService.addRoleToUser("kmj", "ROLE_SUER_ADMIN");
            userService.addRoleToUser("kmj", "ROLE_ADMIN");
            userService.addRoleToUser("kmj", "ROLE_USER");
        };
    }

}
