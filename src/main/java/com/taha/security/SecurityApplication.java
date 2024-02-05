package com.taha.security;

import com.taha.security.auth.AuthenticationService;
import com.taha.security.auth.RegisterRequest;
import com.taha.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner(AuthenticationService authenticationService){
        return args -> {
            var admin = RegisterRequest
                    .builder()
                    .email("admin@admin.com")
                    .firstname("Taha admin")
                    .lastname("oh admin")
                    .password("admin-admin")
                    .role(Role.ADMIN)
                    .build();
             var authAdmin = authenticationService.register(admin);
            System.out.println("Admin token "+ authAdmin.getToken() + "\n " + "refresh token " + authAdmin.getRefreshToken());
            var manager = RegisterRequest
                    .builder()
                    .email("manager@manager.com")
                    .firstname("Taha manager")
                    .lastname("oh manager")
                    .password("manager-manager")
                    .role(Role.MANAGER)
                    .build();
            var authManger =  authenticationService.register(manager);
            System.out.println("Manager token "+ authManger.getToken() + "\n " + "refresh token " + authManger.getRefreshToken() );
            var user = RegisterRequest
                    .builder()
                    .email("user@user.com")
                    .firstname("Taha user")
                    .lastname("oh user")
                    .password("user-user")
                    .role(Role.USER)
                    .build();
            var authUser =  authenticationService.register(user);
            System.out.println("User token "+ authUser.getToken() + "\n " + "refresh token " + authUser.getRefreshToken() );
        };
    }

}
