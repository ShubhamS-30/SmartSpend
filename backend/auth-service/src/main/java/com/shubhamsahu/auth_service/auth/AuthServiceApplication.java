package com.shubhamsahu.auth_service.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {"com.shubhamsahu.auth_service"})
@ComponentScan(basePackages = "com.shubhamsahu.auth_service")
@EnableJpaRepositories(basePackages = "com.shubhamsahu.auth_service.repository")
@EntityScan(basePackages = "com.shubhamsahu.auth_service.entity")
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

}
