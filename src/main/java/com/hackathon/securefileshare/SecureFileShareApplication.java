package com.hackathon.securefileshare;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@org.springframework.scheduling.annotation.EnableScheduling
public class SecureFileShareApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureFileShareApplication.class, args);
		System.out.println("Hello World");
	}

}
