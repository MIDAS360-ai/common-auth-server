package com.bct.mmrcl;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
@PropertySource("classpath:appconstants.properties")
public class MmrclApplication {

	public static void main(String[] args) {
		SpringApplication.run(MmrclApplication.class, args);
	}

}
