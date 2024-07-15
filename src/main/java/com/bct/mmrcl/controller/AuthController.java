package com.bct.mmrcl.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.bct.mmrcl.exception.AuthenticationFailedException;
import com.bct.mmrcl.model.AuthenticationResponse;
import com.bct.mmrcl.model.Client;
import com.bct.mmrcl.repository.ClientRepository;
import com.bct.mmrcl.service.PasswordHasher;
import com.bct.mmrcl.util.EncryptionUtil;
import com.bct.mmrcl.util.JwtUtil;

@RestController
@RequestMapping("/api/common/auth")
public class AuthController {

	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private Environment env; 

	@Autowired
	EncryptionUtil encutil;

	private final PasswordHasher passwordHasher;
	private final ClientRepository clientrepo;

	@Autowired
	public AuthController(PasswordHasher passwordHasher,ClientRepository clientrepo) {
		this.passwordHasher = passwordHasher;
		this.clientrepo = clientrepo;
	}


	@GetMapping("/generate-token")
	public ResponseEntity<?> getProtectedResource(HttpServletRequest request, HttpServletResponse response) throws Exception {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String username = authentication.getName();


		try {
			final String jwt = jwtUtil.generateToken(username);
			return ResponseEntity.ok(new AuthenticationResponse(jwt));
		} catch (AuthenticationException e) {
			throw new AuthenticationFailedException("Authentication failed. Invalid username or password.");
		}
	}


	@GetMapping("/validate-token")
	public ResponseEntity<?> getValidatedResource(HttpServletRequest request, HttpServletResponse response) throws Exception {
		String encryptedResponse = encutil.encrypt(Boolean.TRUE.toString());
		return ResponseEntity.ok(encryptedResponse);
	}


	@GetMapping("/hashPassword")
	public ResponseEntity<String> hashPassword(@RequestParam String plainPassword) {
		try {
			String hashedPassword = passwordHasher.hashPassword(plainPassword);
			return new ResponseEntity<>(hashedPassword, HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<>("Error hashing password", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@GetMapping("/generateAuthorizationHeader")
	public ResponseEntity<String> generateAuthorizationHeader(@RequestParam String clientId) {

		
		Client user = clientrepo.findByClientName(clientId);
		// Encode username and password into Base64
		String plainCredentials = clientId + ":" + user.getClientSecret();
		String encodedCredentials = Base64.getEncoder().encodeToString(plainCredentials.getBytes());

		// Build the Authorization header value
		String authorizationHeader = "Basic " + encodedCredentials;

		// Return the Authorization header value as response
		return new ResponseEntity<>(authorizationHeader, HttpStatus.OK);
	}


}
