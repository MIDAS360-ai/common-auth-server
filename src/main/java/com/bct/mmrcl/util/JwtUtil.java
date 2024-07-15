package com.bct.mmrcl.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import com.bct.mmrcl.model.Client;
import com.bct.mmrcl.repository.ClientRepository;

import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {
	
	
	private final String secretKey;
	
	private final ClientRepository userRepository;
	

	public JwtUtil(ClientRepository userRepository,Environment env) {
		this.userRepository = userRepository;
		this.secretKey = env.getProperty("jwt.token.gen.key");
	}
	// Generate a token
	public String generateToken(String username) {

		Client user = userRepository.findByClientName(username);
		if (user == null) {
			throw new RuntimeException("User not found");
		}

		int tokenIntervalMin = user.getTokenIntervalMin();
		Date issuedAt = new Date(System.currentTimeMillis());
		Date expirationDate = new Date(System.currentTimeMillis() + tokenIntervalMin * 60 * 1000);


		return Jwts.builder()
				.setSubject(username)
				.setIssuedAt(issuedAt)
				.setExpiration(expirationDate)
				.signWith(SignatureAlgorithm.HS256, secretKey)
				.compact();
	}

	// Validate the token
	public Boolean validateToken(String token, String username) {
		final String extractedUsername = extractUsername(token);
		return (extractedUsername.equals(username) && !isTokenExpired(token));
	}

	// Extract username from token
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	// Extract expiration date from token
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	// Check if the token has expired
	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	// Extract a single claim from the token
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	// Extract all claims from the token
	private Claims extractAllClaims(String token) {
		return Jwts.parser()
				.setSigningKey(secretKey)
				.parseClaimsJws(token)
				.getBody();
	}
}
