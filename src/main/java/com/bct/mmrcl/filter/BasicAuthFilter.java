package com.bct.mmrcl.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import com.bct.mmrcl.model.Client;
import com.bct.mmrcl.repository.ClientRepository;
import com.bct.mmrcl.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

@Component
public class BasicAuthFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private ClientRepository userRepository;

	@Autowired
	private Environment env; 

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (request.getRequestURI().contains(env.getProperty("jwt.token.bcypt.url"))) {
			// Skip filter chain for /hashPassword endpoint
			filterChain.doFilter(request, response);
			return;
		}
		else if (request.getRequestURI().contains(env.getProperty("jwt.token.authheader.url"))) {
			filterChain.doFilter(request, response);
			return;
		}
		// Handle authentication based on Authorization header
		String authorizationHeader = request.getHeader("Authorization");
		if (StringUtils.hasText(authorizationHeader)) {
			if (authorizationHeader.startsWith("Basic ")) {
				request.setAttribute("authType", "Basic");
				if (!handleBasicAuthentication(authorizationHeader, response)) {
					return;
				}
			} else if (authorizationHeader.startsWith("Bearer ")) {
				request.setAttribute("authType", "Bearer");
				if (!handleBearerAuthentication(authorizationHeader, response)) {
					return;
				}
			} else {
				sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Unsupported authentication scheme");
				return;
			}
		} else {
			sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Missing Authorization header");
			return;
		}

		// Continue with the filter chain for authenticated requests
		filterChain.doFilter(request, response);
	}

	private boolean handleBasicAuthentication(String authorizationHeader, HttpServletResponse response) throws IOException {
		String base64Credentials = authorizationHeader.substring(6);
		String credentials = new String(Base64Utils.decodeFromString(base64Credentials), StandardCharsets.UTF_8);
		String[] values = credentials.split(":", 2);
		if (values.length == 2) {
			String username = values[0];
			String password = values[1];

			if (isValidUser(username, password)) {
				UsernamePasswordAuthenticationToken authToken =
						new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());
				SecurityContextHolder.getContext().setAuthentication(authToken);
				return true;
			} else {
				sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, env.getProperty("error.auth.invalid_credentials"));
				return false;
			}
		} else {
			sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,env.getProperty("error.auth.invalid_credentials"));
			return false;
		}
	}

	private boolean handleBearerAuthentication(String authorizationHeader, HttpServletResponse response) throws IOException {
		String jwtToken = authorizationHeader.substring(7);
		try {
			String username = jwtUtil.extractUsername(jwtToken);
			if (username != null && jwtUtil.validateToken(jwtToken, username)) {
				UsernamePasswordAuthenticationToken authToken =
						new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
				SecurityContextHolder.getContext().setAuthentication(authToken);
				return true;
			} else {
				sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, env.getProperty("error.jwt.invalid_or_expired"));
				return false;
			}
		} catch (ExpiredJwtException ex) {
			sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, env.getProperty("error.jwt.expired_message"));
			return false;
		}
		catch (Exception e) {
			sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, env.getProperty("error.jwt.expired_message") );
			return false;
		}
	}

	private boolean isValidUser(String username, String password) {
		Client client = userRepository.findByClientName(username);
		if (client != null && client.getClientSecret().equalsIgnoreCase(password) && client.isActiveStatus()) {
			return true;
		}
		return false;
	}

	private void sendErrorResponse(HttpServletResponse response, int status, String message) throws IOException {
		response.setStatus(status);
		response.setContentType("application/json");
		response.getWriter().write("{\"error\": \"" + message + "\"}");
	}

}
