package com.br.senac.EcommerceAPI.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.br.senac.EcommerceAPI.Models.CredencialModel;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.Date;

@Service
public class JwtTokenProvider {

    @Value("${api.ecommerce.token.secret.key:secret}")
    private String secretKey = "secret";

    @Value("${api.ecommerce.token.expiration:3600000}")
    private long validityToken = 3600000; // 1hr

    @Autowired
    private UserDetailsService userDetailsService;

    public String generateToken(CredencialModel credencial) {
        try {
            String issuerUrl = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
            Algorithm algorithm = Algorithm.HMAC512(secretKey);
            Date now = new Date();
            Date expiration = new Date(now.getTime() + validityToken);
            String token = JWT.create()
                    .withClaim("roles", credencial.getRoles())
                    .withIssuedAt(now)
                    .withExpiresAt(expiration)
                    .withIssuer(issuerUrl)
                    .withSubject(credencial.getEmail())
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException ex) {
            throw new RuntimeException("Error", ex);
        }
    }

    public String validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }

        try {
            Algorithm algorithm = Algorithm.HMAC512(secretKey);
            String issuerUrl = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
            return JWT.require(algorithm)
                    .withIssuer(issuerUrl)
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException ex) {
            return null;
        }
    }

    public String resolveToken(HttpServletRequest req) {
        String header = req.getHeader("Authorization");
        if(header == null) return null;
        return header.replace("Bearer ", "");
    }

}
