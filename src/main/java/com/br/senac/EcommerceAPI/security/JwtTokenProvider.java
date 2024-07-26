package com.br.senac.EcommerceAPI.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.br.senac.EcommerceAPI.DTO.TokenDTO;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.Date;
import java.util.List;

@Service
public class JwtTokenProvider {

    @Value("${api.ecommerce.token.secret.key:secret}")
    private String secretKey = "secret";

    @Value("${api.ecommerce.token.expiration:3600000}")
    private long validityToken = 3600000; // 1hr

    @Autowired
    private UserDetailsService userDetailsService;

    public TokenDTO createAccessToken(String username, List<String> roles) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityToken);
        var accessToken = generateToken(username, roles, now, validity);
        var refreshToken = generateRefreshToken(username, roles, now);

        return new TokenDTO(username, true, now, validity, accessToken, refreshToken);
    }

    private String generateToken(String username, List<String> roles, Date now, Date validity) {
//        try {
            String issuerUrl = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
            Algorithm algorithm = Algorithm.HMAC512(secretKey);
            return JWT.create()
                    .withClaim("roles", roles)
                    .withIssuedAt(now)
                    .withExpiresAt(validity)
                    .withIssuer(issuerUrl)
                    .withSubject(username)
                    .sign(algorithm);
    }

    private String generateRefreshToken(String username, List<String> roles, Date now) {
        Date validityRefreshToken = new Date(now.getTime() + (validityToken * 3));
        Algorithm algorithm = Algorithm.HMAC512(secretKey);
        return JWT.create()
                .withClaim("roles", roles)
                .withIssuedAt(now)
                .withExpiresAt(validityRefreshToken)
                .withSubject(username)
                .sign(algorithm)
                .strip();
    }

    public TokenDTO refreshToken(String refreshToken) {
        if (refreshToken.contains("Bearer ")) refreshToken =
                refreshToken.substring("Bearer ".length());
        Algorithm algorithm = Algorithm.HMAC512(secretKey);
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(refreshToken);
        String username = decodedJWT.getSubject();
        List<String> roles = decodedJWT.getClaim("roles").asList(String.class);
        return createAccessToken(username, roles);
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
