package com.br.senac.EcommerceAPI.Services;

import com.br.senac.EcommerceAPI.DTO.AccountCredentialsDTO;
import com.br.senac.EcommerceAPI.DTO.TokenDTO;
import com.br.senac.EcommerceAPI.Models.CredencialModel;
import com.br.senac.EcommerceAPI.Repositories.CredencialRepository;
import com.br.senac.EcommerceAPI.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    private final CredencialRepository credencialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;

    public ResponseEntity<?> authentication(AccountCredentialsDTO dto) throws Exception {

        try {
            CredencialModel user = credencialRepository.findByUsuario(dto.getEmail());
            if(passwordEncoder.matches(dto.getSenha(), user.getPassword())) {
                var tokenResponse = new TokenDTO();
                tokenResponse = tokenProvider.createAccessToken(user.getEmail(), user.getRoles());
                return ResponseEntity.ok(tokenResponse);

            }
        } catch (Exception e) {
            throw new Exception(e);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity refreshToken(String username, String refreshToken) {
        var user = credencialRepository.findByUsuario(username);

        var tokenResponse = new TokenDTO();
        if (user != null) {
            tokenResponse = tokenProvider.refreshToken(refreshToken);
        } else {
            throw new UsernameNotFoundException("Username " + username + " not found!");
        }
        return ResponseEntity.ok(tokenResponse);
    }
}
