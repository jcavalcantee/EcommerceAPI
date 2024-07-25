package com.br.senac.EcommerceAPI.Services;

import com.br.senac.EcommerceAPI.DTO.CredencialDTO;
import com.br.senac.EcommerceAPI.DTO.TokenDTO;
import com.br.senac.EcommerceAPI.Repositories.CredencialRepository;
import com.br.senac.EcommerceAPI.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CredencialRepository credencialRepository;

    public ResponseEntity<?> signin(CredencialDTO dto) throws Exception {
        try {
            var username = dto.getEmail();
            var password = dto.getSenha();
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            var user = credencialRepository.findByUsuario(username);

            var tokenResponse = new TokenDTO();
            if (user != null) {
                tokenResponse = tokenProvider.createAccessToken(username, user.getRoles());
            } else {
                throw new Exception("Erro");
            }
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            throw e;
        }
    }
}
