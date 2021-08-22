package TechNinjas.LocaFacil.Security;

import TechNinjas.LocaFacil.Data.UsuarioData;
import TechNinjas.LocaFacil.Model.UsuarioModel;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.format.number.PercentStyleFormatter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class AutenticateJWTFilter extends UsernamePasswordAuthenticationFilter {

    public static final int TOKEN_EXPIRACAO = 600_000;
    public static final String TOKEN_SENHA = "ff9b5b14-0a0e-46e8-82a6-b72e27d3f06b";

    private final AuthenticationManager authManager;

    public AutenticateJWTFilter(AuthenticationManager authManager) {
        this.authManager = authManager;
    }


    //Batendo o erro aqui (parte de criação de username)
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //try {
            UsuarioModel usuario = new UsuarioModel();
            usuario.setEmail("admin@gmail.com");
            usuario.setSenha("1313");

            //Ver isso depois
            //UsuarioModel usuario = new ObjectMapper().readValue(request.getInputStream(), UsuarioModel.class);

            return  authManager.authenticate(new UsernamePasswordAuthenticationToken(
                    usuario.getEmail(), usuario.getSenha(), new ArrayList<>()));
        //} catch (IOException e) {
            //throw new RuntimeException("Falha ao autenticar o usuario", e);
        //}
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        UsuarioData usuarioData = (UsuarioData) authResult.getPrincipal();
        String token = JWT.create().withSubject(usuarioData.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRACAO)).sign(Algorithm.HMAC512(TOKEN_SENHA));

        Cookie cookie = new Cookie("token", token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(60 * 30); // 30 minutos
        response.addCookie(cookie);

        response.getWriter().write("Login autenticado");
        response.getWriter().write(token);
        response.getWriter().flush();

        super.successfulAuthentication(request, response, chain, authResult);
    }
}