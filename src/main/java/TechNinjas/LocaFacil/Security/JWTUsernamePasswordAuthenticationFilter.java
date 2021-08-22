package TechNinjas.LocaFacil.Security;

import TechNinjas.LocaFacil.Data.UsuarioData;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class JWTUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    //public static final int TOKEN_EXPIRACAO = 600_000;
    //public static final String TOKEN_SENHA = "ff9b5b14-0a0e-46e8-82a6-b72e27d3f06b";

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        User user = (User) authResult.getPrincipal();
        String login = user.getUsername();

        String jwt = JWT.create()
                .withClaim("login", login)
                .sign(Algorithm.HMAC256("algosecretoaqui"));

        Cookie cookie = new Cookie("token", jwt);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(60 * 30); // 30 minutos
        response.addCookie(cookie);

        super.successfulAuthentication(request, response, chain, authResult);
    }
}
