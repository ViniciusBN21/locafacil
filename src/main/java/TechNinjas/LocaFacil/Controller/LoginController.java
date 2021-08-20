package TechNinjas.LocaFacil.Controller;

import TechNinjas.LocaFacil.Data.UsuarioData;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import TechNinjas.LocaFacil.Model.UsuarioModel;
import TechNinjas.LocaFacil.Repository.UsuarioRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Date;
import java.util.Optional;

public class LoginController {

//    public static final int TOKEN_EXPIRACAO = 600_000;
//    public static final String TOKEN_SENHA = "ff9b5b14-0a0e-46e8-82a6-b72e27d3f06b";
//
//    private final UsuarioRepository repository;
//    private final PasswordEncoder encoder;
//
//    public LoginController(UsuarioRepository repository, PasswordEncoder encoder) {
//        this.repository = repository;
//        this.encoder = encoder;
//    }
//
//    @PostMapping("/login")
//    void login(@RequestBody UsuarioData usuarioData, HttpServletResponse response) throws IOException {
//        Optional<UsuarioModel> optUsuario = repository.findByEmail(usuarioData.getUsername());
//        if (optUsuario.isEmpty()){
//            response.getWriter().write("Espaço vazio");
//        }
//
//        String senhaCriptografada = encoder.encode(usuarioData.getPassword());
//        UsuarioModel usuario = optUsuario.get();
//
//        if (!usuario.getSenha().equals(senhaCriptografada)) {
//            response.getWriter().write("Senha errada");
//        }
//
//        String token = JWT.create().withSubject(usuarioData.getUsername()). //Esse puxa o token
//                withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRACAO)).sign(Algorithm.HMAC512(TOKEN_SENHA));
//
//        Cookie cookie = new Cookie("token", token);
//        cookie.setPath("/");
//        cookie.setHttpOnly(true);
//        cookie.setMaxAge(60 * 30); // 30 minutos
//        response.addCookie(cookie);
//    }
}
