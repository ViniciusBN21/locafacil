package TechNinjas.LocaFacil.Security;

import TechNinjas.LocaFacil.Services.UsuarioServiceDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class ConfigJWT extends WebSecurityConfigurerAdapter {
    @Autowired
    private DataSource dataSource;
//    private final UsuarioServiceDetails userService;
//    private final PasswordEncoder passwordEncoder;

//    public ConfigJWT(UsuarioServiceDetails userService, PasswordEncoder passwordEncoder) {
//        this.userService = userService;
//        this.passwordEncoder = passwordEncoder;
//    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userService).passwordEncoder(passwordEncoder);
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
                //.antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                   .formLogin()
                      .loginPage("/login")
                      .usernameParameter("email")
                   .permitAll()
                .and()
//                   .addFilter(new AutenticateJWTFilter(authenticationManager()))
//                   .addFilter(new ValidateJWTFilter(authenticationManager()))
                .addFilter(jwtUsernamePasswordAuthenticationFilter())
                .addFilter(jwtBasicAuthenticationFilter())
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }

    @Bean
    public JWTUsernamePasswordAuthenticationFilter jwtUsernamePasswordAuthenticationFilter() throws Exception {
        JWTUsernamePasswordAuthenticationFilter jwtUsernamePasswordAuthenticationFilter = new JWTUsernamePasswordAuthenticationFilter();
        jwtUsernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager());
        return jwtUsernamePasswordAuthenticationFilter;
    }

    @Bean
    public JWTBasicAuthenticationFilter jwtBasicAuthenticationFilter() throws Exception {
        return new JWTBasicAuthenticationFilter(authenticationManager());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(this.dataSource)
                .usersByUsernameQuery("select email, senha, 1 from usuario where email = ?")
                .authoritiesByUsernameQuery("select ?, 'ROLE_USER';");
    }

//    @Bean
//    CorsConfigurationSource corsConfigurationSource(){
//        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//
//        CorsConfiguration corsConfiguration = new CorsConfiguration().applyPermitDefaultValues();
//        source.registerCorsConfiguration( "/**", corsConfiguration);
//
//        return source;
//    }
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration().applyPermitDefaultValues();
        configuration.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}