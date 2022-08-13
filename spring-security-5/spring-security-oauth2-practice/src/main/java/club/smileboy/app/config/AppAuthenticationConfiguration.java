package club.smileboy.app.config;

import club.smileboy.app.authentication.AppUserDetailsService;
import club.smileboy.app.util.JsonUtil;
import club.smileboy.app.util.ResponseUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author FLJ
 * @date 2022/8/12
 * @time 16:10
 * @Description 应用认证配置
 */
@Configuration
public class AppAuthenticationConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .successHandler(formLoginSuccessHandler())
                .and()
                .csrf()
                .disable()
                .build();
    }



    /**
     * 表单登录 认证成功返回的处理器 ...
     */
    private AuthenticationSuccessHandler formLoginSuccessHandler() {
        return (request, response, authentication) -> {
            Object details = authentication.getDetails();
            ResponseUtil.writeUtf8EncodingMessage(response,() -> {
                try {
                    response.getOutputStream().write(JsonUtil.asJSON(details).getBytes());
                    response.getOutputStream().close();
                }catch (Exception e) {
                    // pass
                    throw new IllegalArgumentException("系统异常 !!!");
                }
            });
        };
    }


    @Bean
    public UserDetailsService userDetailsService() {
        return new AppUserDetailsService();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
