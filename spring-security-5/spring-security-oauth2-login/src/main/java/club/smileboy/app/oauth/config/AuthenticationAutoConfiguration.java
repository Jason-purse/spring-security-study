package club.smileboy.app.oauth.config;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Collections;

/**
 * @author FLJ
 * @date 2022/7/28
 * @time 10:29
 * @Description 认证的配置
 */
@Configuration
@AutoConfigureBefore(OauthAutoConfiguration.class)
public class AuthenticationAutoConfiguration {

    /**
     * userDetails service
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                new User("zs","123456", Collections.emptyList()),
                new User("ls","123456", Collections.emptyList())
        );
    }


    // 我们还需要密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
