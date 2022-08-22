//package club.smileboy.app.openId.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
//import org.springframework.security.web.SecurityFilterChain;
//
///**
// * @author JASONJ
// * @date 2022/8/21
// * @time 11:02
// * @description 认证配置
// **/
//@Configuration
//public class AuthenticationConfig {
//    /**
//     * 增加一个过滤连 ..
//     * @param security
//     * @return
//     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity security) {
//        security.openidLogin()
//                .authenticationUserDetailsService(authenticationUserDetailsService())
//
//    }
//
//    private AuthenticationUserDetailsService<org.springframework.security.openid.OpenIDAuthenticationToken> authenticationUserDetailsService() {
//        return token -> {
//        }
//    }
//}
