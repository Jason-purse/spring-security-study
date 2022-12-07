//package club.smileboy.app.config;
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.builders.WebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
//
///**
// * @author FLJ
// * @date 2022/8/12
// * @time 16:09
// * @Description 应用 Web 配置
// */
//@Configuration
//public class AppWebAutoConfiguration implements WebSecurityCustomizer {
//
//
//    @Override
//    public void customize(WebSecurity web) {
//        web.addSecurityFilterChainBuilder(() -> {
//            HttpSecurity httpSecurity = new HttpSecurity();
//            return httpSecurity.build();
//        });
//    }
//}
