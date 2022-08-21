package club.smileboy.app.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * @author FLJ
 * @date 2022/7/25
 * @time 15:01
 * @Description oauth2 login application
 *
 *
 *
 * The OAuth 2.0 Login feature provides an application with the capability to have users
 * log in to the application by using their existing account at an OAuth 2.0 Provider (e.g. GitHub) or OpenID Connect 1.0 Provider (such as Google).
 * OAuth 2.0 Login implements the use cases: "Login with Google" or "Login with GitHub".
 *
 *
 * 也就是让用户能够通过存在的一种oauth2 提供器登录到自己开发的系统中 ... (或者通过openId登录也是可以的) ...
 */
@SpringBootApplication
@EnableScheduling
public class OauthLoginApplication {
    public static void main(String[] args) {
        SpringApplication springApplication = new SpringApplication(OauthLoginApplication.class);
        springApplication
                // 给环境前缀(让运行在相同机器上的不同应用使用不同的环境变量,它仅仅只是一个标识,不会影响最终的环境变量)  和具体的环境变量进行解耦...
                .setEnvironmentPrefix("mlnlco.app");
        springApplication.run(args);
    }
}
