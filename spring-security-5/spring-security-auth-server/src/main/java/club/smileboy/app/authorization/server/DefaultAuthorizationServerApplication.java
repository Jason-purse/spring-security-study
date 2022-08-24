package club.smileboy.app.authorization.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
/**
 * @author FLJ
 * @date 2022/8/22
 * @time 9:50
 * @Description 基础授权服务器 应用 ...
 */
@SpringBootApplication
public class DefaultAuthorizationServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(DefaultAuthorizationServerApplication.class,args);
    }
}
