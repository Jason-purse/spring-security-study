package club.smileboy.app.sso.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author FLJ
 * @date 2022/7/25
 * @time 11:27
 * @Description Resource application(验证之后,带着access_token 进行资源查询) ...
 */
@SpringBootApplication
public class ResourceApplication {
    public static void main(String[] args) {
        SpringApplication.run(ResourceApplication.class,args);
    }

}
