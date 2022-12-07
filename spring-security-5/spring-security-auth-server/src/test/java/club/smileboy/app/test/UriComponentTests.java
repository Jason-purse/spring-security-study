package club.smileboy.app.test;

import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

/**
 * @author JASONJ
 * @date 2022/8/24
 * @time 17:07
 * @description schema acquire
 **/
public class UriComponentTests {
    public static void main(String[] args) {
        System.out.println(UriComponentsBuilder.fromUri(URI.create("http://localhost:8080/api/authentication/"))
                .build().getScheme());
    }
}
