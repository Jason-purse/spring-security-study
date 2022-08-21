package club.smileboy.app;

import org.junit.jupiter.api.Test;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.LinkedHashMap;

/**
 * @author FLJ
 * @date 2022/8/19
 * @time 10:00
 * @Description uri components tests
 *
 *
 * 在请求的构建中,学习到了几个工具类
 *
 * UriComponentsBuilder
 * DefaultUriBuilderFactory
 * UriUtils
 *
 */
public class UriComponentsTests {


    @Test
    public void test() {

        System.out.println(UriComponentsBuilder.fromUriString("{baseSchema}{baseHost}:{basePort}/login/oauth2/code/{registrationId}")
                .buildAndExpand(new LinkedHashMap<String, String>() {{
                    put("baseUrl", "http://localhost/api");
                    put("basePort", "8080");
                    put("baseSchema", "http://");
                    put("baseHost", "localhost");
                    put("registrationId", "google");
                    put("basePath", "api");
                    put("action", "login");
                }}));

    }

    @Test
    public void uriFactory() {
        DefaultUriBuilderFactory defaultUriBuilderFactory = new DefaultUriBuilderFactory("https://accounts.google.com/");
        defaultUriBuilderFactory
                .setEncodingMode(DefaultUriBuilderFactory.EncodingMode.URI_COMPONENT);
        System.out.println(
                defaultUriBuilderFactory.uriString("o/oauth2/v2/auth").build());
    }
}
