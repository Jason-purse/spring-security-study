package club.smileboy.app.oauth.util;

import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

public class ResponseUtil {

    private ResponseUtil() {

    }

    /**
     * 先执行编码 ...
     * 执行一次 action ...
     * @param response 响应
     * @param consumer 消费器
     */
    public static void doAction(HttpServletResponse response, Consumer<HttpServletResponse> consumer) {
        response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        consumer.accept(response);
    }



}
