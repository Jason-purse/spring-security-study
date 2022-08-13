package club.smileboy.app.util;

import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;

/**
 * @author FLJ
 * @date 2022/8/12
 * @time 16:31
 * @Description 响应UTIL
 */
public class ResponseUtil {

    private ResponseUtil() {
        throw new IllegalArgumentException("Response util can't instantiate !!!");
    }

    public static void writeUtf8EncodingMessage(HttpServletResponse response, Operation responseConsumer) {
        response.setCharacterEncoding("utf-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        responseConsumer.execute();
    }

    public interface Operation {
        public void execute();
    }
}
