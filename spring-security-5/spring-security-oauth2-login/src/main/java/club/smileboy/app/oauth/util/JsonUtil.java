package club.smileboy.app.oauth.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.ser.InstantSerializer;

import java.time.Instant;

public class JsonUtil {
    private final static ObjectMapper objectMapper = new ObjectMapper();

    static  {
        SimpleModule module = new SimpleModule();
        module.addSerializer(Instant.class,InstantSerializer.INSTANCE);
        objectMapper.registerModule(module);
    }
    private JsonUtil() {

    }

    public static String toJSON(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        }catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
