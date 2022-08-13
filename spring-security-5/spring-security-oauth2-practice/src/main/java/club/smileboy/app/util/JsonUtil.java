package club.smileboy.app.util;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.lang.Nullable;

import java.io.InputStream;
import java.util.Map;

/**
 * @author FLJ
 * @date 2021/11/15 12:39
 * @description json util
 */
public class JsonUtil {
    private JsonUtil() {

    }

    private final static ObjectMapper objectMapper = new ObjectMapper();
    static  {
        objectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES,false);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,false);
        objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS,false);
        // 至少保证getter方法的字段正确序列化出来
        // 切记getter 需要注意形式
        objectMapper.setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.ANY);
    }

    /**
     * 从输入流中获取一个map
     * @param stream stream data
     * @return Map<?,?>
     */
    public static Map<String,Object> asMap(@Nullable InputStream stream) {
        if(stream != null) {
            try {
                return objectMapper.readValue(stream, new TypeReference<Map<String,Object>>() {});
            }catch (Exception e) {
                // pass
            }
        }
        return null;
    }

    public static Map<String,?> asMap(String value) {
        if(value != null) {
            try {
                return objectMapper.readValue(value, new TypeReference<Map<String,?>>() {
                });
            }catch (Exception e) {
                // pass
            }
        }
        return null;
    }

    /**
     * 转换到目标类对象
     * @param object origin
     * @param clazz target
     * @param <T> class type
     * @return instance or null
     */
    public static <T> T convertTo(Object object,Class<T> clazz) {
        if(clazz != null && object != null) {
           try {
               return objectMapper.convertValue(object, clazz);
           }catch (Exception e) {
               // pass
           }
        }
        return null;
    }

    /**
     * 使用typeReference 解析实例
     * @param object data
     * @param typeReference obtain class type reference
     * @param <T> class type
     * @return instance or null
     */
    public static <T> T convertTo(Object object,TypeReference<T> typeReference) {
        if(typeReference != null && object != null) {
            try {
                return objectMapper.convertValue(object, typeReference);
            }catch (Exception e) {
                // pass
            }
        }
        return null;
    }

    /**
     * 转为json
     * @param object target
     * @return "" or object json
     */
    public static String asJSON(Object object) {
        if(object != null) {
            try{
                return objectMapper.writeValueAsString(object);
            }catch (Exception e) {
                // pass
            }
        }
        return  "";
    }
}
