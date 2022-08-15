package club.smileboy.app;

import club.smileboy.app.util.UidUtil;
import org.junit.jupiter.api.Test;

/**
 * @author JASONJ
 * @date 2022/8/14
 * @time 12:24
 * @description 加密字段策略
 **/
public class SecretTests {
    @Test
    public void secretGenerate() {
        System.out.println(UidUtil.generateUUid());
    }
}
