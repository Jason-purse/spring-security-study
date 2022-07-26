package club.smileboy.app.sso.client;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptTests {
    @Test
    public void test() {
        String encode = new BCryptPasswordEncoder().encode("123456");
        System.out.println(encode);
    }
}
