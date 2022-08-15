package club.smileboy.app;

import club.smileboy.app.authentication.UserInfo;
import club.smileboy.app.model.dto.UserDetailDto;
import club.smileboy.app.model.entity.User;
import club.smileboy.app.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeanUtils;

import java.util.Arrays;

/**
 * @author JASONJ
 * @date 2022/8/14
 * @time 12:44
 * @description jwt tests
 **/
public class JwtTests {

    @Test
    public void jwtSignTest() {
        UserInfo userInfo = UserInfo.ofDefault();
        UserDetailDto user = new UserDetailDto();
        user.setUserName("zs");
        user.setEmail("617229004@qq.com");
        user.setSex("男");
        user.setRoles(Arrays.asList("admin"));
        user.setPermissions(Arrays.asList("music:read","music:write"));
        BeanUtils.copyProperties(user,userInfo);
        System.out.println(JwtUtil.generateJwtToken(userInfo));
    }
}
