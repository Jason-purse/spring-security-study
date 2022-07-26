package club.smileboy.app.oauth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/test")
public class TestController {
    /**
     * 获取所有的用户信息
     * @return
     */
    @GetMapping("userinfos")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public List<String> getAllUserInfosByPage() {
        return Arrays.asList("1","2","3");
    }

    @GetMapping("user/{userId}")
    @PreAuthorize("hasAnyAuthority('ADMIN','USER:READ')")
    public String getUserInfoById(@PathVariable("userId") String userId) {
        return "1";
    }
}
