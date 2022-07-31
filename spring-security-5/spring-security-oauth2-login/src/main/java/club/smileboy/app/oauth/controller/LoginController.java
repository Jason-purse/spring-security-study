package club.smileboy.app.oauth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author FLJ
 * @date 2022/7/28
 * @time 11:00
 * @Description 登录的Controller
 */
@RestController
@RequestMapping("api/login")
public class LoginController {

    /**
     * 获取当前登录用户信息的名称
     * @param authentication 登录认证的信息
     * @return 登录用户信息
     */
    @GetMapping("userinfo")
    public String getUserInfo(Authentication authentication) {

        return authentication.getName();
    }


    @GetMapping("forward")
    public void forward(HttpServletRequest request,HttpServletResponse response) throws ServletException, IOException {
        // 转发是内部资源 .... 所以login 无法找到 ...
        request.getRequestDispatcher("/login").forward(request,response);
    }
}
