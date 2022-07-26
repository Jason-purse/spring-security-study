package club.smileboy.app.sso.resource.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("order")
public class OrderController {

    /**
     * 获取资源信息 ...
     * @param principal
     * @param authentication
     * @return
     */
    @GetMapping("/info")
    public String info(Principal principal, Authentication authentication) {
        System.out.println(principal);
        System.out.println(authentication.getPrincipal());
        System.out.println(authentication.getAuthorities());
        return "hello world";
    }
}