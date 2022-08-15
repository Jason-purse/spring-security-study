package club.smileboy.app.controller;

import club.smileboy.app.authentication.UserInfo;
import club.smileboy.app.model.dto.UserDetailDto;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/user")
public class UserController {

    @Autowired
    private SessionRegistry sessionRegistry;

    @GetMapping("{email}")
    public String getLoginUserStatus(@PathVariable("email") String email) {
        UserDetailDto userDetailDto = new UserDetailDto();
        userDetailDto.setEmail(email);
        UserInfo userInfo = UserInfo.ofDefault();
        BeanUtils.copyProperties(userDetailDto,userInfo);
        List<SessionInformation> allSessions = sessionRegistry.getAllSessions(userInfo, false);
        if(allSessions != null && allSessions.size() > 0) {
            return "logined !!";
        }
        return "no login";
    }

    @GetMapping("current/info")
    public String getCurrentLoginUserIdentify(@AuthenticationPrincipal Object principal) {
        UserInfo principal1 = (UserInfo) principal;
        return ((UserInfo) principal).getEmail();
    }
}
