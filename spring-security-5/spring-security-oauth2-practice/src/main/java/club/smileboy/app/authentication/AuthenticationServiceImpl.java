package club.smileboy.app.authentication;

import club.smileboy.app.event.AuthenticationCacheEvent;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthenticationServiceImpl implements AuthenticationService , ApplicationContextAware {

    private AuthenticationInfoRepository authenticationInfoRepository;

    @Override
    public UserInfo findAuthenticationInfo(String token) {
        return authenticationInfoRepository.findAuthenticationInfo(token);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        // 创建仓库 ..
        authenticationInfoRepository = new DefaultAuthenticationInfoRepository();
    }

    @EventListener(AuthenticationCacheEvent.class)
    public void authenticationCache(AuthenticationCacheEvent event) {
        authenticationInfoRepository.saveAuthenticationInfo(event.getUserInfo());
    }
}

/**
 * memory cache
 */
class DefaultAuthenticationInfoRepository implements AuthenticationInfoRepository {
    private Map<String,UserInfo> userInfos = new ConcurrentHashMap<String,UserInfo>();

    @Override
    public UserInfo findAuthenticationInfo(String token) {
        return Optional.ofNullable(userInfos.get(token))
                .orElseThrow(() -> new IllegalStateException("未发现登录用户信息 ..."));
    }

    @Override
    public void saveAuthenticationInfo(UserInfo userInfo) {
        userInfos.put(userInfo.getUsername(),userInfo);
    }
}