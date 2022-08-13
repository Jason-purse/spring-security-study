package club.smileboy.app.authentication;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
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
}

/**
 * memory cache
 */
class DefaultAuthenticationInfoRepository implements AuthenticationInfoRepository {
    private Map<String,UserInfo> userInfos = new ConcurrentHashMap<String,UserInfo>();

    @Override
    public UserInfo findAuthenticationInfo(String token) {
        return Optional.ofNullable(userInfos.get(token))
                .orElseThrow(() -> new IllegalStateException("当前用户未登录 ..."));
    }

    @Override
    public void saveAuthenticationInfo(UserInfo userInfo) {
        if(userInfos.containsKey(userInfo.getUserName())) {
            throw new IllegalStateException("当前用户已经登录,请不要重复登录 !!!");
        }
        userInfos.put(userInfo.getUserName(),userInfo);
    }
}