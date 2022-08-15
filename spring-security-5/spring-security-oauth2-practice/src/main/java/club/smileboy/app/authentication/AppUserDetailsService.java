package club.smileboy.app.authentication;

import club.smileboy.app.event.AuthenticationCacheEvent;
import club.smileboy.app.model.dto.UserDetailDto;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;
public class AppUserDetailsService implements UserDetailsService , ApplicationContextAware, ApplicationEventPublisherAware {

    private UserDetailsRepository userDetailsRepository;

    private ApplicationEventPublisher applicationEventPublisher;

    private UserDetailsConfiguration userDetailsConfiguration;

    /**
     * 在这里发现了一个问题, 自动装配发生在 bean的Aware接口执行之前 . 于是 需要注意 .. Aware接口的执行依赖于 对应的初始化后置处理器实现 ..
     * 自动注入发生在实例化前 ..
     * @param userInfos
     */
    @Autowired
    public void setUserInfos(UserDetailsConfiguration userInfos) {
        this.userDetailsConfiguration = userInfos;
    }

    @PostConstruct
    public void init() {
        this.userDetailsRepository.setUserInfos(userDetailsConfiguration.getUserDetailDtos());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetailDto userDetailDto = userDetailsRepository.loadUserDetailByUserName(username);
        if(userDetailDto == null) {
            throw new AuthenticationServiceException("不存在当前用户信息!");
        }
        UserInfo userInfo = UserInfo.ofDefault();
        BeanUtils.copyProperties(userDetailDto,userInfo);
        return userInfo;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        userDetailsRepository = new DefaultUserDetailsRepository();
    }

    /**
     * 认证成功的事件 ..
     * @param event
     */
    @EventListener(AuthenticationSuccessEvent.class)
    public void authenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        AuthenticationCacheEvent authenticationCacheEvent = new AuthenticationCacheEvent(loadUserByUsername(authentication.getName()));
        applicationEventPublisher.publishEvent(authenticationCacheEvent);
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }
}

class DefaultUserDetailsRepository implements UserDetailsRepository {

    private Map<String, UserDetailDto> userInfos = new ConcurrentHashMap<>();

    @Override
    public UserDetailDto loadUserDetailByUserName(String userName) {
        return userInfos.get(userName);
    }

    @Override
    public void setUserInfos(List<UserDetailDto> userInfos) {
        Optional.ofNullable(userInfos)
                .map(list -> list.stream().collect(Collectors.toMap(UserDetailDto::getUserName, Function.identity())))
                .ifPresent(users ->  this.userInfos.putAll(users));
    }
}
