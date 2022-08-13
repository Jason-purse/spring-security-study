package club.smileboy.app.authentication;

import club.smileboy.app.model.dto.UserDetailDto;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

public class AppUserDetailsService implements UserDetailsService , ApplicationContextAware {

    private UserDetailsRepository userDetailsRepository;

    @Autowired
    public void setUserInfos(List<UserDetailDto> userInfos) {
        userDetailsRepository.setUserInfos(userInfos);
    }

    @Autowired
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetailDto userDetailDto = userDetailsRepository.loadUserDetailByUserName(username);
        UserInfo userInfo = UserInfo.ofDefault();
        BeanUtils.copyProperties(userDetailDto,userInfo);
        return userInfo;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        userDetailsRepository = new DefaultUserDetailsRepository();
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
                .map(list -> list.stream().collect(Collectors.toMap(UserDetailDto::getName, Function.identity())))
                .ifPresent(users ->  this.userInfos.putAll(users));
    }
}
