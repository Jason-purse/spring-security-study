package club.smileboy.app.authentication;
/**
 * @author FLJ
 * @date 2022/8/12
 * @time 16:24
 * @Description 认证仓库 ..
 */
public interface AuthenticationInfoRepository {

    UserInfo findAuthenticationInfo(String token);

    void saveAuthenticationInfo(UserInfo userInfo);
}
