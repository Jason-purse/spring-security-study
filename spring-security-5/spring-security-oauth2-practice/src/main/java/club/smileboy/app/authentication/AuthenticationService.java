package club.smileboy.app.authentication;
/**
 * @author FLJ
 * @date 2022/8/12
 * @time 16:15
 * @Description 认证服务,用户查询已经认证的用户信息(基于TOKEN) ...
 */
public interface AuthenticationService {

    /**
     * 根据一个token  获取当前登录认证信息
     * @param token token
     * @return 用户信息
     */
    UserInfo  findAuthenticationInfo(String token);
}
