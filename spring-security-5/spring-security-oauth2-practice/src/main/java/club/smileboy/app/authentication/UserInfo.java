package club.smileboy.app.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author FLJ
 * @date 2022/8/12
 * @time 16:18
 * @Description 用户信息
 */
public interface UserInfo extends UserDetails {


    String getEmail();

    String getSex();

    /**
     * 所有权限
     */
    List<String> getPermissions();

    /**
     * 获取所有的角色
     * @return
     */
    List<String> getRoles();

    /**
     * 默认返回一个实现 ..
     */
    static UserInfo ofDefault() {

        return new UserInfoImpl();
    }
}

class UserInfoImpl extends User implements UserInfo {

    private String userName;

    private String password;

    private String email;

    private String sex;

    private List<String> permissions;

    private List<String> roles;

    public UserInfoImpl() {
        this(null,null);
    }

    public UserInfoImpl(String userName,String password) {
        this(userName,password,null);
    }

    public UserInfoImpl(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public UserInfoImpl(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }


    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public String getSex() {
        return sex;
    }

    @Override
    public List<String> getPermissions() {
        return permissions;
    }

    @Override
    public List<String> getRoles() {
        return roles;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        config();
        // 用我们自己的
        LinkedList<GrantedAuthority> grantedAuthorities = new LinkedList<>();
        if(roles != null && roles.size() > 0) {
            List<SimpleGrantedAuthority> roles = this.roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());
            grantedAuthorities.addAll(roles);
        }
        if(permissions != null) {
            List<SimpleGrantedAuthority> permissions = this.permissions.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
            grantedAuthorities.addAll(permissions);
        }
        return grantedAuthorities;
    }

    private void config() {
        this
    }

}
