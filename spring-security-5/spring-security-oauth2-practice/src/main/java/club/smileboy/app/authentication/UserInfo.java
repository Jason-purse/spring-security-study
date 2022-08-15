package club.smileboy.app.authentication;

import club.smileboy.app.model.commons.JwtEntity;
import club.smileboy.app.util.DateUtil;
import club.smileboy.app.util.JsonUtil;
import club.smileboy.app.util.UidUtil;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author FLJ
 * @date 2022/8/12
 * @time 16:18
 * @Description 用户信息
 */
public interface UserInfo extends UserDetails, JwtEntity {


    String getEmail();

    String getSex();

    /**
     * 所有权限
     */
    List<String> getPermissions();

    /**
     * 获取所有的角色
     *
     * @return
     */
    List<String> getRoles();

    void erasePassword();


    String getToken();

    void setToken(String token);

    /**
     * 是否配置过 ..
     *
     * @return
     */
    boolean isConfiged();

    /**
     * 默认返回一个实现 ..
     */
    static UserInfo ofDefault() {

        return new UserInfoImpl();
    }
}


class UserInfoImpl extends User implements UserInfo {
    @JsonProperty("username")
    private String userName;

    private String password;

    private String email;

    private String sex;

    private List<String> permissions;

    private List<String> roles;


    public void setSex(String sex) {
        this.sex = sex;
    }

    /**
     * token
     * <p>
     * 在登录成功之后,通过这种丑陋的方式,注入到authentication中 .. 然后传递给前端 ...
     */
    private String token;

    /**
     * 是否过期
     */
    @com.fasterxml.jackson.annotation.JsonIgnore
    private Long expireTime;

    /**
     * 默认没有配置
     */
    private boolean configed = false;


    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public void erasePassword() {
        this.password = "";
    }

    public UserInfoImpl() {
        this("default", "default");
    }

    public UserInfoImpl(String userName, String password) {
        this(userName, password, Collections.emptyList());
    }

    public UserInfoImpl(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public UserInfoImpl(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }


    public void setToken(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
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

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

    public void addRoles(List<String> roles) {
        this.roles.addAll(roles);
    }

    public void addPermissions(List<String> permissions) {
        this.permissions.addAll(permissions);
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
    @JsonIgnore
    public Collection<GrantedAuthority> getAuthorities() {
        // 用我们自己的
        LinkedList<GrantedAuthority> grantedAuthorities = new LinkedList<>();
        if (roles != null && roles.size() > 0) {
            List<SimpleGrantedAuthority> roles = this.roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());
            grantedAuthorities.addAll(roles);
        }
        if (permissions != null) {
            List<SimpleGrantedAuthority> permissions = this.permissions.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
            grantedAuthorities.addAll(permissions);
        }
        return grantedAuthorities;
    }


    @Override
    public String encryptAlgorithmType() {
        return "HS256";
    }

    @Override
    public String tokenType() {
        return "JWT";
    }

    @Override
    public String generateJwtToken(JWTCreator.Builder builder) {
        // 先给定header
        builder.withHeader(new LinkedHashMap<String, Object>() {{
            put("alg", encryptAlgorithmType());
            put("type", tokenType());
        }});


        // 我们自己最常用的几种 ,iss(颁发者) / aud(受众)  / expire(过期时间) / sub(主体,主题), appId(app id) / jti(jwt ID,这个就可以作为 sessionId)
        // iat 颁发时间

        // 所以我们到时候,自己还要开发一个应用管理平台 .. /appId
        builder.withClaim("iss", "www.smileboy.club");
        builder.withClaim("aud", "music.smileboy.club");
        builder.withClaim("sub", "music platform");
        // 获取最终时间
        builder.withClaim("exp", DateUtil.toEpochMillis(30 * 1000 * 60));
        builder.withClaim("appId", "music_smileboy.club_1");
        builder.withClaim("jti", UidUtil.generateUUid());
        builder.withClaim("iat", DateUtil.nowEpochMillis());
        // claims
        builder.withClaim("principal", JsonUtil.asJSON(this));

        String sign = builder.sign(Algorithm.HMAC256("397546ff-c551-8974-1126-0788049990ce"));
        setToken(sign);
        return sign;
    }

    @Override
    public void config(DecodedJWT decodeInfo) {
        String algorithm = decodeInfo.getAlgorithm();
        if (!encryptAlgorithmType().equalsIgnoreCase(algorithm)) {
            throw new IllegalArgumentException("can't resolve jwt token,because algorithm type mismatch !!");
        }
        if (!tokenType().equalsIgnoreCase(decodeInfo.getType())) {
            throw new IllegalArgumentException("can't resolve jwt token,because jwt type mismatch !!");
        }

        try {
            Claim principal = decodeInfo.getClaim("principal");
            UserInfoImpl userInfo = JsonUtil.fromJson(principal.asString(), getClass());
            if (userInfo == null) {
                throw new IllegalArgumentException("user info must not be null");
            }
            // over
            BeanUtils.copyProperties(userInfo, this);

            // 过期时间计算
            this.expireTime = decodeInfo.getExpiresAt().getTime();
            this.configed = true;
        } catch (Exception e) {
            throw new IllegalArgumentException("can't resolve jwt token, because jwt data mismatch !!");
        }
    }

    @Override
    @com.fasterxml.jackson.annotation.JsonIgnore
    public Boolean isExpired() {
        if (expireTime == null) {
            throw new IllegalArgumentException("expire must not be null, call the config method before calling it from jwt parse or full initialize it ...");
        }
        return Instant.now().toEpochMilli() - expireTime > 0 ? Boolean.TRUE : Boolean.FALSE;
    }

    @Override
    @JsonIgnore
    public boolean isConfiged() {
        return configed;
    }
}
