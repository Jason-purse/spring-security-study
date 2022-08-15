package club.smileboy.app.authentication;

import club.smileboy.app.model.commons.JwtEntity;
import club.smileboy.app.model.entity.User;
import club.smileboy.app.util.JwtUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

/**
 * @author JASONJ
 * @date 2022/8/13
 * @time 11:35
 * @description 基于 http header 的形式 获取 SecurityContext ...
 *
 * 并且 通过 JWT Token的形式进行 token 解析,如果没有过期,那么则保留,当它更新
 *
 * 这个SecurityContext上下文仓库,仅仅解析前端的 header上的特定字段,然后给出 上下文 ...
 *
 * 原来这个 repository 是被 SecurityContextPersistenceFilter 使用 ...
 *
 *
 * 工作原理就是, 这个仓库提前解析出, SecurityContext,
 * 后面SessionManagementFilter 根据这个仓库判断,是否存在上下文,存在的情况下,上下文的认证不等于null 且不是匿名的时候,
 * 开启 会话认证策略认证  Authentication,由于我们重写了 Session认证策略,所以一旦 这个Token 对应的用户已经登录,直接告诉它当前用户已经登录 ...
 **/
public class HttpHeaderSecurityContextRepository implements SecurityContextRepository {

    /**
     * 认证Token header name
     */
    private static final String  AUTHORIZATION_HEADER = "Authorization";

    protected SecurityContext generateNewContext() {
        return this.securityContextHolderStrategy.createEmptyContext();
    }
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();


    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
        this.securityContextHolderStrategy = strategy;
    }
    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        Optional<String> identifier = resolveIdentifier(requestResponseHolder.getRequest());
        if(identifier.isPresent()) {
            JwtEntity jwtEntity = JwtUtil.parseJwtToken(identifier.get());
            SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
            UserInfo userInfo = (UserInfo) jwtEntity;
            userInfo.setToken(identifier.get());
            emptyContext.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(jwtEntity,null, userInfo.getAuthorities()));
            return emptyContext;
        }
        return SecurityContextHolder.createEmptyContext();
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        // pass
        // 对于我们来说,我们并不需要更新上下文,
        // 比如它修改了什么东西,对于Jwt Token来说,没有办法改变, 仅仅只能够忍受 ... 这就离谱 ..
        // 所以 我们必须采用redis 来保留这个token,如果它存在,则解析,否则不允许解析 ...
        // 啥也不做 ..
    }

    /**
     * 判断是否存在安全上下文 ...
     * @param request
     * @return
     */
    @Override
    public boolean containsContext(HttpServletRequest request) {
        Optional<String> identifier = resolveIdentifier(request);
        return identifier.isPresent();
    }

    private Optional<String> resolveIdentifier(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(AUTHORIZATION_HEADER));
    }
}
