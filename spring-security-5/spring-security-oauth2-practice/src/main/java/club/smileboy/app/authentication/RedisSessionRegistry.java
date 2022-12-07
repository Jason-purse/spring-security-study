package club.smileboy.app.authentication;

import club.smileboy.app.model.dto.UserDetailDto;
import club.smileboy.app.util.JwtUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author JASONJ
 * @date 2022/8/13
 * @time 12:37
 * @description Redis Session 存储,仅仅存储Token ..
 *
 * 为了保持会话刷新 ...(并发会话控制) ..
 *
 * 如果说我们使用 JWT Token(我们不需要保存上次请求触发session保存) ...
 *
 * 相反,我们需要使用 refresh token(来刷新客户端的token) ...
 **/
public class RedisSessionRegistry implements SessionRegistry, ApplicationListener<AbstractAuthenticationEvent> {

    protected final Log logger = LogFactory.getLog(RedisSessionRegistry.class);


    private final ConcurrentHashMap<String,String> sessionCache = new ConcurrentHashMap<>(8);

    /**
     * 一个用户对应的多个会话
     */
    private final ConcurrentHashMap<String,List<String>> identifyCache = new ConcurrentHashMap<>(8);



    /**
     * 一次性拉出所有的登录会话信息是不允许的 ...
     */
    @Override
    public List<Object> getAllPrincipals() {
       throw new UnsupportedOperationException("Get all user information is not supported ...");
    }

    /**
     * 对于我们来说,这是不需要的 ....(因为我们会替换ConcurrentSessionControlAuthenticationStrategy) ...
     * 返回所有的会话信息
     * @param principal 主体身份
     * @param includeExpiredSessions 是否包括过期的会话
     */
    @Override
    public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
        // 根据一个 token 获取是否有对应的信息(它是否还登录)
        UserInfo principal1 = (UserInfo) principal;
        List<String> sessions = identifyCache.get(principal1.getEmail());
        if(sessions == null) {
            return Collections.emptyList();
        }
        return sessions.stream().map(session -> AppSessionInformation.ofDefault(session,id -> removeSessionInformation(id,principal1))).collect(Collectors.toList());
    }

    /**
     * 这个 方法是允许的 .
     * 但是这个含义取决于我们 ...
     * @param sessionId 会话id
     * @return 登录的或者过期的会话信息
     */
    @Override
    public SessionInformation getSessionInformation(String sessionId) {
        String userIdentity = sessionCache.getOrDefault(sessionId, null);
        return  userIdentity != null ? AppSessionInformation.ofDefault(sessionId,id -> {
            UserInfo userInfo = UserInfo.ofDefault();
            UserDetailDto userDetailDto = new UserDetailDto();
            userDetailDto.setEmail(userIdentity);
            BeanUtils.copyProperties(userDetailDto,userInfo);
            removeSessionInformation(id,userInfo);
        }) : null;
    }

    @Override
    public void refreshLastRequest(String sessionId) {
        // 刷新最新请求 ... ,啥也不做,等待过期之后,刷新Token ...
    }

    @Override
    public void registerNewSession(String sessionId, Object principal) {
        UserInfo principal1 = (UserInfo) principal;
        // 注册新的会话 ..
        sessionCache.put(sessionId,((UserInfo) principal).getEmail());
        identifyCache.computeIfAbsent(principal1.getEmail(), key -> new LinkedList<>())
                .add(sessionId);
    }

    @Override
    public void removeSessionInformation(String sessionId) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        // 先拿一下,有没有,如果有,则移除
        SessionInformation info = getSessionInformation(sessionId);
        if (info == null) {
            return;
        }
        if (this.logger.isTraceEnabled()) {
            this.logger.debug("Removing session " + sessionId + " from set of registered sessions");
        }
        this.sessionCache.remove(sessionId);
    }

    private void removeSessionInformation(String sessionId,Object principal) {
        removeSessionInformation(sessionId);
        UserInfo principal1 = (UserInfo) principal;
        if (this.identifyCache.containsKey(principal1.getEmail())) {
            List<String> sessionIds = this.identifyCache.get(principal1.getEmail());
            if(sessionIds != null && sessionIds.size() > 0) {
                // 对目标数组进行处理 ...
                synchronized (sessionIds) {
                    sessionIds.remove(sessionId);
                    if(sessionIds.isEmpty()) {
                        this.identifyCache.remove(principal1.getEmail());
                    }
                }
            }
        }
    }

    @Override
    public void onApplicationEvent(AbstractAuthenticationEvent event) {
        // 主体信息
        UserInfo principal =  (UserInfo) event.getAuthentication().getPrincipal();
        // 认证成功,加入一个登录的用户会话信息
        if(event instanceof AuthenticationSuccessEvent) {

            String token = JwtUtil.generateJwtToken(principal);
            removeSessionInformation(token,principal);
            registerNewSession(token,principal);
        }

        else if(event instanceof LogoutSuccessEvent) {
            removeSessionInformation(((UserInfo) event.getAuthentication().getPrincipal()).getToken(),principal);
        }
    }
}

class AppSessionInformation extends SessionInformation {
    private final Consumer<String> removeCallback;
    public AppSessionInformation(Object principal, String sessionId, Date lastRequest,Consumer<String> consumer) {
        super(principal, sessionId, lastRequest);
        this.removeCallback = consumer;
    }

    @Override
    public void expireNow() {
        // 我们这里的过期,就自动移除 ...
        removeCallback.accept(getSessionId());
    }


    public static AppSessionInformation ofDefault(String sessionId,Consumer<String> consumer) {
        return new AppSessionInformation("default",sessionId,new Date(),consumer);
    }
}
