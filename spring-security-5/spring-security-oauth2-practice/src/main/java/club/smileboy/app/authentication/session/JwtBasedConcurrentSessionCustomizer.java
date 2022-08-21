package club.smileboy.app.authentication.session;

import club.smileboy.app.authentication.UserInfo;
import club.smileboy.app.model.commons.JwtEntity;
import club.smileboy.app.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * @author JASONJ
 * @date 2022/8/14
 * @time 11:03
 * @description 同样为了控制用户的同时在线Token ...数量(也相当于防止重复登录)...
 * <p>
 * <p>
 * 为什么需要写这个(首先,security 本身的 ConcurrentSessionFilter 是控制session 过期的,进行处理) ...
 * 所以我们应该需这个的替代版来执行  token 刷新 ...
 * <p>
 * 其次,session 并发控制也需要,它执行在并发session 控制过滤器之后,然后判断是否存在并发的session 登录(这里的session 指的是一个账户的登录状态) ...
 * 如果已经登录了不需要再登录,否则 抛出异常 ...
 * <p>
 * 最后,由于security 本身的session 认证策略是可定制的,那么 session 并发校验就不需要这个定制器 处理 ... 我们仅仅需要关心 token 刷新 ...
 **/
public class JwtBasedConcurrentSessionCustomizer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<SessionManagementConfigurer<H>, H> {
    private final SessionRegistry sessionRegistry;
    private RequestMatcher loginMatcher;
    private AuthenticationTrustResolver authenticationTrustResolver;
    public JwtBasedConcurrentSessionCustomizer(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }
    @Override
    public void configure(H builder) throws Exception {
        AppConcurrentSessionFilter filter = null;
        if(loginMatcher != null && authenticationTrustResolver != null) {
            filter = new AppConcurrentSessionFilter(sessionRegistry,authenticationTrustResolver,loginMatcher);
        }
        else if(loginMatcher != null) {
            filter = new AppConcurrentSessionFilter(sessionRegistry,loginMatcher);
        }

        else if(authenticationTrustResolver != null) {
            filter = new AppConcurrentSessionFilter(sessionRegistry,authenticationTrustResolver);
        }
        else {
            filter = new AppConcurrentSessionFilter(sessionRegistry);
        }
        // 配置去替代并发会话控制 ...
        builder.addFilterBefore(this.postProcess(filter), ConcurrentSessionFilter.class);
    }


    public JwtBasedConcurrentSessionCustomizer<H> loginMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher,"login matcher must not be null !!!");
        this.loginMatcher = requestMatcher;
        return this;
    }

    public JwtBasedConcurrentSessionCustomizer<H> trustAuthenticationResolver(AuthenticationTrustResolver authenticationTrustResolver) {
        this.authenticationTrustResolver = authenticationTrustResolver;
        return this;
    }

    public static class AppConcurrentSessionAuthenticationStrategy implements SessionAuthenticationStrategy , MessageSourceAware {

        private final SessionRegistry sessionRegistry;

        public AppConcurrentSessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
            Assert.notNull(sessionRegistry,"sessionRegistry must be exists !!");
            this.sessionRegistry = sessionRegistry;
        }

        protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
        /**
         * 直接抛出异常
         */
        private boolean exceptionIfMaximumExceeded = true;

        @Override
        public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
            List<SessionInformation> allSessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
            if(allSessions != null && allSessions.size() > 1) {
                allowableSessionsExceeded(allSessions,1,sessionRegistry);
            }
            // 否则啥也不做
        }

        /**
         * Allows subclasses to customise behaviour when too many sessions are detected.
         * @param sessions either <code>null</code> or all unexpired sessions associated with
         * the principal
         * @param allowableSessions the number of concurrent sessions the user is allowed to
         * have
         * @param registry an instance of the <code>SessionRegistry</code> for subclass use
         *
         */
        protected void allowableSessionsExceeded(List<SessionInformation> sessions, int allowableSessions,
                                                 SessionRegistry registry) throws SessionAuthenticationException {

            if (this.exceptionIfMaximumExceeded || (sessions == null)) {
                if(sessions != null) {
                    clearSessions(sessions,allowableSessions,1,sessions.size());
                }
                throw new SessionAuthenticationException(
                        this.messages.getMessage("ConcurrentSessionControlAuthenticationStrategy.exceededAllowed",
                                new Object[] { allowableSessions }, "Maximum sessions of {0} for this principal exceeded"));
            }
            int maximumSessionsExceededBy = sessions.size() - allowableSessions + 1;
            clearSessions(sessions, allowableSessions,0,maximumSessionsExceededBy);
        }

        private void clearSessions(List<SessionInformation> sessions, int allowableSessions,int startIndex,int endIndex) {
            // Determine least recently used sessions, and mark them for invalidation
            // 在我们这种方式中,根本不需要排序 ...
//            sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
            List<SessionInformation> sessionsToBeExpired = sessions.subList(startIndex, endIndex);
            for (SessionInformation session : sessionsToBeExpired) {
                session.expireNow();
            }
        }

        @Override
        public void setMessageSource(MessageSource messageSource) {
            this.messages = new MessageSourceAccessor(messageSource);
        }
    }
}

/**
 * 自定义的 token 过期处理 ..
 * 可以经过 应用上下文处理 ...
 *
 * 由于它过滤在登出之前,登出之后,进行了重定向 ... 导致这里拦截到就直接给出会话过期,没有登出成功提示 ！！！
 * 所以我们需要配合登出处理器,才能正确处理
 */
class AppConcurrentSessionFilter extends GenericFilterBean {
    private final Logger logger = LoggerFactory.getLogger(AppConcurrentSessionFilter.class);

    private final SessionRegistry  sessionRegistry;
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    /**
     * 登录路径 ...
     */
    private  RequestMatcher requestMatcher = new AntPathRequestMatcher("/login");

    public AppConcurrentSessionFilter(SessionRegistry sessionRegistry) {
        this(sessionRegistry,new AntPathRequestMatcher("/login"));
    }

    public AppConcurrentSessionFilter(SessionRegistry sessionRegistry,AuthenticationTrustResolver authenticationTrustResolver,RequestMatcher loginMatcher) {
        Assert.notNull(sessionRegistry,"sessionRegistry must not be null !!");
        Assert.notNull(trustResolver,"trustResolver must not be null !!");
        Assert.notNull(requestMatcher,"loginMatcher must not be null !!");
        this.sessionRegistry = sessionRegistry;
        this.trustResolver = authenticationTrustResolver;
        this.requestMatcher = loginMatcher;
    }

    public AppConcurrentSessionFilter(SessionRegistry sessionRegistry,RequestMatcher loginMatcher) {
        this(sessionRegistry,new AuthenticationTrustResolverImpl(),loginMatcher);
    }

    public AppConcurrentSessionFilter(SessionRegistry sessionRegistry,AuthenticationTrustResolver authenticationTrustResolver) {
        this(sessionRegistry,authenticationTrustResolver,new AntPathRequestMatcher("/login"));
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        doInternalFilter(servletRequest, servletResponse,filterChain);
    }

    private void doInternalFilter(ServletRequest servletRequest, ServletResponse servletResponse,FilterChain filterChain) throws ServletException, IOException {

        // login 路径我们不拦截 ...
        if (!requireValidSession((HttpServletRequest) servletRequest)) {
            filterChain.doFilter(servletRequest,servletResponse);
            return ;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 非匿名才解析 ...
        if (authentication != null && !trustResolver.isAnonymous(authentication)) {
            UserInfo principal = (UserInfo) authentication.getPrincipal();
            boolean isExpired = false;
            if(principal.isConfiged()) {
                isExpired = principal.isExpired();
            }
            else {
                JwtEntity jwtEntity;
                try {
                    jwtEntity = JwtUtil.parseJwtToken(principal.getToken());
                    isExpired = jwtEntity.isExpired();
                } catch (Exception e) {
                    // 服务器无法解析这个token,那么让过滤链继续处理 ...
                    logger.debug("server can't resolve jwt token, so simple skip it ...");
                }
            }

            // 如果未过期,但是从数据中心查到它过期了,那么显式的提醒它 ..
            // 否则 本身就过期了,就当作匿名用户登录即可 ...
            if(!isExpired) {
                // 如果redis不存在这个token 也算未登录 ...
                SessionInformation sessionInformation = sessionRegistry.getSessionInformation(principal.getToken());
                if(sessionInformation == null) {
                    isExpired = true;
                }

                // 判断是否过期了 ...
//                if (isExpired) {
//                    // 如果过期了 ..
//                    ResponseUtil.writeUtf8EncodingMessage(servletResponse,() -> {
//                        try {
//                            LinkedHashMap<String, String> map = new LinkedHashMap<String, String>() {{
//                                put("code", "200");
//                                put("message", "您的账户已经过期 ...");
//                            }};
//                            servletResponse.getOutputStream().write(JsonUtil.asJSON(map).getBytes());
//                        }catch (Exception e) {
//                            // pass
//                            throw new IllegalArgumentException("系统异常 !!!");
//                        }
//                    });
//                    return ;
//                }
            }
            if(isExpired) {
                // 匿名用户 ..
                doAnonymousAuthentication();
            }

        }
        filterChain.doFilter(servletRequest,servletResponse);
    }

    private boolean requireValidSession(HttpServletRequest servletRequest) {
        return !requestMatcher.matcher(servletRequest).isMatch();
    }

    // 给出匿名认证
    // 后续的anonymousAuthenticationFilter 会处理
    private void doAnonymousAuthentication() {
        SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(emptyContext);
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        Assert.notNull(trustResolver, "trustResolver cannot be null");
        this.trustResolver = trustResolver;
    }
}
