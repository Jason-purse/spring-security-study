package club.smileboy.app.config;

import club.smileboy.app.authentication.*;
import club.smileboy.app.authentication.session.JwtBasedConcurrentSessionCustomizer;
import club.smileboy.app.util.JsonUtil;
import club.smileboy.app.util.ResponseUtil;
import org.springframework.beans.BeanUtils;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.InvalidSessionStrategy;

import java.util.LinkedHashMap;

/**
 * @author FLJ
 * @date 2022/8/12
 * @time 16:10
 * @Description 应用认证配置
 */
@EnableWebSecurity
@Configuration
@EnableConfigurationProperties(UserDetailsConfiguration.class)
public class AppAuthenticationConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/api/user/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .disable()
                // 取消security 本身的并发session 管理(也就是取消session方式的过期策略)..
//                .maximumSessions()
//                .maxSessionsPreventsLogin(true)
//                .sessionConcurrency(concurrencyControlConfigurer -> {
//                    concurrencyControlConfigurer.sessionRegistry(sessionRegistry());
//                })
                // 无效session 不在需要 ..(当不在创建 session的时候,前端带上 JSESSIONID 我们也不再处理) ..
                // 也就是无效session 不再处理, 其次管理会话失效的处理 ...
                // 详情查看 SessionManagementFilter 管理这一段的逻辑处理 ...
//                .invalidSessionStrategy(invalidSessionStrategy())
                // 其次 原来的并发会话判断(也就是不允许多个账户登陆的策略我们也应该替换)
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                .sessionAuthenticationFailureHandler(sessionAuthenticationFailureHandler())
                .and()
                // 应用一个自定义的并发会话控制 ...  仅仅是判断会话是否过期,如果过期,则抛出写出提示 ..
                .apply(new JwtBasedConcurrentSessionCustomizer<>(sessionRegistry()))
                .and()
                .securityContext()
                .securityContextRepository(securityContextRepository())
                .and()

                .logout()
                .logoutSuccessHandler(logoutSuccessHandler())
                .and()
                // 等待处理的 oauth2 login ..
//                .oauth2Login()
//                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint())
                // 这里的访问拒绝其实是 权限拒绝 ..
                .accessDeniedHandler(accessDeniedHandler())
                .and()
                .formLogin()
                // 收集进行认证详情的信息
//                .authenticationDetailsSource()
                .loginProcessingUrl("/api/authentication/login")
                .failureHandler(formAuthenticationFailureHandler())
                .successHandler(formLoginSuccessHandler())
                .and()
                // 当前HttpSecurity 认证提供器配置 ...
                .authenticationProvider(currentHttpSecurityAuthenticationProvider())
                .apply(new SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>() {
                    @Override
                    public void init(HttpSecurity builder) throws Exception {
                        // 设置事件监听器 ...
                        AuthenticationManagerBuilder sharedObject = builder.getSharedObject(AuthenticationManagerBuilder.class);
                        ApplicationContext context = builder.getSharedObject(ApplicationContext.class);
                        // 基于自动配置(必然包含一个) ...
                        sharedObject.authenticationEventPublisher(context.getBean(AuthenticationEventPublisher.class));
                    }
                })
                .and()
                .csrf()
                .disable()
                .build();
    }

    // 让当前认证提供器处理完毕之后 完毕 ..
    private AuthenticationProvider currentHttpSecurityAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                System.out.println("httpSecurity provider authenticate ...");
                return super.authenticate(authentication);
            }
        };
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return  daoAuthenticationProvider;
    }

    /**
     *
     * 这样也就直接处理了 ....
     * logout Success Handler
     * @return  登出处理器
     */
    private LogoutSuccessHandler logoutSuccessHandler() {
//        return httpStreamLogoutSuccessHandler();
        return (request, response, authentication) ->  {
            response.setHeader("Authorization",null);
            // 重定向到login?logout
            response.sendRedirect("/login?logout");
        };
    }

    private LogoutSuccessHandler httpStreamLogoutSuccessHandler() {
        return (request, response, authentication) ->  {
            ResponseUtil.writeUtf8EncodingMessage(response,() -> {
                response.setHeader("Authorization",null);
                try {
                    response.getOutputStream().write(JsonUtil.asJSON(new LinkedHashMap<String,String>() {{
                        put("code","200");
                        put("message","登出成功!!!");
                    }}).getBytes());
                    response.getOutputStream().close();
                }catch (Exception e) {
                    // pass
                    throw new IllegalArgumentException("系统异常 !!!");
                }
            });
        };
    }

    /**
     * 安全上下文仓库 ..
     */
    private SecurityContextRepository securityContextRepository() {
        return new HttpHeaderSecurityContextRepository();
    }

    /**
     * 自定义的 并发session 认证策略 ...
     * 通过判断jwt token 是否存在,如果存在,则不允许登录 ...
     * @return  session 认证策略
     */
    private SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new JwtBasedConcurrentSessionCustomizer.AppConcurrentSessionAuthenticationStrategy(sessionRegistry());
    }

    /**
     * 如果客户端提供了一个无效的JSESSIONID 则处理无效会话使用它 ..
     * @return
     */
    private InvalidSessionStrategy invalidSessionStrategy() {
        return (request, response) -> {
          ResponseUtil.writeUtf8EncodingMessage(response,() -> {
              try {
                  LinkedHashMap<String, String> map
                          = new LinkedHashMap<>();
                  map.put("code","200");
                  map.put("message","登录状态失效,请重新登录!!");

                  response.getOutputStream().write(JsonUtil.asJSON(map).getBytes());
              }catch (Exception e)  {
                  throw new IllegalArgumentException("系统异常 !!!");
              }
          });
        };
    }

    // 使用redis 存储 ...
    @Bean
    protected SessionRegistry sessionRegistry() {
        return new RedisSessionRegistry();
    }

    /**
     * 存在无效 会话的时候,认证失败的处理 ...
     * @return 处理器 ...
     */
    private AuthenticationFailureHandler sessionAuthenticationFailureHandler() {
        return (request, response, exception) -> {
            throw new AuthenticationServiceException("当前已登录,请勿再登录 !!!");
        };
    }

    private AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            // 请处理登录
            ResponseUtil.writeUtf8EncodingMessage(response,() -> {
                LinkedHashMap<String, String> linkedHashMap = new LinkedHashMap<String, String>() {{
                    put("code", "200");
                    put("message", "未登录,请登录,登录请求提交地址/api/authentication/login");
                }};
                try {
                    response.getOutputStream().write(JsonUtil.asJSON(linkedHashMap).getBytes());
                }catch (Exception e) {
                    // pass
                    throw new IllegalArgumentException("系统异常");
                }
            });
        };
    }

    private AccessDeniedHandler  accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            // 异常处理 ..
            ResponseUtil.writeUtf8EncodingMessage(response,() -> {
                try {
                    LinkedHashMap<String, String> linkedHashMap = new LinkedHashMap<String, String>() {{
                        put("code", "200");
                        put("message", accessDeniedException.getMessage());
                    }};
                    response.getOutputStream().write(JsonUtil.asJSON(linkedHashMap).getBytes());
                }catch (Exception e) {
                    // pass
                    throw new IllegalArgumentException("系统错误 !!!");
                }
            });
        };
    }

    /**
     * 表单登录认证失败处理器
     */
    private AuthenticationFailureHandler formAuthenticationFailureHandler() {
        return (request, response, exception) ->  {
          ResponseUtil.writeUtf8EncodingMessage(response,() -> {
              // 会话约束异常  ...
              String message =  exception.getMessage();
              if(exception instanceof SessionAuthenticationException) {
                  message = "当前已登录,请勿重复登录 !!!";
              }
              try {
                  String finalMessage = message;
                  response.getOutputStream()
                          .write(JsonUtil.asJSON(new LinkedHashMap<String,String>() {{
                              put("code","200");
                              put("message", finalMessage);
                          }}).getBytes());
              }catch (Exception e) {
                  // pass
                  throw new IllegalArgumentException("系统异常 !!!");
              }
          });
        };
    }


    /**
     * 表单登录 认证成功返回的处理器 ...
     */
    private AuthenticationSuccessHandler formLoginSuccessHandler() {
        return (request, response, authentication) -> {
            Object userInfo = authentication.getPrincipal();
            UserInfo userInfo1 = (UserInfo) userInfo;
            UserInfo userInfo2 = UserInfo.ofDefault();
            BeanUtils.copyProperties(userInfo1,userInfo2);
            userInfo2.erasePassword();
            LinkedHashMap<String, String> map = new LinkedHashMap<>();
            map.put("code","200");
            map.put("message", "login success");
            map.put("result",userInfo2.getToken());

            ResponseUtil.writeUtf8EncodingMessage(response,() -> {
                try {
                    response.getOutputStream().write(JsonUtil.asJSON(map).getBytes());
                    response.getOutputStream().close();
                }catch (Exception e) {
                    // pass
                    throw new IllegalArgumentException("系统异常 !!!");
                }
            });
        };
    }


    @Bean
    public UserDetailsService userDetailsService() {
        return new AppUserDetailsService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 由于session 不再使用,那么session 事件派发也不再需要 ..
     */
//    @Bean
//    public HttpSessionEventPublisher httpSessionEventPublisher() {
//        return new HttpSessionEventPublisher();
//    }
}
