package club.smileboy.app.oauth.config;

import club.smileboy.app.oauth.util.JsonUtil;
import club.smileboy.app.oauth.util.ResponseUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.*;


/**
 * @author FLJ
 * @date 2022/7/25
 * @time 15:04
 * @Description oauth2 配置
 * <p>
 * 终端用户的代理其实就是浏览器 ... 一般来说可以这样理解(前后端分离,也就是前端) ...
 * <p>
 * <p>
 * spring security 为我们提供了常用的 registration ,它可以简化我们的开发  ...例如 github /  google ...
 * 一般来说,我的理解是,provider 提供的client(也就是我们的认证服务器) .... 不会存在还需要再次代理的请求另一个服务 ...
 * 如果有我们正确配置client 服务,能够让我们的授权服务器正确进行处理 ...
 * <p>
 * <p>
 * <p>
 * <p>
 * 由于oauth2 认证流程是:
 * Authorization Endpoint: 由客户端用来重定向用户代理到资源拥有者(认证服务器资源)中获取临时认证码
 * Authorization Endpoint: 客户端用来交换授权码获取访问token(主要是客户端认证) ...
 * <p>
 * 需要一个重定向客户端:
 * Redirection Endpoint: 授权服务器返回包含认证凭证信息的响应(本质上是通过资源拥有者的用户代理(浏览器.. / 前端页面))
 * <p>
 * 最后获取的访问token,就可以取用户信息端点(资源拥有者处)进行 需要的信息请求 ..
 * <p>
 * <p>
 * 使用oauth2 client的情况下:
 * DefaultLoginPageGeneratingFilter  负责 oauth2 登录页面默认生成, ClientRegistration.clientName as link 名称,然后发起一个授权请求(oauth2 login)
 * 然后系统的OAuth2AuthorizationRequestRedirectFilter就会负责将这个请求重定向到具体的位置 ... 那么它必须匹配这个路径,所以默认生成页面的过滤器它使用的link地址
 * 是根据OAuth2AuthorizationRequestRedirectFilter#DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{registrationId}" 进行拼接的 ...
 * 如果需要覆盖,则修改oauth2的认证端点的baseURI即可 ... 默认登录页面路径为 /login ...
 * <p>
 * 当重定向url得到了resource owner的返回,那么我们就需要开始映射用户的基本信息到我们的系统中 ...
 * 那么我们就需要使用userInfoEndpoint ...
 * 以下三种都可以得到相同的目的 ...
 * 1.  Mapping User Authorities
 * 2.  OAuth 2.0 UserService
 * 3.  OpenID Connect 1.0 UserService
 * 当成功由provider认证之后, OAuth2User.getAuthorities() /  OidcUser.getAuthorities() 被需要代理到GrantedAuthority  实例上,它们本质上都是由OAuth2AuthenticationToken 提供的 ...
 * (正如前面所提到,授权码最终交换的是token, OAuth2AuthenticationToken 代理前面的两个方法,需要获取对应的权限 ..)
 * // 例如: OAuth2AuthenticationToken.getAuthorities() is used for authorizing requests, such as in hasRole('USER') or hasRole('ADMIN').
 * <p>
 * 那么首先我们先使用 GrantedAuthoritiesMapper 进行权限映射 ... 假设我们现在有一个内存用户服务,直接抓取用户信息,进行权限映射 ...
 * 然后使用Oauth2 ... service / oidcUserService ..
 * <p>
 * open connect id 引入了一种 security token ,(也成为 ID token https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
 * 这是一个安全令牌，其中包含有关授权服务器在客户端使用时对最终用户进行身份验证的声明。
 * The ID Token is represented as a JSON Web Token (JWT) and MUST be signed using JSON Web Signature (JWS).
 * OidcIdTokenDecoderFactory 提供了 JwtDecoder 对 OidcIdToken  进行 token 验证,但是有些时候 客户端 registration 使用的算法有所不同 ..
 * 默认是RS256,在这种情况下,可以为特定的客户端指定特定期待的JWS 算法 ..
 * <p>
 * 当然在spring security中, JWS algorithm resolver 是一个 FUNCTION ,它接受一个ClientRegistration  returns the expected JwsAlgorithm,例如SignatureAlgorithm.RS256 or MacAlgorithm.HS256
 * 例如为所有的客户端配置同一套token 校验算法 .. 仅仅只需要配置OidcIdTokenDecoderFactory工厂 ...
 * <p>
 * 对于 HS256、HS384 或 HS512 等基于 MAC 的算法，使用与 client-id 对应的 client-secret 作为签名验证的对称密钥。
 * 对于超过多个的Open client 1.0认证的多个clientRegistration
 * <p>
 * <p>
 * 最后一个版块就是登出了:
 * 1. OpenID connect 1.0 Logout
 * 也就是OpenID Connect Session Management 1.0 允许使用客户端在提供商出登出终端用户 ... 其中一个策略是  RP-Initiated Logout
 * https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
 * 如果OpenID 提供器同时支持会话管理和 发现 https://openid.net/specs/openid-connect-discovery-1_0.html ,那么客户端也许可以从OpenID提供器的 Discovery Metadata中获取
 * end_session_endpoint URL ... 这能够通过配置ClientRegistration 的issuer-uri来实现这个目的 ...
 * spring:
 * security:
 * oauth2:
 * client:
 * registration:
 * okta:
 * client-id: okta-client-id
 * client-secret: okta-client-secret
 * ...
 * provider:
 * okta:
 * issuer-uri: https://dev-1234.oktapreview.com
 * 以及OidcClientInitiatedLogoutSuccessHandler ,它实现了RP-Initiated Logout
 * 也就是对于我们来说,我们仅仅只需要关注业务,登录实现我们自己的登录退出逻辑即可 ... 无需关心 Open Connect ID1.0的退出逻辑 ..
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OauthAutoConfiguration {

    /**
     * 用户的权限信息
     */
    private Map<String, List<String>> userAuthorities = new HashMap<String, List<String>>();

    OauthAutoConfiguration() {
        userAuthorities.put("zs", Arrays.asList("ADMIN", "USER_READ", "USER_WRITE"));
    }



    /**
     * 通过 SecurityFilterChain 配置
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        // 当我们在这里调用build的时候,
//        其实就是在给builder 提供SecurityConfigurer

        http
                .oauth2Login(oauth2Configurer -> {
                    oauth2Configurer
                            .redirectionEndpoint()
                            // OAuth 2.0 Login leverages the Authorization Code Grant. Therefore, the authorization credential is the authorization code.
                            // 由于oauth2 利用的是授权码授权,授权凭证是一个授权码 ...
                            // 默认重定向地址 OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI定义的baseUri ..
                            // 修改了这个也需要修改 registration提供的重定向Uri,因为它被用来拼接重定向参数( registration提供的重定向Uri 需要和 resource owner的设置一样(也就是需要匹配这个uri模式) ... 资源 拥有者会对这个地址进行校验)
                            // 这里表示需要拦截这个返回的重定向地址,进行最终的用户信息抓取 ...
                            // 当认证成功之后,我们还需要配置其他东西 ...
                            .baseUri("/api/auth/oauth2/login/code/*")
                            .and()
                            .authorizationEndpoint()
                            // 还是会保留最终的registrationId ...(如果我们使用这个注册表的话,CommonOAuth2Provider提供的) .. => 本质上最终是 ClientRegistrationRepository
                            // 这里的baseUri 和 重定向的 baseUri 做出区分,否则无限重定向
                            .baseUri("/api/auth/oauth2/authorize").
                            and()
                            .userInfoEndpoint()
//                            .userAuthoritiesMapper(userAuthoritiesMapper());
                            .userService(oAuth2UserService())
                            .oidcUserService(oidcUserService());
                })
                .logout()
                // 登出的时候,可以删除cookie内容
                // 但是这样无法使用基于hash的cookie token remember me 服务 ..
                .deleteCookies("JSESSIONID")
                .logoutSuccessHandler(logoutSuccessHandler(clientRegistrationRepository))
                // 加上这一行,我们的 DefaultLogoutGeneratePageFilter就生效了 ...
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", RequestMethod.POST.name()))
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
//                .authenticationEntryPoint(authenticationEntryPoint())
                // 它会优先匹配/api下面的路径, 然后走这个逻辑
                // 因为它和默认的oauth-client 创建的authenticationEntryPoint 进行结合,先匹配我们这里写的,然后匹配其他规则 ...
                .defaultAuthenticationEntryPointFor(authenticationEntryPoint(), new AntPathRequestMatcher("/api/**"))
                .and()
                .sessionManagement(sessionManagement())
                .authorizeHttpRequests(authorize -> authorize
//                        .mvcMatchers("/login").permitAll()
                                .anyRequest().authenticated()
                )
                .csrf()
                .disable()
                .formLogin()
//                .loginPage("/form/login/index")
//                 这里需要 一定要以 / 开头
                .loginProcessingUrl("/form/login/processing")
                .successHandler(formLoginSuccessHandler())
                .permitAll();
//                .successForwardUrl("/")
//                .failureForwardUrl("form");
        return http.build();
    }

    /**
     * 表单登录 成功处理器 ...
     */
    private AuthenticationSuccessHandler formLoginSuccessHandler() {
        return (request, response, authentication) -> {

            System.out.println("登录成功. ...");
            // 凭证信息打印
            final Object credentials = authentication.getCredentials();
            System.out.println("凭证信息:  ");
            System.out.println(credentials);
            System.out.println("身份信息:  ");
            System.out.println(authentication.getPrincipal());
            System.out.println("------------------------------------------");


            // 将认证信息,返回出去 ..
            ResponseUtil.doAction(response,res -> {
                try(ServletOutputStream outputStream = res.getOutputStream()) {
                   outputStream.write(Objects.requireNonNull(JsonUtil.toJSON(
                           new LinkedHashMap<String,Object>() {{
                               put("code",200);
                               put("message","login success !!!");
                               put("user",authentication.getPrincipal());
                           }}
                   )).getBytes());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        };
    }

    /**
     * 会话管理
     *
     * 并发会话控制
     * @return
     */
    private Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagement() {
        return configurer -> configurer.maximumSessions(1)
                // 这种方式,如果用户不退出直接关闭浏览器,那么在token 过期之前无法登录
                .maxSessionsPreventsLogin(true)
                .and()
                // 还可以执行session 创建策略
                // 也就是不会创建session,也不会使用包含在SecurityContext中的信息
                // 先不设置 ...
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                // 当用户没有在当前的登录请求中验证,那么它会创建一个非匿名的 Authentication,假设之前的过滤器都已经对它认证过 ..
                // 然后执行这个策略,如果当前用户没有认证,那么同样会执行 InvalidSessionStrategy,例如跳转页面重新登录,或者给出提示 ...
                // 根据SessionManagementConfigurer#getSessionAuthenticationStrategy() 可以发现,我们仅仅需要配置一点点东西即可,没必要自己重写SessionAuthenticationStrategy ..
//                .sessionAuthenticationStrategy(new ConcurrentSessionControlAuthenticationStrategy())
                // 无效会话策略 ...

                // 当认证失败之后(会话控制导致的认证失败), 那么我们直接重写会话认证失败处理器 ...
                .sessionAuthenticationFailureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        ResponseUtil.doAction(response,res -> {
                            try(final ServletOutputStream outputStream = res.getOutputStream()) {
                                // 然后直接告诉,当前用户已经登录即可 ...
                                outputStream.write(Objects.requireNonNull(JsonUtil.toJSON(new LinkedHashMap<String, String>() {{
                                    put("code", "400");
                                    put("message", "当前用户已经登录 !!!");
                                }})).getBytes());

                            }catch (Exception e) {
                                // pass
                            }
                        });
                    }
                })
                .sessionAuthenticationErrorUrl("/api/session/login/failure");
                // 当我们明知道请求携带JSESSIONID (检测到无效会话之后,如果重定向到login,会无济于事)
                // 因为Cookie 携带登录的时候,会触发这个函数,于是进入了死循环 ..
                // 所以我们就不再处理,交给后面的认证授权过滤器进行判断,未登录就重定向到login,在登录表达请求的时候,由于
                // 这个没有设定,那么就向下处理,交给认证授权过滤器,于是登录成功 ..
                // 总而言之下面的这个代码请求转发的是内部资源(但是一般spring mvc前后端分离项目并没有servlet 内部资源)
                // 也不建议开启重定向,导致代码进入死循环(不断判断存在无效JSESSIONID 这很离谱,直接让它登录就行了,过滤掉这个错误) ..
//                .invalidSessionStrategy((request, response) -> ResponseUtil.doAction(response, res -> {
//                    System.out.println("会话失效,无效的sessionId");
//
////                    try (ServletOutputStream outputStream = res.getOutputStream()) {
////                        outputStream.write(Objects.requireNonNull(JsonUtil.toJSON(new LinkedHashMap<String, String>() {{
////                            put("code", "200");
////                            put("message", "session outime!!!");
////                        }})).getBytes());
//                        // 请重新登录(也就是它没有直接Logout,那么携带了一个无效的sessionId,那么此时我们需要 转发到login页面进行登录
//
////                    }catch (Exception e) {
//                        // pass
////                    }
//
//                    // 重定向 login
//                    // 重定向cookie 会丢失 ..
//                    // 通过请求转发解决 ...
//                    Cookie[] cookies = request.getCookies();
//                    for (Cookie cookie : cookies) {
//                        if(cookie.getName().equals("JSESSIONID")) {
//                            cookie.setMaxAge(0);
//                            response.addCookie(cookie);
//                            break;
//                        }
//                    }
//                    try {
//                        // 请求转发 ...
//                        // 这个转发并没有走 dispatch ... 这是问题
//                        request.getRequestDispatcher("/index.html").forward(request, response);
//                    } catch (ServletException | IOException e) {
//                        e.printStackTrace();
//                    }
//                }));
    }

    /**
     * 需要这个监听HttpSession Event 事件
     * @return
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }


    private AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> ResponseUtil.doAction(response, res -> {
//            try {
//                res.getOutputStream().write(Objects.requireNonNull(JsonUtil.toJSON("未登录,请登录 !!!")).getBytes());
//            } catch (IOException e) {
//                e.printStackTrace();
//            } finally {
//                try {
//                    res.getOutputStream().close();
//                } catch (IOException e) {
//                    e.printStackTrace();
//                }
//            }
            // 目前让它重定向到 /login
            System.out.println("未登录");
            try {
                response.sendRedirect("/login");
                response.setStatus(301);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }


    private AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            // 直接处理 ..
            ResponseUtil.doAction(response, (res) -> {
                try {
                    res.getOutputStream().write(Objects.requireNonNull(JsonUtil.toJSON(new LinkedHashMap<String, String>() {{
                        put("code", "403");
                        put("message", "无权访问!!!");
                    }})).getBytes());
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        response.getOutputStream().close();
                    } catch (Exception e) {
                        // pass
                    }
                }
            });
        };
    }

    /**
     * 用户权限映射器 ...
     *
     * @return
     */
    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    // id token
                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
                    // 用户信息
                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();
                    if (userInfo == null) {
                        System.out.println("用户信息 == null");
                    }
                    System.out.printf("login success,userinfo: %s%n", JsonUtil.toJSON(userInfo));
                    System.out.println(String.format("oidc Id token is: %s", JsonUtil.toJSON(idToken)));

                    // Map the claims found in idToken and/or userInfo
                    // to one or more GrantedAuthority's and add it to mappedAuthorities

                    // 根据返回的idToken 我们可以从我们的系统中拿取权限,映射 ...
                    Map<String, Object> claims = idToken.getClaims();
                    Object iss = claims.get("iss");
                    // 判断颁布者为我们系统支持的哪一种
                    if (iss.toString().matches(".*?google.*")) {
                        Object email = claims.get("email");
                        // 根据邮箱匹配,这里我们就不匹配了,直接给它 ..
                        mappedAuthorities.add(new SimpleGrantedAuthority("ADMIN"));
                        mappedAuthorities.add(new SimpleGrantedAuthority("USER:READ"));
                        mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                    } else {
                        // 直接返回认证异常
                        throw new OAuth2AuthorizationException(new OAuth2Error("system not support this way authorize !!!"));
                    }
                } else if (authority instanceof OAuth2UserAuthority) {
                    OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority) authority;

                    // 获取用户的属性 ...
                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                    // Map the attributes found in userAttributes
                    // to one or more GrantedAuthority's and add it to mappedAuthorities
                    userAttributes.forEach((key, value) -> {
                        System.out.printf("key is %s,value is %s%n", key, value);
                    });
                }
            });

            return mappedAuthorities;
        };
    }

    /**
     * 基于代理策略的 Oauth2用户服务
     * 也就是将OAuth2UserRequest  请求 / OAuth2User交给你自己来自定义访问并抓取数据 ..
     * 或者 OidcUserRequest and OidcUser(openID connect 1.0 UserService)
     * <p>
     * OAuth2UserRequest 能够访问相关联的OAuth2AccessToken,  也就是咱们通过访问token 获取 用户的私有信息,然后再对用户进行 authorities 的映射 ...
     * <p>
     * 其实最后也就是说,OAuth2User 它的表现形式(用户的最终表现形式) = >AuthenticatedPrincipal
     * <p>
     * 默认的   DefaultOAuth2UserService uses a RestOperations when requesting the user attributes at the UserInfo Endpoint.
     * 如果我们需要定制, 也就是预处理 userinfo request,可以 DefaultOAuth2UserService.setRequestEntityConverter() 设置一个自定义的 Converter<OAuth2UserRequest, RequestEntity<?>>
     * 进行转换 ...,默认实现就是 OAuth2UserRequestEntityConverter 它只做了一件事情,将accessToken 设置到Authorization  认证头上 ...
     * <p>
     * 由于底层使用的是RestOptions,所以它们是将OAuth2UserRequest 转换为RequestEntity了 ... 所以如果你需要,也可以定制 ..
     * 例如需要定制请求的后置处理,直接自己设置一个自定义的DefaultOAuth2UserService.setRestOperations()  RestOptions ..
     * 这是通用的处理形式:
     * RestTemplate restTemplate = new RestTemplate();
     * restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
     * <p>
     * OAuth2ErrorResponseErrorHandler is a ResponseErrorHandler that can handle an OAuth 2.0 Error (400 Bad Request)
     * OAuth2ErrorHttpMessageConverter for converting the OAuth 2.0 Error parameters to an OAuth2Error ...
     */
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        OidcUserService userService = new OidcUserService();
        DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        return userRequest -> {
//            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            ClientRegistration clientRegistration = userRequest.getClientRegistration();
            // 加载用户信息 ..
            OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);
            String userNameAttributeName = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
            // 但是我们最终需要 将GrantedAuthority 进行设置 ...
            return new DefaultOAuth2User(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("USER:WRITE")), oAuth2User.getAttributes(), userNameAttributeName);


        };
    }

    /**
     * open connect ID login
     * <p>
     * 对于open connect ID 用户服务来说,它默认使用 DefaultOAuth2UserService  请求来自用户端点的用户数据  ..
     * If you need to customize the pre-processing of the UserInfo Request and/or the post-handling of the UserInfo Response,
     * you will need to provide OidcUserService.setOauth2UserService() with a custom configured DefaultOAuth2UserService.
     */
    private OidcUserService oidcUserService() {

        return new OidcUserService() {

            @Override
            public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
                OidcUser oidcUser = super.loadUser(userRequest);
                System.out.println("oidc open connect id 方式登录");
                return new DefaultOidcUser(Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("USER:READ")), oidcUser.getIdToken(), oidcUser.getUserInfo());
            }
        };
    }

//    @Bean
//    public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
//        OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
//        idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> MacAlgorithm.HS256);
//        return idTokenDecoderFactory;
//    }

    /**
     * 自定义登出处理器 ... 最终返回json  ...
     *
     * @param clientRegistrationRepository client RegistrationRepository ..
     */
    private LogoutSuccessHandler logoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {

        // 处理 open connect id 1.0 rp initiated logout ...
        // 以及其他的登出 ...
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

        // Sets the location that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        // OidcClientInitiatedLogoutSuccessHandler supports the {baseUrl} placeholder. If used, the application’s base URL,
        // like https://app.example.org, will replace it at request time.
//        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

        // 对于我们来说,我们可能直接返回json
        oidcLogoutSuccessHandler.setRedirectStrategy((request, response, url) -> {
            // 在这里我们就不再重定向了,代码怎么写取决于我们 ..
            ResponseUtil.doAction(response, res -> {
                try (OutputStream outputStream = res.getOutputStream()) {
                    outputStream.write(Objects.requireNonNull(JsonUtil.toJSON(new LinkedHashMap<String, String>() {{
                        put("code", "200");
                        put("message", "logout success!!!");
                    }})).getBytes());
                } catch (Exception e) {
                    // pass
                }
            });
        });
        return oidcLogoutSuccessHandler;
    }

}
