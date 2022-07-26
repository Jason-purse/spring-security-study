package club.smileboy.app.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author FLJ
 * @date 2022/7/26
 * @time 11:01
 * @Description OAuth2.0 client 支持
 *
 *
 * The OAuth 2.0 Client features provide support for the Client role as defined in the OAuth 2.0 Authorization Framework.
 * https://tools.ietf.org/html/rfc6749#section-1.1 ...
 *
 * 核心特性:
 * 1. 认证授权支持:
 *      1. 授权码 https://tools.ietf.org/html/rfc6749#section-1.3.1
 *      2. 刷新Token https://tools.ietf.org/html/rfc6749#section-6
 *      3. 客户端凭证 https://tools.ietf.org/html/rfc6749#section-1.3.4
 *      4. Resource Owner Password Credentials https://tools.ietf.org/html/rfc6749#section-1.3.3
 *      5. jwt bearer token https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
 *
 * 2.  Client Authentication support
 *      1. jwt bearer token
 *
 * 3.   Http Client support
 *      1. WebClient integration for Servlet Environments (for requesting protected resources)
 *
 *
 * 于是在开启oauth2 认证授权的同时,我们可以定制 oauth2 client的行为 ...
 * HttpSecurity.oauth2Client() 可以用来配置被oauth2 client使用的核心组件 ...
 * HttpSecurity.oauth2Client().authorizationCodeGrant() enables the customization of the Authorization Code grant.
 *
 *
 * 首先了解一下: OAuth2AuthorizedClientManager  负责Oauth2Client的认证或者重认证(授权)
 *  它和多个 OAuth2AuthorizedClientProvider 合作 ..
 *
 *  其次了解核心接口:
 *      1. ClientRegistration
 *          它代表者一个Oauth2 / Open client ID provider 注册的客户端呈现
 *           A client registration holds information, such as client id, client secret,
 *           authorization grant type, redirect URI, scope(s), authorization URI, token URI, and other details.
 *          它其中的一些属性我们需要了解:
 *               clientAuthenticationMethod: 使用Provider 认证这个客户端的方法: client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt and none (public clients https://tools.ietf.org/html/rfc6749#section-2.1)
 *                  也可以说,provider根据这里配置的方式,初始化合适于认证客户端的授权请求 ..
 *               authorizationGrantType:  定义了四种授权授予类型:   authorization_code, client_credentials, password,还有扩展的类型:   urn:ietf:params:oauth:grant-type:jwt-bearer
 *               redirectUri: 客户端注册到授权服务器的一个用于终端用户被认证且允许访问对应客户端之后,使用用户代理重定向的url ...
 *               scope: 也就是客户端在授权请求流中请求的scope(请求范围),例如 openid, email / profile ...
 *               authorizationUri: 授权服务器的接口地址
 *               tokenUri: 授权服务器颁发token的接口地址
 *               jwkSetUri:  用于从授权服务器检索 JSON Web 密钥 （JWK） 集的 URI，其中包含用于验证 ID 令牌的 JSON Web 签名 （JWS） 和 UserInfo 响应（可选）的加密密钥。
 *               issuerUri: 返回 OpenID Connect 1.0 提供者或 OAuth 2.0 授权服务器的颁发者标识符 uri ..
 *               configurationMetadata:  The OpenID Provider Configuration Information https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
 *                                       This information will only be available if the Spring Boot 2.x property spring.security.oauth2.client.provider.[providerId].issuerUri is configured.
 *               (userInfoEndpoint)uri: 用于访问认证的终端用户的属性或者 声明 ...的 用户 端点接口地址 ..
 *               (userInfoEndpoint)authenticationMethod: 用于发送access_token到 用户终端的认证方法,支持的方式有 header / form / query ..
 *               userNameAttributeName: 用户info 响应中的属性的名称(key) ,指示终端用户的名字和标识符 ...
 *       可以使用 OpenID Connect 提供者的配置端点或授权服务器的元数据端点的发现来初始配置 ClientRegistration。
 *       ClientRegistrations 提供了大量方便的方法来配置 ClientRegistration ,例如通过issuerUri 查询提供者 配置,例如:
 *       ClientRegistration clientRegistration =
 *          ClientRegistrations.fromIssuerLocation("https://idp.example.com/issuer").build();
 *
 *           查询到第一个就ok ...
 *           The above code will query in series https://idp.example.com/issuer/.well-known/openid-configuration,
 *           and then https://idp.example.com/.well-known/openid-configuration/issuer,
 *           and finally https://idp.example.com/.well-known/oauth-authorization-server/issuer,
 *           stopping at the first to return a 200 response.
 *
 *           ClientRegistrations.fromOidcIssuerLocation() to only query the OpenID Connect Provider’s Configuration endpoint
 *
 *    2.  ClientRegistrationRepository 用来表示从仓库中获取提供者注册的client ..( OAuth 2.0 / OpenID Connect 1.0 ClientRegistration)
 *      由于Client registration information  是存在于授权服务器中,这个仓库仅仅只是配置的一个子集,需要合理更新 ...
 *      // 要么通过网络抓取,要么通过数据库中的数据抓取(只是提供了一种方式去抓取授权服务器中托管的client registration  配置) ..
 *      spring boot 2.0 自动配置 spring.security.oauth2.client.registration.[registrationId] 的配置到 ClientRegistration ,并且所有的ClientRegistration  都存放在 ClientRegistrationRepository中 ..
 *      默认 ClientRegistrationRepository 是一个  InMemoryClientRegistrationRepository ...
 *
 *      自动配置注册了一个 ClientRegistrationRepository  到ApplicationContext 中,所以依赖注入可以使用 ..
 *
 *    3. OAuth2AuthorizedClient
 *        OAuth2AuthorizedClient  呈现为 一个已授权的客户端(也就是授权服务器承认的客户端)  当最终用户（资源所有者）已授权客户端访问其受保护的资源时，该客户端被视为已获得授权。
 *        它也提供了一个目的,用于关联OAuth2AccessToken(或者一个可选的刷新Token OAuth2RefreshToken) 到 ClientRegistration(客户端)和 资源拥有者(用于授权终端用户身份) ...
 *
 *    4. OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService
 *          这个客户端仓库用于在web请求之间持久化 OAuth2AuthorizedClient,  OAuth2AuthorizedClientService 的主要角色是在应用层面上管理 OAuth2AuthorizedClient ..
 *          从开发者的角度上看, OAuth2AuthorizedClientRepository  或者  OAuth2AuthorizedClientService  提供了一种查询与客户端关联的OAuth2AccessToken的能力(因此它也徐被用来初始化受保护的资源请求) ...
 *
 *          例如访问用户的受保护的资源 ...
 *          SpringBoot 2.x 自动配置 注册了一个  OAuth2AuthorizedClientRepository  /  OAuth2AuthorizedClientService  bean ..
 *          当然应用可以选择覆盖 ...  只需要注册 OAuth2AuthorizedClientRepository  /  OAuth2AuthorizedClientService
 *          默认的OAuth2AuthorizedClientService  是 InMemoryOAuth2AuthorizedClientService,它在内存中存储  OAuth2AuthorizedClient(被认证/ 授权的)客户端 ..
 *          除此之外,我们可以选择JDBC 实现 JdbcOAuth2AuthorizedClientService ,能够持久化 OAuth2AuthorizedClients到数据库 ...
 *          但是JDBC 实现依赖于  OAuth 2.0 Client Schema中的定义 -  https://docs.spring.io/spring-security/reference/servlet/appendix/database-schema.html#dbschema-oauth2-client
 *
 *    5. OAuth2AuthorizedClientManager /  OAuth2AuthorizedClientProvider
 *      之前我们已经大概了解了它被用来让客户端进行验证 ..
 *      OAuth2AuthorizedClientManager  负责管理 OAuth2AuthorizedClient(s) ...
 *      主要职责:
 *          - Authorizing (or re-authorizing) an OAuth 2.0 Client, using an OAuth2AuthorizedClientProvider.
 *          - 代理 OAuth2AuthorizedClient的持久化,通常使用 OAuth2AuthorizedClientService  /  OAuth2AuthorizedClientRepository  ...(可以看出来service 可以面向其他,而repository 面向jpa)
 *          - 代理一个 OAuth2AuthorizationSuccessHandler  认证成功处理器(当OAuth2.0 client 已经成功的授权(或者重新授权)...
 *          - 代理一个OAuth2AuthorizationFailureHandler  ,认证失败处理器(或者重授权失败)
 *   一个 OAuth2AuthorizedClientProvider  实现了OAuth 2.0客户端授权 / 重新授权的策略 ... 实现将通常实现一个 授权授予类型,authorization_code, client_credentials 等等 ..
 *   默认实现OAuth2AuthorizedClientManager -> DefaultOAuth2AuthorizedClientManager,它关联了一个  OAuth2AuthorizedClientProvider(也许支持多个授权授予类型)- 使用基于代理的组合而成的一个provider ...
 *   OAuth2AuthorizedClientProviderBuilder  也许被用来配置 并构建 基于代理的组合 ...
 *
 *   当授权尝试成功,默认的 DefaultOAuth2AuthorizedClientManager 将会代理到 OAuth2AuthorizationSuccessHandler 进行处理,默认将会通过 OAuth2AuthorizedClientRepository 保存 OAuth2AuthorizedClient
 *   在重新授权失败的情况下, 例如刷新token 不再有效,那么 OAuth2AuthorizedClientRepository  将会移除之前保留的 OAuth2AuthorizedClient ,通过 RemoveAuthorizedClientOAuth2AuthorizationFailureHandler 处理 ..
 *   默认的行为可以通过 setAuthorizationSuccessHandler(OAuth2AuthorizationSuccessHandler) 和 setAuthorizationFailureHandler(OAuth2AuthorizationFailureHandler).进行定制 ...
 *   默认的DefaultOAuth2AuthorizedClientManager  同样关联了一个Function<OAuth2AuthorizeRequest,Map<String,Object>>类型的 contextAttributesMapper  ..
 *   它负责将 OAuth2AuthorizeRequest 映射到 Map中并关联到OAuth2AuthorizationContext ...
 *   这是非常有用的,当你需要为OAuth2AuthorizedClientProvider提供具有必须支持的属性(s) ....
 *
 *   例如: PasswordOAuth2AuthorizedClientProvider 需要资源拥有者的 username / password必须出现在 OAuth2AuthorizationContext.getAttributes() ...
 *   那么就可以使用这个 上下文属性映射器去填充或者其他方式让它拥有这样必须存在的属性(取决于你怎么做)
 *
 *   DefaultOAuth2AuthorizedClientManager  设计能够使用在HttpServletRequest的上下文中,当在HttpServletRequest上下文之外操作时, 使用 AuthorizedClientServiceOAuth2AuthorizedClientManager 代替 ...
 *   一个service 应用是使用AuthorizedClientServiceOAuth2AuthorizedClientManager 最常见的情况,Service 应用经常运行在背后,没有任何用户交互,并且通常在系统级帐户而不是用户帐户下运行 ..
 *   一个OAuth2.0 客户端(使用client_credentials grant type)能够考虑为一个服务应用 ...
 *
 *
 */
public class OAuthClientAutoConfiguration {

    /**
     * 我们都知道  spring security 包含一个 Filter ... 叫做 DelegatingFilterProxy ->  FilterChainProxy -> many SecurityFilterChain ...
     * 那么我们先乱一写一下,oauthAutoConfiguration 已经注册了一个 .. 我们这次对oauth2Client进行处理 ...
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .oauth2Client(oauth2 -> oauth2
                        .clientRegistrationRepository(this.clientRegistrationRepository())
                        .authorizedClientRepository(this.authorizedClientRepository())
                        .authorizedClientService(this.authorizedClientService())
                        .authorizationCodeGrant(codeGrant -> codeGrant
                                .authorizationRequestRepository(this.authorizationRequestRepository())
                                .authorizationRequestResolver(this.authorizationRequestResolver())
                                .accessTokenResponseClient(this.accessTokenResponseClient())
                        )
                );
        return http.build();
    }

    /**
     *  创建一个oauth2 client 授权管理器 ...
     * @param clientRegistrationRepository 客户端注册表仓库(可以放在数据库,维护,也可以内存保存) ...
     * @param authorizedClientRepository 授权客户端仓库 ??
     * @return 以下代码返回了一个grant type支持四种的 Auth2AuthorizedClientProvider composite ..   authorizedClientManager使用这个Provider 合作进行oauth2Client 授权 ...
     */
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .password()
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }
}
