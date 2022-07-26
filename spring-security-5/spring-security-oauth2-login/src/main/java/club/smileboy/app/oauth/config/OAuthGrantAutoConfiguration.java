package club.smileboy.app.oauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

import java.util.function.Consumer;

/**
 * @author FLJ
 * @date 2022/7/26
 * @time 13:48
 * @Description Oauth2 authorization grant ...
 *
 *
 * 1. 授权授予分为很多种:
 *      详情参考OAuth2 认证框架 rfc ...  https://tools.ietf.org/html/rfc6749#section-1.3.1
 *      1. Authorization Code
 *          1. 获取Authorization  ..
 *              参考 授权请求 / 响应协议流 了解 授权码授予 ..
 *          2. 初始化授权请求
 *              OAuth2AuthorizationRequestRedirectFilter 使用 OAuth2AuthorizationRequestResolver  解析一个 OAuth2AuthorizationRequest  并初始化授权码授予工作流(通过
 *              重定向终端用户的用户代理到授权服务器的授权端点)
 *
 *              OAuth2AuthorizationRequestResolver 的主要角色是从一个提供的Web 请求解析 OAuth2AuthorizationRequest,DefaultOAuth2AuthorizationRequestResolver 的默认实现
 *              匹配默认路径(/oauth2/authorization/{registrationId},抓取 registrationId)的授权请求(前面提到根据拦截对应的请求 使得用户代理重定向到授权服务器的授权端点)然后解析一个OAuth2AuthorizationRequest ...
 *              通过抓取的registrationId 拿取关联的ClientRegistration 构建一个 OAuth2AuthorizationRequest  ...
 *              只要我们正确配置 registration ,那么 OAuth2AuthorizationRequestRedirectFilter  最终会拦截来自 /oauth2/authorization/{registrationId}的请求,初始化认证请求并开启授权码授予流程
 *              注意:
 *                  AuthorizationCodeOAuth2AuthorizedClientProvider  是一个 OAuth2AuthorizedClientProvider 的实现(针对授权码授予),它会初始化由OAuth2AuthorizationRequestRedirectFilter
 *                  重定向的授权请求 ..
 *                  如果OAuth2.0 客户端是一个 Public Client ... https://tools.ietf.org/html/rfc6749#section-2.1 ..也就是不会存在客户端认证方式 ...
 *                  可能registration配置就不再需要client_secret 且包含一个 client-authentication-method = none
 *              使用代码交换的证明密钥（PKCE）支持公共客户,如果客户端运行在不信任的环境中(例如,原生应用或者基于web浏览器的应用)因此不能够保证凭证的机密性,PKCE将自动的使用(当条件成立)
 *              Prof Key for Code Exchange: https://tools.ietf.org/html/rfc7636
 *              条件如下:
 *                  1. client-secret 被忽略 / 或者为空
 *                  2. client-authentication-method 设置为 "none"(ClientAuthenticationMethod.NONE) ..
 *              如果OAuth 2.0Provider 对于 Confidential Clients(https://tools.ietf.org/html/rfc6749#section-2.1)支持 PKCE,你也许能够可选的使用
 *              DefaultOAuth2AuthorizationRequestResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce()) 配置它 ...
 *              DefaultOAuth2AuthorizationRequestResolver  使用UriComponentsBuilder 且支持URI 模板变量(例如redirect-uri)
 *              例如:
 *                       spring:
 *                           security:
 *                             oauth2:
 *                              client:
 *                                 registration:
 *                                   okta:
 *                                     ...
 *                                     redirect-uri: "{baseScheme}://{baseHost}{basePort}{basePath}/authorized/{registrationId}"
 *                                     ...
 *              {baseUrl} resolves to {baseScheme}://{baseHost}{basePort}{basePath} ..
 *              配置redirect-uri 使用URI 模板变量特别有用(当OAuth2.0 客户端运行在 一个代理服务器之后,这能够确保 X-Forwarded-*请求头能够被用来扩展redirect-uri) ...
 *              例如正确渲染出重定向地址,而不是处于代理服务器之后的本机地址(这样才是正确的),一般来说,我们应该只信任我们的前端代理服务器转发给我们的请求 ...所以可以配置 转发头匹配策略 ...
 *              详情需要参考spring boot https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#howto.webserver.use-behind-a-proxy-server
 *
 *
 *          3. 定制授权请求
 *              OAuth2AuthorizationRequestResolver 使用的最主要的一种情况是,能够自定义授权请求(例如使用额外的参数,定义在OAuth2.0 授权框架定义的标准参数) ...
 *              例如: OpenID Connect 定义了额外的OAuth2.0请求参数(扩展了定义在OAuth 2.0 Authorization Framework的标准参数),其中一个就是prompt 参数 ...
 *              可选的。空格分隔、区分大小写的 ASCII 字符串值列表，指定授权服务器是否提示最终用户重新进行身份验证和同意。定义的值是：none、login、consent、select_account ..
 *              例如以下例子展示了DefaultOAuth2AuthorizationRequestResolver 使用Consumer<OAuth2AuthorizationRequest.Builder> 为oauth2Login()定义授权请求 ... 通过
 *              包括request parameter prompt=consent ..
 *
 *              一些通用修改,这样就够了,但是为了完全控制授权请求URI的构建通过简单的覆盖OAuth2AuthorizationRequest.authorizationRequestUri 即可 ...
 *              OAuth2AuthorizationRequest.Builder.build() 也能够构造 OAuth2AuthorizationRequest.authorizationRequestUri ...
 *              它呈现了  Authorization Request URI 且包含了所有的查询参数(使用application/x-www-form-urlencoded格式) ..
 *
 *         4. 存储AuthorizationRequest
 *              AuthorizationRequestRepository 负责持久化 OAuth2AuthorizationRequest(在请求初始化直到 授权响应接收到之前(回调))
 *              OAuth2AuthorizationRequest 被用来关联和验证AuthorizationResponse ...
 *              AuthorizationRequestRepository 的默认实现是 HttpSessionOAuth2AuthorizationRequestRepository,它将存储OAuth2AuthorizationRequest  到HttpSession中 ...
 *              如果你有自定义AuthorizationRequestRepository的实现 ,可以直接配置:
 *
 *              http.oauth2Client(oauth2 -> oauth2
 * 				.authorizationCodeGrant(codeGrant -> codeGrant
 * 					.authorizationRequestRepository(this.authorizationRequestRepository())
 * 					...
 * 				    )
 * 			    );
 * 			5. 请求一个访问Token
 * 		        可以参考  授权码授予的   Access Token Request/Response protocol flow .. https://tools.ietf.org/html/rfc6749#section-4.1.3
 * 		        OAuth2AccessTokenResponseClient的默认实现(针对授权码授予)是 DefaultAuthorizationCodeTokenResponseClient, 它使用RestOperations 用交换的 授权码 去在
 * 		        授权服务器的Token 端点获取 access token ...
 * 		        默认的 DefaultAuthorizationCodeTokenResponseClient 是十分灵活的, 它允许你定制 Token请求的预处理 以及 token响应的后置处理 ...
 * 		        在前后端分离的项目中,一般来说这些都归到前端去处理了 ...,我们只需要拿到最终的 accessToken 访问出用户信息然后传递給后端进行真正的token 派发以及 用户信息绑定 ...
 * 		    6.定制访问token 请求
 * 		        如果你需要预处理 token请求,通过DefaultAuthorizationCodeTokenResponseClient.setRequestEntityConverter() 通过一个自定义的Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>>
 * 		            进行定制,同从用户端点拿取信息的RequestEntity 类似 ... 都可以convert, 默认OAuth2AuthorizationCodeGrantRequestEntityConverter 构建了
 * 		            标准的OAuth 2.0 Access Token Request(https://tools.ietf.org/html/rfc6749#section-4.1.3)的RequestEntity 呈现 ..
 * 		            然而,通过自定义的转换器允许你扩展标准Token请求也可以增加自定义参数 ...
 * 		            如果仅仅只是自定义请求参数,你能够提供OAuth2AuthorizationCodeGrantRequestEntityConverter.setParametersConverter() 提供一个自定义的
 * 		            Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> 转换器能够完全覆盖这个请求发送的参数 .. 通常这比直接构造一个RequestEntity 更简单 ...
 * 		            如果你仅仅只是想增加一些额外的参数, 你只需要提供OAuth2AuthorizationCodeGrantRequestEntityConverter.addParametersConverter(), 它将会执行且将属性和已有的RequestEntity
 * 		            的请求参数进行聚合 ..(底层是将它们聚合成一个复合的转换器处理) ..
 * 		            自定义转换器必须返回 OAuth 2.0 访问令牌请求的有效 RequestEntity 表示，该请求可由预期的 OAuth 2.0 提供者理解。
 * 		   7.定制访问Token 响应
 * 		        另一方面你可以定制Token响应的后置处理,你将需要提供DefaultAuthorizationCodeTokenResponseClient.setRestOperations() ,自定义一个RestOperations 拦截响应处理 ..
 * 		        默认的如下:
 * 		        RestTemplate restTemplate = new RestTemplate(Arrays.asList(
 * 		         new FormHttpMessageConverter(),
 * 		         new OAuth2AccessTokenResponseHttpMessageConverter()));
 *
 *                  restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
 *
 *
 *              SpringMvc FormHttpMessageConverter 是必须的(因为在发送OAuth2.0访问Token请求的时候 使用了它) ..
 *              OAuth2AccessTokenResponseHttpMessageConverter  是一个HttpMessageConverter 进行OAuth2.0 访问token 的响应 转换... 你能够提供
 *              OAuth2AccessTokenResponseHttpMessageConverter.setAccessTokenResponseConverter() 使用 Converter<Map<String, Object>, OAuth2AccessTokenResponse> 转换OAuth 2.0 Access Token
 *              响应参数到 OAuth2AccessTokenResponse ..
 *
 *              OAuth2ErrorResponseErrorHandler  是一个ResponseErrorHandler 能够处理Oauth2.0 错误,例如 400 错误请求,它使用一个 OAuth2ErrorHttpMessageConverter  转换 OAuth2.0 错误参数到
 *              OAuth2Error ...
 *
 *              无论你定制DefaultAuthorizationCodeTokenResponseClient  还是提供自定义的 OAuth2AccessTokenResponseClient,你都需要配置oauth2Client 配置 ..
 *
 * 2.刷新Token
 *     Please refer to the OAuth 2.0 Authorization Framework for further details on the Refresh Token. https://tools.ietf.org/html/rfc6749#section-1.5
 *     1. 刷新访问token
 *          OAuth2AccessTokenResponseClient  针对刷新token 授予的默认实现 DefaultRefreshTokenTokenResponseClient, 它使用RestOperations(当需要在授权服务器Token 端点刷新访问token时使用) ...
 *          默认的 DefaultRefreshTokenTokenResponseClient  是十分灵活的,允许你定制 Token请求的预处理 或者Token 响应的后置处理 ..
 *
 *     2. 定制访问Token 请求
 *          如果你需要定制预处理,DefaultRefreshTokenTokenResponseClient.setRequestEntityConverter(),通过 Converter<OAuth2RefreshTokenGrantRequest, RequestEntity<?>> 即可 ..
 *          默认的 OAuth2RefreshTokenGrantRequestEntityConverter  将会构建一个 标准的 OAuth 2.0 Access Token Request的RequestEntity 呈现 ..
 *          然而,提供了一个自定义Converter,可以允许你扩展标准的Token 请求并增加自定义的参数(parameter) ...
 *
 *          如果仅仅是定制参数,你可以设置 OAuth2RefreshTokenGrantRequestEntityConverter.setParametersConverter()  Converter<OAuth2RefreshTokenGrantRequest, MultiValueMap<String, String>>
 *              用来将一个请求的params转换为一个Map .. 能够完整的覆盖这个请求的请求参数 ...(这比直接构造一个RequestEntity更简单 ..)
 *          很类似,如果仅仅只是增加额外的参数,提供 OAuth2RefreshTokenGrantRequestEntityConverter.addParametersConverter() 使用 Converter<OAuth2RefreshTokenGrantRequest, MultiValueMap<String, String>> 构造一个
 *          聚合的Converter 来实现额外参数的增加 ..
 *          自定义转换器必须返回有效的 OAuth 2.0 Access Token Request 的RequestEntity 呈现(它们必须被预期的OAuth 2.0 提供器理解) ..
 *
 *     3. 定制访问Token Response ...
 *          另一方面定制Token 响应的后置处理,其实都差不多,DefaultRefreshTokenTokenResponseClient.setRestOperations() ,设置一个自定义的RestOperations 处理 ..
 *          RestTemplate restTemplate = new RestTemplate(Arrays.asList(
 * 		            new FormHttpMessageConverter(),
 * 		            new OAuth2AccessTokenResponseHttpMessageConverter()));
 *
 *          restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
 *
 *          上面这是默认实现 ...
 *          Spring MVC FormHttpMessageConverter  必须被使用,在发送 OAuth 2.0 Access Token Request时 ..
 *          OAuth2AccessTokenResponseHttpMessageConverter 是一个 HttpMessageConverter (用于转换OAuth 2.0 Access Token Response) ..
 *          你能够提供 OAuth2AccessTokenResponseHttpMessageConverter.setAccessTokenResponseConverter() 设置一个自定义的转换器 Converter<Map<String, Object>, OAuth2AccessTokenResponse>
 *              将OAuth 2.0 Access Token Response parameters 响应转换为 OAuth2AccessTokenResponse ..
 *          OAuth2ErrorResponseErrorHandler 是一个ResponseErrorHandler 能够处理OAuth2.0 错误,例如 400错误请求,也可以使用OAuth2ErrorHttpMessageConverter  转换 OAuth2.0 错误参数到OAuth2Error .
 *
 *          无论你是定制DefaultRefreshTokenTokenResponseClient 还是提供子自己的OAuth2AccessTokenResponseClient,你都需要配置到dsl 语法的oauth2client中 ...
 *              // Customize
 *          OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient = ...
 *
 *          OAuth2AuthorizedClientProvider authorizedClientProvider =
 * 		        OAuth2AuthorizedClientProviderBuilder.builder()
 * 				    .authorizationCode()
 * 				    .refreshToken(configurer -> configurer.accessTokenResponseClient(refreshTokenTokenResponseClient))
 * 				    .build();
 *
 *          ...
 *
 *          authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
 *          正对我们的主题,刷新Token  ..
 *          OAuth2AuthorizedClientProviderBuilder.builder().refreshToken() 可以配置一个 RefreshTokenOAuth2AuthorizedClientProvider,
 *          它是一个实现了刷新Token 授予的 OAuth2AuthorizedClientProvider  实现 ..
 *          对于authorization_code / password grant type -> OAuth2RefreshToken  能够可选的从 Access Token Response  中返回 ..
 *          如果OAuth2AuthorizedClient.getRefreshToken() 存在并且 OAuth2AuthorizedClient.getAccessToken() 过期,那么它将自动的通过 RefreshTokenOAuth2AuthorizedClientProvider 刷新 ..
 *          (还记得RefreshTokenOAuth2AuthorizedClientProvider Provider能够干嘛，构造请求)
 *
 *   3. Client Credentials
 *          Please refer to the OAuth 2.0 Authorization Framework for further details on the Client Credentials grant.
 *          1. 请求一个访问TOKEN
 *              Please refer to the Access Token Request/Response protocol flow for the Client Credentials grant.
 *              对于 Client Credentials grant 的OAuth2AccessTokenResponseClient 的默认实现是DefaultClientCredentialsTokenResponseClient,
 *              它使用RestOperations(当从授权服务器Token 端点请求访问Token时) ..
 *              DefaultClientCredentialsTokenResponseClient  是非常灵活的(能够定制 Token 请求的预处理 / Token 响应的后置处理) ...
 *          2. 定制访问Token 请求 ..
 *              ... DefaultClientCredentialsTokenResponseClient.setRequestEntityConverter() 使用 Converter<OAuth2ClientCredentialsGrantRequest, RequestEntity<?>>
 *                  OAuth2ClientCredentialsGrantRequestEntityConverter 默认构建 a RequestEntity representation of a standard OAuth 2.0 Access Token Request.
 *                  仅仅修改请求参数:
 *                      OAuth2ClientCredentialsGrantRequestEntityConverter.setParametersConverter() with
 *                      a custom Converter<OAuth2ClientCredentialsGrantRequest, MultiValueMap<String, String>> to completely override the parameters sent with the request.
 *                      This is often simpler than constructing a RequestEntity directly.
 *                  对于增加额外的请求参数:
 *                      OAuth2ClientCredentialsGrantRequestEntityConverter.addParametersConverter()  使用 Converter<OAuth2ClientCredentialsGrantRequest, MultiValueMap<String, String>> which constructs an aggregate Converter
 *         3. 定制访问Token 响应
 *               DefaultClientCredentialsTokenResponseClient.setRestOperations() ... 设置自定义RestOperations ..
 *               RestTemplate restTemplate = new RestTemplate(Arrays.asList(
 * 		            new FormHttpMessageConverter(),
 * 		            new OAuth2AccessTokenResponseHttpMessageConverter()));
 *
 *              restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
 *              Spring MVC FormHttpMessageConverter is required as it’s used when sending the OAuth 2.0 Access Token Request.
 *
 *             由于授权类型不同,最终同上面的几种授权类型一样,通过Provider 进行组合实现自己的 OAuth2AuthorizedClientProvider ..
 *             // Customize
 *              OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient = ...
 *
 *              OAuth2AuthorizedClientProvider authorizedClientProvider =
 * 		            OAuth2AuthorizedClientProviderBuilder.builder()
 * 				        .clientCredentials(configurer -> configurer.accessTokenResponseClient(clientCredentialsTokenResponseClient))
 * 				        .build();
 *
 *                      ...
 *
 *                  authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
 *
 *             OAuth2AuthorizedClientProviderBuilder.builder().clientCredentials() configures a ClientCredentialsOAuth2AuthorizedClientProvider, which is an implementation of an OAuth2AuthorizedClientProvider for the Client Credentials grant.
 *
 *          4. 使用访问Token
 *              跟其他的方式差不多,不再赘述 ...
 *              详情: https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorization-grants.html#_using_the_access_token
 *
 *
 *    4. Resource Owner Password Credentials
 *          Please refer to the OAuth 2.0 Authorization Framework for further details on the Resource Owner Password Credentials grant. https://tools.ietf.org/html/rfc6749#section-1.3.3
 *          1. Requesting an Access Token
 *              Please refer to the Access Token Request/Response protocol flow for the Resource Owner Password Credentials grant. https://tools.ietf.org/html/rfc6749#section-4.3.2
 *              对于 Resource Owner Credentials grant的OAuth2AccessTokenResponseClient 默认实现 是DefaultPasswordTokenResponseClient,
 *              它使用 RestOperations  请求授权服务器Token 端的访问Token ...
 *              定制非常的灵活 ... Token 请求的预处理 / Token 响应的后置处理 ...
 *          2. Customizing the Access Token Request
 *               DefaultPasswordTokenResponseClient.setRequestEntityConverter()  Converter<OAuth2PasswordGrantRequest, RequestEntity<?>>
 *                   OAuth2PasswordGrantRequestEntityConverter  默认实现 直接构建 standard OAuth 2.0 Access Token Request.
 *                   自定义转换器能够扩展Token 请求  并增加自定义参数 ...
 *               OAuth2PasswordGrantRequestEntityConverter.setParametersConverter() Converter<OAuth2PasswordGrantRequest, MultiValueMap<String, String>> 完全覆盖请求参数
 *               OAuth2PasswordGrantRequestEntityConverter.addParametersConverter()  Converter<OAuth2PasswordGrantRequest, MultiValueMap<String, String>> 增加额外的参数(它将组合成一个聚合Converter) ..
 *          3. Customizing the Access Token Response
 *              DefaultPasswordTokenResponseClient.setRestOperations() 设置 RestOperations 即可
 *              Spring MVC FormHttpMessageConverter is required as it’s used when sending the OAuth 2.0 Access Token Request.
 *
 *          最终不管是定制还是自定义:
 *              对于password-credentials grant type,
 *              // Customize
 *              OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordTokenResponseClient = ...
 *
 *                  OAuth2AuthorizedClientProvider authorizedClientProvider =
 * 		                OAuth2AuthorizedClientProviderBuilder.builder()
 * 				        .password(configurer -> configurer.accessTokenResponseClient(passwordTokenResponseClient))
 * 				        .refreshToken()
 * 				        .build();
 *
 *                  ...
 *
 *                  authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
 *
 *                   OAuth2AuthorizedClientProviderBuilder.builder().password() configures a PasswordOAuth2AuthorizedClientProvider,
 *                   which is an implementation of an OAuth2AuthorizedClientProvider for the Resource Owner Password Credentials grant.
 *
 *    5. JWT Bearer
 *      Please refer to JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants for further details on the JWT Bearer grant.
 *      1. 请求一个访问Token
 *          Please refer to the Access Token Request/Response protocol flow for the JWT Bearer grant. https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
 *           JWT Bearer grant的 OAuth2AccessTokenResponseClient  的默认实现是 DefaultJwtBearerTokenResponseClient,它使用 RestOperations (从授权服务器 Token 端点请求访问token)
 *           DefaultJwtBearerTokenResponseClient 十分灵活,你能够定制预处理Token 请求或者Token响应的后置处理 ...
 *      2. Customizing the Access Token Request
 *           DefaultJwtBearerTokenResponseClient.setRequestEntityConverter() 使用  Converter<JwtBearerGrantRequest, RequestEntity<?>>j
 *           默认实现 JwtBearerGrantRequestEntityConverter 直接构建  RequestEntity representation of a OAuth 2.0 Access Token Request.
 *           定制Converter,能够扩展Token 请求和自定义参数 ...
 *         JwtBearerGrantRequestEntityConverter.setParametersConverter() 自定义覆盖请求参数 ..
 *         或者 JwtBearerGrantRequestEntityConverter.addParametersConverter()  增加额外得请求参数(本质上是聚合为一个Converter)
 *      3. Customizing the Access Token Response
 *          DefaultJwtBearerTokenResponseClient.setRestOperations() 即可 ..
 *              // Customize
 *          OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> jwtBearerTokenResponseClient = ...
 *
 *          JwtBearerOAuth2AuthorizedClientProvider jwtBearerAuthorizedClientProvider = new JwtBearerOAuth2AuthorizedClientProvider();
 *          jwtBearerAuthorizedClientProvider.setAccessTokenResponseClient(jwtBearerTokenResponseClient);
 *
 *          OAuth2AuthorizedClientProvider authorizedClientProvider =
 * 		            OAuth2AuthorizedClientProviderBuilder.builder()
 * 				    .provider(jwtBearerAuthorizedClientProvider)
 * 				    .build();
 *
 *          ...
 *
 *          authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
 *      4. Using the Access Token
 *           jwt bearer 属于扩展grant type : urn:ietf:params:oauth:grant-type:jwt-bearer
 *           https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorization-grants.html#_using_the_access_token_3
 *
 *           JwtBearerOAuth2AuthorizedClientProvider resolves the Jwt assertion via OAuth2AuthorizationContext.getPrincipal().getPrincipal() by default,
 *           所以如果我们是JWT Bearer.... 可以直接使用  JwtAuthenticationToken  然后通过参数解析器进行解析 ..
 *           对于不同来源JWT token 断言 ,我们可以提供断言器 JwtBearerOAuth2AuthorizedClientProvider.setJwtAssertionResolver() -> Function<OAuth2AuthorizationContext, Jwt>
 */
public class OAuthGrantAutoConfiguration {


    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(
                                        authorizationRequestResolver(this.clientRegistrationRepository)
                                )
                        )
                );
        return http.build();
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(
                authorizationRequestCustomizer());

        return  authorizationRequestResolver;
    }

    /**
     * 虽然可以定制,如果 对于特定的provider 总是一种行为,那么我们可以直接追加到 authorization-uri上 ...
     * 例如prompt总是 consent ...
     * spring:
     *   security:
     *     oauth2:
     *       client:
     *         provider:
     *           okta:
     *             authorization-uri: https://dev-1234.oktapreview.com/oauth2/v1/authorize?prompt=consent
     * @return
     */
    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {



        return customizer -> customizer
                // 直接修改 请求URI ..
//                .authorizationRequestUri();
                .additionalParameters(params -> params.put("prompt", "consent"));

//        return customizer -> customizer
//                .authorizationRequestUri(uriBuilder -> uriBuilder
//                        .queryParam("prompt", "consent").build());
    }
}
