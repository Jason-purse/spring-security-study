package club.smileboy.app.oauth.config;
/**
 * @author FLJ
 * @date 2022/7/26
 * @time 16:47
 * @Description 授权客户端的特性
 *
 * 1. 解析一个授权的客户端
 *      @RegisteredOAuth2AuthorizedClient 提供了一种解析方法参数到 OAuth2AuthorizedClient的能力, 这是一种方便的方式去访问 OAuth2AuthorizedClient
 *      (避免了通过 OAuth2AuthorizedClientManager  / OAuth2AuthorizedClientService 访问的繁琐代码) .
 *
 *          @GetMapping("/")
 *        public String index(@RegisteredOAuth2AuthorizedClient("okta") OAuth2AuthorizedClient authorizedClient) {
 * 		        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
 *
 * 		        ...
 *
 * 		        return "index";
 *          }
 *       这个注解 通过 OAuth2AuthorizedClientArgumentResolver 处理,  它直接使用 OAuth2AuthorizedClientManager  因此继承了它的一些能力 ..
 *
 *  2. WebClient integration for Servlet Environments
 *          OAuth2.0 client 支持使用ExchangeFilterFunction 与 WebClient集成 ..
 *          ServletOAuth2AuthorizedClientExchangeFilterFunction  提供了一个简单的机制 去请求保护资源 (通过使用一个 OAuth2AuthorizedClient 并包含关联的
 *          OAuth2AccessToken  作为一个Bearer Token), 它直接使用了  OAuth2AuthorizedClientManager,因此继承了以下的能力 ..
 *          1. 一个OAuth2AccessToken 将会被请求,如果客户端没有被授权:
 *              1.1 authorization_code  触发授权请求重定向并初始化流
 *              1.2 client_credentials  直接从Token Endpoint中获取访问Token ..
 *              1.3 password 直接从Token Endpoint中获取访问Token ...
 *          2. 如果OAuth2AccessToken  过期了,他将会刷新(或者重新授权) - 如果 OAuth2AuthorizedClientProvider  具有这样的能力时 ..
 *   以下的代码展示了如何配置一个WebClient具有OAuth 2.0 客户端支持
 *      @Bean
 *      WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
 * 	        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
 * 			    new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
 * 	            return WebClient.builder()
 * 			    .apply(oauth2Client.oauth2Configuration())
 * 			    .build();
 *      }
 * 3. Providing the Authorized Client
 *  ServletOAuth2AuthorizedClientExchangeFilterFunction  决定客户端(对于一个请求)使用 - 通过解析来自ClientRequest.attributes()(请求属性) 中的OAuth2AuthorizedClient
 *  对应上面的WebClient 和 ServletOAuth2AuthorizedClientExchangeFilterFunction的集成,这个函数通过ClientRequest.attributes()解析需要使用的客户端 ...
 *
 *      以下代码展示了如何将一个客户端作为属性:
 *          @GetMapping("/")
 *              public String index(@RegisteredOAuth2AuthorizedClient("okta") OAuth2AuthorizedClient authorizedClient) {
 * 	            String resourceUri = ...
 *
 * 	                String body = webClient
 * 			            .get()
 * 			            .uri(resourceUri)
 * 			            .attributes(oauth2AuthorizedClient(authorizedClient))
 * 			            .retrieve()
 * 			            .bodyToMono(String.class)
 * 			            .block();
 *
 * 	                      ...
 *
 *                  	return "index";
 *                  }
 *                  oauth2AuthorizedClient() is a static method in ServletOAuth2AuthorizedClientExchangeFilterFunction.
 *                  ClientRegistration.getRegistrationId() as a request attribute:
 *                  同上webClient. xxx....attributes(clientRegistrationId("okta"))
 *                  clientRegistrationId() is a static method in ServletOAuth2AuthorizedClientExchangeFilterFunction.
 *
 * 4. 默认的授权客户端
 *  如果没有提供授权过的Client,(例如没有提供 OAuth2AuthorizedClient  或者 ClientRegistration.getRegistrationId())作为请求属性,
 *  ServletOAuth2AuthorizedClientExchangeFilterFunction  决定一个默认的客户端去使用(取决于配置)
 *  setDefaultOAuth2AuthorizedClient(true) 配置,并且用户通过 HttpSecurity.oauth2Login()认证,那么 OAuth2AuthenticationToken 关联的OAuth2AccessToken 将被使用 ...
 *  @Bean
 *  WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
 * 	ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
 * 			new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
 * 	oauth2Client.setDefaultOAuth2AuthorizedClient(true);
 * 	return WebClient.builder()
 * 			.apply(oauth2Client.oauth2Configuration())
 * 			.build();
 * }
 *
 * 建议谨慎使用此功能，因为所有 HTTP 请求都会收到访问令牌。(按道理来说,这也是不和规矩的)
 * 除此之外,如果 一个有效的 ClientRegistration 设置了 setDefaultClientRegistrationId("okta"),那么 当前  OAuth2AuthorizedClient关联的 OAuth2AccessToken  将被使用 ...
 * @Bean
 * WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
 * 	ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
 * 			new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
 * 	oauth2Client.setDefaultClientRegistrationId("okta");
 * 	return WebClient.builder()
 * 			.apply(oauth2Client.oauth2Configuration())
 * 			.build();
 * }
 * 同样谨慎使用这个特性, 所有的http请求都会收到令牌 ..
 */
public class OAuthorizedClientAutoConfiguration {
}
