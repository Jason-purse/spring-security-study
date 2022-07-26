package club.smileboy.app.oauth.config;
/**
 * @author FLJ
 * @date 2022/7/26
 * @time 16:26
 * @Description 客户端认证支持 ...
 *  Please refer to JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants for further details on JWT Bearer Client Authentication.
 *
 *  JWT Bearer Client Authentication的默认实现是 NimbusJwtClientAuthenticationParametersConverter, 这是一个转换器 通过增加一个JWS签名的json web token到 client_assertion参数上 定制Token请求 ..
 *
 *  java.security.PrivateKey  / javax.crypto.SecretKey  被用来进行 jws 签名(由 NimbusJwtClientAuthenticationParametersConverter 关联的 com.nimbusds.jose.jwk.JWK 解析器提供)
 *  1. 使用private_key_jwt 认证
 *      首先 private_key_jwt 是一种客户端认证方式
 *
 *      // 我们创建一种jwkResolver ...  产生公私钥 ..
 *      Function<ClientRegistration, JWK> jwkResolver = (clientRegistration) -> {
 * 	        if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
 * 		    // Assuming RSA key type
 * 		    RSAPublicKey publicKey = ...
 * 		    RSAPrivateKey privateKey = ...
 * 		    return new RSAKey.Builder(publicKey)
 * 				.privateKey(privateKey)
 * 				.keyID(UUID.randomUUID().toString())
 * 				.build();
 *          }
 * 	        return null;
 *      };
 *
 *      OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter =
 * 		    new OAuth2AuthorizationCodeGrantRequestEntityConverter();
 * 		    // 也就是它会增加一个参数  client_assertion 对jwt token 进行签名 ...
 *      requestEntityConverter.addParametersConverter(
 * 		    new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));
 *
 *      DefaultAuthorizationCodeTokenResponseClient tokenResponseClient =
 * 		    new DefaultAuthorizationCodeTokenResponseClient();
 *      tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
 *  2. 使用client_secret_jwt 认证
 *        client-authentication-method: client_secret_jwt
 *             authorization-grant-type: client_credentials
 *        使用这种方式认证,需要配置 DefaultClientCredentialsTokenResponseClient
 *          Function<ClientRegistration, JWK> jwkResolver = (clientRegistration) -> {
 * 	        if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
 * 		        SecretKeySpec secretKey = new SecretKeySpec(
 * 				clientRegistration.getClientSecret().getBytes(StandardCharsets.UTF_8),
 * 				"HmacSHA256");
 * 		        return new OctetSequenceKey.Builder(secretKey)
 * 				.keyID(UUID.randomUUID().toString())
 * 				.build();
 *          }
 *          	return null;
 *          };
 *
 *          OAuth2ClientCredentialsGrantRequestEntityConverter requestEntityConverter =
 * 		        new OAuth2ClientCredentialsGrantRequestEntityConverter();
 *          requestEntityConverter.addParametersConverter(
 * 		        new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));
 *
 *          DefaultClientCredentialsTokenResponseClient tokenResponseClient =
 * 		        new DefaultClientCredentialsTokenResponseClient();
 *          tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
 *
 *   3. Customizing the JWT assertion
 *      NimbusJwtClientAuthenticationParametersConverter 产生的JWT 包含 iss,sub,aud,jti,iat,exp claims ..
 *      你可以定制headers / 或者claims - 通过提供 Consumer<NimbusJwtClientAuthenticationParametersConverter.JwtClientAuthenticationContext<T>>
 *          将它设置到 setJwtClientAssertionCustomizer() 即可 ...
 *          例如:
 *              Function<ClientRegistration, JWK> jwkResolver = ...
 *
 *          NimbusJwtClientAuthenticationParametersConverter<OAuth2ClientCredentialsGrantRequest> converter =
 * 		        new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver);
 *              converter.setJwtClientAssertionCustomizer((context) -> {
 * 	                context.getHeaders().header("custom-header", "header-value");
 * 	                context.getClaims().claim("custom-claim", "claim-value");
 *              });
 */
public class OAuthClientAuthenticationAutoConfiguration {
}
