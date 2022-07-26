package club.smileboy.app.oauth.config;
/**
 * @author FLJ
 * @date 2022/7/26
 * @time 17:08
 * @Description OAuth 2.0 Resource Server
 *
 * Spring security 支持两种形式的OAuth 2.0 Bearer Token(https://tools.ietf.org/html/rfc6750.html) 保护端点
 * 1. JWT https://tools.ietf.org/html/rfc7519
 * 2. Opaque Tokens
 *
 * 仅当一个应用的授权管理交给了授权服务器之后,才应该使用(例如 Okta或者Ping Identity)
 * 授权服务器能够 被资源服务器咨询去授权请求
 *
 *
 */
public class OAuthResourceServerAutoConfiguration {
}
