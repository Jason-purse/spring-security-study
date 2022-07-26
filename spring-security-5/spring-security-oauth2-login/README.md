# OAuth2
## OAuth2 Resource Server
### JWT
#### OAuth 2.0 Resource Server JWT
## JWT的最小依赖
    大多数资源服务器支持收集到了spring-security-oauth2-resource-server. 然而对于JWT 的解码和校验的支持是在spring-security-oauth2-jose中,
    意味着两者都是必要的(为了拥有一个支持JWT 编码 Bearer Token的资源服务器工作)

## JWT的最小配置
    当使用Spring Boot,配置一个应用作为资源服务器只需要两步,第一步包括前面所说的依赖,第二步指明授权服务器的位置 ..
### 指明Authorization 服务器的位置
```yml
    spring:
    security:
      oauth2:
        resourceserver:
          jwt:
            issuer-uri: https://idp.example.com/issuer
```
这里的https://idp.example.com/issuer 是包含在JWT token的iss声明中的值(表示授权服务器颁发的),资源服务器使用这个属性
去进一步的自我配置,发现授权服务器的公钥,以及后续校验进入的JWT ..
为了使用issuer-uri 属性,以下其中一个地址必须有一个能够支持访问且返回正确的元数据 ..
类似:
https://idp.example.com/issuer/.well-known/openid-configuration,
https://idp.example.com/.well-known/openid-configuration/issuer, 
or https://idp.example.com/.well-known/oauth-authorization-server/issuer
表示授权服务器支持的端点,这个端点指的是 [Provider Configuration endpoint](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) or a [Authorization Server Metadata endpoint](https://tools.ietf.org/html/rfc8414#section-3).

### 开始期望
当这个属性以及这些依赖被使用,资源服务器将自动的配置它自己去校验JWT编码的Bearer Token ..
它通过确定性启动过程来实现这一点：
    1. 它根据jwks_url属性来查询Provider 配置或者授权服务器元数据端点
    2. 根据支持的算法查询jwks_url端点
    3. 针对发现的有效的公钥算法 配置验证策略去查询jwks_url
    4. 针对iss值 配置校验策略去验证每一个JWT iss 声明
这个过程的结果是授权服务器必须启动且接收这些请求为了资源服务器成功的启动 ..
如果授权服务器死亡(当资源服务器查询它的时候(会有合理的超时),启动将会失败)

### 运行期望
一旦应用启动,资源服务器将尝试处理包含了Authorization: Bearer请求头的任何请求 ...
因此只要这个schema(方案) 被指定,资源服务器将会尝试根据Bearer Token 规范处理请求 ..