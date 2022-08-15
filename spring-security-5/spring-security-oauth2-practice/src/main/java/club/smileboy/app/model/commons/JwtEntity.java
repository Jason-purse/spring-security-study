package club.smileboy.app.model.commons;

import club.smileboy.app.authentication.UserInfo;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.BeanUtils;

/**
 * @author JASONJ
 * @date 2022/8/14
 * @time 11:30
 * @description 一个未加密的JwtEntity 实体
 **/
public interface JwtEntity {

    /**
     * 加密算法类型
     * @return 加密算法文本标识
     */
    String encryptAlgorithmType();

    /**
     * 令牌类型
     * @return 令牌类型(jwt / jws)
     */
    String tokenType();

    /**
     * 通过给定的jwt Util 创建 jwt Token
     * @param builder JWTCreateor.builder
     * @return jwt token
     */
    String generateJwtToken(JWTCreator.Builder builder);

    /**
     * 配置一个Jwt Entity
     * @param decodeInfo 解析出来信息
     */
    void config(DecodedJWT decodeInfo);

    /**
     * 是否过期
     */
    Boolean isExpired();

    /**
     * 创建一个默认的 JwtEntity
     */
    static JwtEntity ofDefault() {
        return UserInfo.ofDefault();
    }

    static JwtEntity ofDefault(Class<JwtEntity> entityClass) {
        return  BeanUtils.instantiateClass(entityClass);
    }
}
