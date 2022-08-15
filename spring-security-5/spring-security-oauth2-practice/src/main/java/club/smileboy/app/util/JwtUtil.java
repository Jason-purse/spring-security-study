package club.smileboy.app.util;

import club.smileboy.app.model.commons.JwtEntity;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * @author JASONJ
 * @date 2022/8/14
 * @time 11:23
 * @description JWT 令牌解析 ...
 **/
public class JwtUtil extends UtilBaseClass {

    public static JWTCreator.Builder getJwtBuilder() {
        return JWT.create();
    }

    /**
     * 产生Jwt Token
     * @param jwtEntity 一个可以产生jwt Token的 实体
     */
    public static String generateJwtToken(JwtEntity jwtEntity) {
        return jwtEntity.generateJwtToken(JwtUtil.getJwtBuilder());
    }

    public static JwtEntity parseJwtToken(String jwtToken) {
        DecodedJWT decode = JWT.decode(jwtToken);
        JwtEntity jwtEntity = JwtEntity.ofDefault();
        jwtEntity.config(decode);
        return jwtEntity;
    }

    public static JwtEntity parseJwtToken(String jwtToken,Class<JwtEntity> jwtEntityClass) {
        JwtEntity jwtEntity = JwtEntity.ofDefault(jwtEntityClass);
        jwtEntity.config(JWT.decode(jwtToken));
        return jwtEntity;
    }
}
