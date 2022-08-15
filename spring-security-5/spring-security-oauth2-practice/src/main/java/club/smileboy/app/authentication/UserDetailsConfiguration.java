package club.smileboy.app.authentication;

import club.smileboy.app.model.dto.UserDetailDto;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * 用户详情配置
 */
@ConfigurationProperties(prefix = "user")
public class UserDetailsConfiguration {

    private List<UserDetailDto> details;

    public void setDetails(List<UserDetailDto> details) {
        this.details = details;
    }

    public List<UserDetailDto> getUserDetailDtos() {
        return details;
    }
}
