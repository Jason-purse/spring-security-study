package club.smileboy.app.authentication;

import club.smileboy.app.model.dto.UserDetailDto;

import java.util.List;

/**
 * @author FLJ
 * @date 2022/8/12
 * @time 17:15
 * @Description 用户详情仓库
 */
public interface UserDetailsRepository {

    UserDetailDto loadUserDetailByUserName(String userName);

    void setUserInfos(List<UserDetailDto> userInfos);
}
