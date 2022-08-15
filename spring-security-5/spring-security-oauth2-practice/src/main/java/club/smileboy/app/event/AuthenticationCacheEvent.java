package club.smileboy.app.event;

import club.smileboy.app.authentication.UserInfo;
import org.springframework.context.ApplicationEvent;

import java.time.Clock;

public class AuthenticationCacheEvent extends ApplicationEvent {
    public AuthenticationCacheEvent(Object source) {
        super(source);
    }

    public AuthenticationCacheEvent(Object source, Clock clock) {
        super(source, clock);
    }

    public UserInfo getUserInfo() {
        return ((UserInfo) this.getSource());
    }
}
