package club.smileboy.app.util;

import java.time.Instant;

public class DateUtil extends UtilBaseClass{

    public static Long nowEpochMillis() {
        return Instant.now().toEpochMilli();
    }

    public static Long toEpochMillis(long millis) {
        return Instant.now().plusMillis(millis).toEpochMilli();
    }
}
