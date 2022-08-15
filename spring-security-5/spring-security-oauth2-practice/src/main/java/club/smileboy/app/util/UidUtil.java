package club.smileboy.app.util;

import org.springframework.util.AlternativeJdkIdGenerator;

/**
 * @author JASONJ
 * @date 2022/8/14
 * @time 12:13
 * @description Uid
 **/
public class UidUtil extends UtilBaseClass {

    private static final AlternativeJdkIdGenerator generator = new AlternativeJdkIdGenerator();

    public static String generateUUid() {
        // 397546ff-c551-8974-1126-0788049990ce
        return generator.generateId().toString();
    }
}
