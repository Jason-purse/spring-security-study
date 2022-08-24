package club.smileboy.app;

import org.junit.jupiter.api.Test;

public class CharacterTests {
    @Test
    public void test() {

        // 如果在给定 进制下,无法给出,则 -1 ..
        //由于A B C D E F 在 16进制下  ch = 16 - 10 + A;
        // 所以, 其他进制下, ch = rax - 10 + A; (但是 这是所能表示的最大数值)... 所以 ch 必须小于这个值 ... (radix - 10 + 'A') ...
        // 所以 值等于 radix =  ch - 'A' + 10 ....
        System.out.println(Character.digit('A', 10));
        System.out.println(Character.digit('A',16));

        System.out.println(Character.digit('0',10));
        System.out.println(Character.digit('1',10));

        // 所以Character.digit 是将字符转为有意义的数值 ...
        System.out.println((int)'9');
    }


    // 移位
    @Test
    public void test1() {

        System.out.println( 1 << 4);

    }
}
