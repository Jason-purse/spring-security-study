package club.smileboy.app.oauth.lifeCycle;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.Lifecycle;
import org.springframework.stereotype.Component;

@Component
public class DaemonProcess implements Lifecycle  {
    private volatile boolean running;
    @Override
    public void start() {
        System.out.println("daemon process start");
        this.running = true;
    }

    @Override
    public void stop() {
        System.out.println("daemon process stop");
        this.running = false;
    }

    @Override
    public boolean isRunning() {
        return running;
    }

}
