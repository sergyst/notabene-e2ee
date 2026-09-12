package id.notabene.e2ee;

import id.notabene.e2ee.config.NotabeneProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(NotabeneProperties.class)
public class NotabeneE2eeApplication {

    public static void main(String[] args) {
        SpringApplication.run(NotabeneE2eeApplication.class, args);
    }
}
