package com.zeekad.dashboard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ZeekAdDashboardApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZeekAdDashboardApplication.class, args);
    }
}
