package com.github.hellxz.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 授权服务器 入口
 *
 * @author mason
 */
@SpringBootApplication
public class AuthorizationCodeAuthorizationServerApp {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationCodeAuthorizationServerApp.class, args);
    }
}
