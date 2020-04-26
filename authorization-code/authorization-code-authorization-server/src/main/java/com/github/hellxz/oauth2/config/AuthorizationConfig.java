package com.github.hellxz.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

//授权服务器配置
@Configuration
@EnableAuthorizationServer //开启认证授权服务中心
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    private static final int ACCESSTOKENVALIDITYSECONDS = 7200; //两个小时
    private static final int REFRESHTOKENVALIDITYSECONDS = 7200;
    @Autowired
    private PasswordEncoder passwordEncoder;


    //配置认证规则，那些需要认证那些不需要
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //允许表单提交，配置资源客户端（第三方应用）的表单提交权限，如果不配置，客户端将无法换取token
        security.allowFormAuthenticationForClients()
                .checkTokenAccess("isAuthenticated()");
    }

    /**
     * 配置appid、appkey、回调地址、token的有效期
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // @formatter: off
        clients.inMemory()
                .withClient("client-a") //客户端唯一标识（client_id）
                    .secret(passwordEncoder.encode("client-a-secret")) //客户端的密码(client_secret)，这里的密码应该是加密后的
                    .authorizedGrantTypes("authorization_code") //授权模式标识
                    .scopes("read_user_info") //作用域，用于限制客户端与用户无法访问没有作用域的资源
                    .resourceIds("resource1") //资源id，可以对应一个资源服务器
                    .redirectUris("http://localhost:9001/callback") //回调地址，如果放开，则取code的时候可以不用传
                    .accessTokenValiditySeconds(ACCESSTOKENVALIDITYSECONDS)
                    .refreshTokenValiditySeconds(REFRESHTOKENVALIDITYSECONDS);
        // @formatter: on
    }


}
