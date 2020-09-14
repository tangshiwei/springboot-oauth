package com.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * OAuth 授权服务器配置
 */

//OAuth2定义了4种模式:
//        授权码模式（authorization code）
//        简化模式（implicit）
//        密码模式（resource owner password credentials）
//        客户端模式（client credentials）(主要用于api认证，跟用户无关)

@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    //accessToken 过期
    private int accessTokenValiditySecond = 60 * 60 * 2; //2小时
    private int refreshTokenValiditySecond = 60 * 60 * 24 * 7; // 7 天

    //添加商户信息
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.inMemory().withClient("yyy_client").secret(passwordEncoder().encode("yyy_secret"))

                //=============== 1.密码模式 ===============//
                //请求url: http://localhost:8080/oauth/token?grant_type=password&username=user_1&password=123456&client_id=yyy_client&client_secret=yyy_secret&scope=all

                //设置权限类型,用密码，客户端,刷新的token  权限为所有人
                .authorizedGrantTypes("password","refresh_token").scopes("all")


                //=============== 2.客户端模式 client_credentials ===============//
                //请求url:http://localhost:8080/oauth/token?grant_type=client_credentials&client_id=yyy_client&client_secret=yyy_secret

                //客户端模式不需要账号密码
                .authorizedGrantTypes("client_credentials","refresh_token").scopes("all")


                //=============== 3.授权模式：首先获取code,然后获取TOKEN ================//
                // 第一步：http://localhost:8080/oauth/authorize?response_type=code&client_id=yyy_client&redirect_uri=http://www.baidu.com
                // 访问对应路径将参数传递过去
                // response_type=code  写死的
                // client_id=yyy_client 这是后端config定义好的
                // redirect_uri=http://www.baidu.com 这是重新返回的uri 访问后会携带一个code
                //第二步：http://localhost:8080/oauth/token?grant_type=authorization_code&code=&client_id=yyy_client&client_secret=yyy_secret&&redirect_uri=http://www.baidu.com
                //注意：访问后会携带一个code只能使用一次。
                //可以看到即便code不一致但是token是一致的

                .authorizedGrantTypes("authorization_code", "refresh_token").scopes("all")


                //============================================//
                .accessTokenValiditySeconds(accessTokenValiditySecond)
                .refreshTokenValiditySeconds(refreshTokenValiditySecond);


    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

        //允许表单认证
        security.allowFormAuthenticationForClients();

        //允许 check_token 访问
        security.checkTokenAccess("permitAll()");

    }

    //定义授权和令牌端点和令牌服务
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //刷新令牌时需要的认证管理和用户信息来源
        endpoints.authenticationManager(authenticationManager()).allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
        endpoints.authenticationManager(authenticationManager());
        endpoints.userDetailsService(userDetailsService());
    }

    @Bean
    AuthenticationManager authenticationManager() {
        AuthenticationManager authenticationManager = new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                return daoAuhthenticationProvider().authenticate(authentication);
            }
        };
        return authenticationManager;
    }

    @Bean
    public AuthenticationProvider daoAuhthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        daoAuthenticationProvider.setHideUserNotFoundExceptions(false);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    // 设置添加用户信息,正常应该从数据库中读取
    @Bean
    UserDetailsService userDetailsService() {
        String pass = passwordEncoder().encode("123456");
        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
        userDetailsService.createUser(User.withUsername("user_1").password(pass)
                .authorities("ROLE_USER").build());
        userDetailsService.createUser(User.withUsername("user_2").password(pass)
                .authorities("ROLE_USER").build());
        return userDetailsService;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        // 加密方式
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder;
    }


}
