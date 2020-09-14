package com.oauth.config;

import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Component;

//需要配置一个security，不然会报错
//User must be authenticated with Spring Security before authorization can be completed.

@Component
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//暂时什么都没写

}