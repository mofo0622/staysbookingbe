package com.laioffer.staybooking.config;


import com.laioffer.staybooking.filter.JwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

// for config only, no logic operation yet (logic is realized by framework)

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired // 自动创建
    private DataSource dataSource;

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override //authorize 判断权限 是否能访问url（是否会员）
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/register/*").permitAll()
                .antMatchers(HttpMethod.POST, "/authenticate/*").permitAll()
                .antMatchers("/stays").hasAuthority("ROLE_HOST")
                .antMatchers("/stays/*").hasAuthority("ROLE_HOST")
                .antMatchers("/search").hasAuthority("ROLE_GUEST")
                .antMatchers("/reservations").hasAuthority("ROLE_GUEST")
                .antMatchers("/reservations/*").hasAuthority("ROLE_GUEST")// only guest can search
                .anyRequest().authenticated()
                .and()
                .csrf()
                .disable();
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override //authenticate 验证 http request 能否能够登陆
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .jdbcAuthentication()
                .dataSource(dataSource)
                .passwordEncoder(passwordEncoder())
                .usersByUsernameQuery("SELECT username, password, enabled FROM user WHERE username = ?") // get info from DB
                .authoritiesByUsernameQuery("SELECT username, authority FROM authority WHERE username = ?");
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception{ //manager 相当于build了一个
        return super.authenticationManagerBean();
    }

}


