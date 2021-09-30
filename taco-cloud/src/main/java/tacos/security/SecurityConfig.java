package tacos.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private UserDetailsService userDetailsService;
	/* DataSource dataSource; */
	
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	// /design과 /orders의 요청은 ROLE_USER 권한을 갖는 사용자에게만 허용된다.
	// 이외의 모든 요청은 모든 사용자에게 허용된다.
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.authorizeRequests()
		.antMatchers("/design", "/orders").access("hasRole('USER_ROLE')")
		.antMatchers("/", "/**").access("permitAll")
			.and()
				.formLogin()
					.loginPage("/login")
					//.defaultSuccessUrl("/design")  	// 로그인 성공 후 이동페이지 지정
		.and()
			.logout()
				.logoutSuccessUrl("/") 		//로그아웃 성공 후 이동
		.and()
			.csrf()
		;
	}
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		/*
		 * auth.inMemoryAuthentication() .withUser("user1") .password("{noop}password1")
		 * .authorities("ROLE_USER") .and() .withUser("user2")
		 * .password("{nooppassword2}") .authorities("ROLE_USER");
		 */
		/*
		 * auth.jdbcAuthentication() .dataSource(dataSource)
		 * .usersByUsernameQuery("select username, password, enabled from users " +
		 * "where username=?")
		 * .authoritiesByUsernameQuery("select username, authority from authorities " +
		 * "where username=?") .passwordEncoder(new NoEncodingPasswordEncoder());
		 */
		
		auth.userDetailsService(userDetailsService)
		.passwordEncoder(encoder());
		
	}
	
}
