package tacos.security;

import org.springframework.security.crypto.password.PasswordEncoder;

public class NoEncodingPasswordEncoder implements PasswordEncoder{

	//로그인시 입력한 비밀번호를 암호화하지않고 String으로 반환한다.
	@Override
	public String encode(CharSequence rawPassword) {
		// TODO Auto-generated method stub
		return rawPassword.toString();
	}

	//encode()에서 반환된 비밀번호를 데이터베이스에서 가저온 비밀번호와 비교한다.
	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		// TODO Auto-generated method stub
		return rawPassword.toString().equals(encodedPassword);
	}
	
}
