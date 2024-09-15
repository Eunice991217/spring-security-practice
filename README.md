# spring-security-practice

## 스프링 시큐리티

[스프링 시큐리티 1 : 실습 목표 및 간단한 동작 원리](https://www.youtube.com/watch?v=y0PXQgrkb90&list=PLJkjrxxiBSFCKD9TRKDYn7IE96K2u3C3U)

> 시큐리티 동작 원리
> 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/a0ff2a03-773c-4953-af24-b9d7906c8e17/9a888c3d-f151-4aa8-af74-ae9459a911af/image.png)

스프링은 서블릿 컨테이너 위에 존재하고 있음 → 클라이언트 요청하면 서블릿 컨테이너가 요청 받아서 여기 안에 존재하는 필터들 거친 후에, 스프링 부트에 요청이 도달하게 되는데 → 스프링 시큐리티 config 파일을 등록해두면, config 파일이 필터에 특정한 필터를 만들어서 클라이언트 요청을 가로챔 → 클라이언트가 가고싶은 목적지 이전에 해당 클라이언트가 권한이 있는지 분석함 → 만약에 admin controller 가고싶은데, admin 권한이없으면 필터에서 권한을 막게 됨 → 로그인 진행해야 할 경우 필터에서 모든 유저에 대한 접근 허용해서 로그인 컨트롤러가서 로그인 진행하고 → 세션에 로그인 정보가 등록됨. → 이후 다른 페이지 갈때는 세션에 유저가 등록되어있어서 필터에서 통과를 허용시켜서 마이페이지 컨트롤러에 접근할 수 있음

[Spring Security란? 사용하는 이유부터 설정 방법까지 알려드립니다! I 이랜서 블로그](https://www.elancer.co.kr/blog/view?seq=235)

> 프로젝트 생성
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668bd5de16014d6810ed85f3)

cf. **머스테치(Mustache)** 는 JSP와 같이 HTML을 만들어 주는 템플릿 엔진

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/a0ff2a03-773c-4953-af24-b9d7906c8e17/e707e2e4-6eb7-48c4-b424-e025bbe54a3d/image.png)

[[Spring Boot] Chap 4.Mustache로 화면 구성하기](https://doorisopen.github.io/spring/2020/03/03/spring-freelec-springboot-chap4.html)

> 인가
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668bd6bf16014d6810ed85f5)

<aside>
💡 특정한 경로에 요청이 들어오면 Controller 클래스에 도달하기 전 필터에서 스프링 시큐리티가 미리 검증을 하는 작업

</aside>

: 특정한 경로는 모두에게 오픈 시키고, 다른 특정한 경로는 인가된 사용자에게만 오픈 시키도록 실습

⇒ 이런 작업을 하려면 Security Configuration (인가 설정을 진행하는 클래스) 

cf. 기본적인 인가 작업은 모든 경로에 대해서 로그인하도록 지정되어 있음 

- 따로 커스텀 하려면 config 클래스를 등록해둬야 함

[스프링 시큐리티에서 @EnableWebSecurity 어노테이션의 활용 방법과 기능](https://jjangadadcodingdiary.tistory.com/entry/스프링-시큐리티에서-EnableWebSecurity-어노테이션의-활용-방법과-기능)

[SpringSecurity - antMatchers()와 requestMatchers() 차이](https://velog.io/@jeongm/SpringSecurity-antMatchers와-requestMatchers-차이)

- **`permitAll`** : 로그인 하지 않아도 모든 사용자가 접근할 수 있도록 설정
- **`hasRole`** : 특정한 로그인 같은 규칙이 있어야 이 경로에 접근할 수 있도록 설정
- **`authenticated`** : 로그인만 진행하면 모두 접근 가능하도록 설정
- **`denyAll`** : 로그인해도 모든 사용자 접근하지 못하도록 설정

⇒ 동작되는 순서가 상단부터 진행되서 순서 중요함 

: 처음에 anyRequest 하면 안됨. 

가장 아래에서 모든 경로에 대한 세팅을 진행해줘야 함 

```java
package com.example.securityprac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // spring security 활성화 (웹 보안 활성화)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated());
                // requestMatchers : 특정한 url 에 대해 경로 설정
                // + 보안 설정
                // anyRequest : 위에서 처리 하지 못한 나머지 경로 처리

        return http.build();
    }

}

```

cf. 시큐리티 버전별 구현 방법

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668bd7fe16014d6810ed85f7)

⇒ 릴리즈 노트 확인하기

https://github.com/spring-projects/spring-security/releases

: 스프링 부트 3 버전으로 

> 커스텀 로그인
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668bd94716014d6810ed85f9)

→ 로그인 하지 않은 상태로 특정한 admin 경로에 접근하게 되면, 페이지 엑세스 자체가 거부됨 (리다이렉팅 작업이 필요) 

: 특정 경로에 대한 접근 권한이 없는 경우 자동으로 로그인 페이지로 리다이렉팅 되지 않고 오류 페이지가 발생

- csrf : 스프링 위변조 방지 설정
    
    csrf 토큰 - 서버에 들어온 요청이 실제 서버에서 허용한 요청이 맞는지 확인하기 위한 토큰 
    
    [CSRF토큰이란?](https://velog.io/@jupiter-j/CSRF토큰이란)
    
    ⇒ 스프링 시큐리티에는 csrf가 자동으로 설정되어 있음. 근데, 이 설정이 동작되면 post 요청을 보낼 때 csrf 토큰도 보내주어야 동작이 됨. (개발 환경에서는 꺼둬야 로그인 진행됨) 
    

```java
package com.example.securityprac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // spring security 활성화 (웹 보안 활성화)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated());
                // requestMatchers : 특정한 url 에 대해 경로 설정
                // + 보안 설정
                // anyRequest : 위에서 처리 하지 못한 나머지 경로 처리

        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/LoginProc")
                        .permitAll());

                // loginPage : login page 로 redirect
                // loginProcessingUrl : login 한 데이터를 특정한 경로로 보냄

        http
                .csrf((auth)->auth.disable());

        return http.build();
    }

}

```

> BCrypt 암호화 메소드
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668bda0b16014d6810ed85fb)

- 암호화를 무조건 진행해야 함.
- 사용자가 로그인할 때 아이디랑 비밀번호를 검증하는데, 비밀번호는 단방향 해시 암호화를 진행해서 저장되어 있는 비밀번호와 대조함. (비밀번호를 저장할 때도 해시 암호화 해서 저장해야 함)
- 이런 암호화를 위해 BCrypt 클래스를 제공하고 있음
- 그래서 이 클래스를 return 하는 메소드를 만들어 @Bean으로 등록해두면 회원가입, 검증할 때 자동으로 사용할 수 있도록 설정할 수 있음

**[단방향 해시 암호화]**

: 데이터를 고정된 크기의 해시 값으로 변환하는 과정 (이 해시 값에서 원래의 데이터를 복구하는 것이 매우 어렵거나 불가능한 암호화 방식)

cf. 해시함수는 단방향 (원본 데이터를 해시 값으로 변환하는 것은 쉽지만, 해시 값에서 원본 데이터를 복원하는 것은 사실상 불가능)

```java
@Bean
public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
}
```

> DB 연결
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668bda7916014d6810ed85fd)

![스크린샷 2024-09-02 오후 11.16.18.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/a0ff2a03-773c-4953-af24-b9d7906c8e17/f0aeb53d-9cc2-41c4-a044-cf8bc2f71226/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2024-09-02_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_11.16.18.png)

> 회원가입 로직
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668bdd44b374ad837c3f9deb)

- 회원정보를 통해 인증, 인가를 진행하기 때문에 로그인이 진행되어야 한다.
- 기존에 스프링 어플리케이션에 저장된 회원 정보를 가지고 진행하게 되는데, 스프링 어플리케이션에 기본적으로 사용자의 회원 정보를 가지고 있어야 한다.

![스크린샷 2024-09-08 오후 6.53.47.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/a0ff2a03-773c-4953-af24-b9d7906c8e17/56424ac8-b11b-445b-a278-cfbee4f48ed0/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2024-09-08_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_6.53.47.png)

1. 우선 페이지 먼저 생성

```java
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
</head>
<body>

<form action="/joinProc" method="post" name="joinForm">
    <input type="text" name="username" placeholder="Username"/>
    <input type="password" name="password" placeholder="Password"/>
    <input type="submit" value="Join"/>
</form>

</body>
</html>
```

1. dto 객체 

```java
package com.example.securityprac.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class JoinDto {

    private String userName;
    private String password;

}

```

1. Controller에 넘어가는 페이지 지정

```java
package com.example.securityprac.controller;

import com.example.securityprac.dto.JoinDto;
import com.example.securityprac.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @GetMapping("/join")
    public String joinP() {
        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProcess(JoinDto joinDto) {

        System.out.println(joinDto.getUserName());

        joinService.joinProcess(joinDto);

        return "redirect:/login";
    }
}

```

1. Entity 생성 (user) 

```java
package com.example.securityprac.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;
    private String password;
    private String role; // 권한을 저장할 role 값 넣어 주기

}

```

1. DB에 접근할 수 있게 Repository 생성

: 무조건 interface 형태로 생성

```java
package com.example.securityprac.repository;

import com.example.securityprac.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    

}

```

1. Table은 **Hibernate ddl**로 설정

→ update로 해두면 entity를 기반으로 테이블이 생성됨 

```java
spring.application.name=SecurityPrac

spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.datasource.url=jdbc:mysql://localhost:3306/SecurityPrac?useSSL=false&useUnicode=true&serverTimezone=Asia/Seoul&allowPublicKeyRetrieval=true
spring.datasource.username=root
spring.datasource.password=0070

spring.jpa.hibernate.ddl-auto=update
spring.jpa.hibernate.naming.physical-strategy=org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl
```

[[JPA] hibernate의 ddl-auto 속성의 종류와 주의해야할 점](https://colabear754.tistory.com/136)

: 그냥 실행할때만 update 

(테이블 만들어두면 다시 none으로 바꾸기) 

1. Service 로직 구현

: ROLE_ADMIN, ROLE_USER ← role 넣어주기

```java
package com.example.securityprac.service;

import com.example.securityprac.dto.JoinDto;
import com.example.securityprac.entity.UserEntity;
import com.example.securityprac.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDto joinDto) {

        // DB에 동일한 username 을 가진 회원이 존재 하는지 검증 필수 !!

        UserEntity data = new UserEntity();

        data.setUsername(joinDto.getUserName());
        data.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        data.setRole("ROLE_USER");

        userRepository.save(data);
    }

}

```

1. SecurityConfig 접근 권한 설정

```java
http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated());
```

: join, joinProc도 넣어줘야 로그인하지 않아도 모든 user가 접근 가능해짐 (이 경로에 접근해서 회원가입을 진행해야 하므로) 

> 회원 중복 검증 방법
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668be19d654633b8ec42f660)

- 중복된 가입에 대한 로직을 처리해줘야 함

→ 이 column이 unique 할 수 있도록

1. Entity 수정

```java
package com.example.securityprac.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(unique = true)
    private String username;
    private String password;
    private String role; // 권한을 저장할 role 값 넣어 주기

}

```

1. Repository 

```java
package com.example.securityprac.repository;

import com.example.securityprac.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    // 존재하면 true, 아니면 false 
    boolean existsByUsername(String username);
}

```

1. Service

```java
package com.example.securityprac.service;

import com.example.securityprac.dto.JoinDto;
import com.example.securityprac.entity.UserEntity;
import com.example.securityprac.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDto joinDto) {

        // DB에 동일한 username 을 가진 회원이 존재 하는지 검증 필수 !!
        boolean isUser = userRepository.existsByUsername(joinDto.getUserName());
        if (isUser) { // 동일한 회원 이면 
            return; // 함수 종료 
        }

        UserEntity data = new UserEntity();

        data.setUsername(joinDto.getUserName());
        data.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        data.setRole("ROLE_USER");

        userRepository.save(data);
    }

}

```

- 아이디, 비밀번호에 대한 정규식 처리도 필요함!
    - 아이디의 자리수
    - 아이디의 특수문자 포함 불가
    - admin과 같은 아이디 사용 불가
    - 비밀번호 자리수
    - 비밀번호 특수문자 포함 필수

> DB 기반 로그인 검증 로직
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668be4696a08359d16576c45)

![스크린샷 2024-09-08 오후 10.29.46.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/a0ff2a03-773c-4953-af24-b9d7906c8e17/d3780bad-065f-4733-84a7-c912ffb7f1d1/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2024-09-08_%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE_10.29.46.png)

→ 데이터베이스로부터 저장된 회원정보를 가지고 들어오는 데이터로 아이디 검증을 진행하려면 UserDetailService, UserDetails를 통해 구현 해야한다. 

[Spring Security UserDetails, UserDetailsService 란? - 삽질중인 개발자](https://programmer93.tistory.com/68#google_vignette)

1. Repository

```java
package com.example.securityprac.repository;

import com.example.securityprac.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    // 존재하면 true, 아니면 false
    boolean existsByUsername(String username);

    // username 을 통해 UserEntity 찾기 
    UserEntity findByUsername(String username);
}

```

1) UserDetailsService 는 DB로 부터 특정한 username에 대한 데이터를 들고올거고 

2) 들고온 데이터를 UserDetails 클래스에 넣어서 SecurityConfig에 전달해주면 SecurityConfig가 username에 대한 password, 특정한 role들을 검증함

3) 검증이 완료되면 스프링 세션에 저장해서 사용자가 들어오면 접근할 수 있도록 허용해줌 

1. CustomUserDetails Dto 생성

```java
package com.example.securityprac.dto;

import com.example.securityprac.entity.UserEntity;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@Getter
@Setter
public class CustomUserDetails implements UserDetails {

    private UserEntity userEntity;

    public CustomUserDetails(UserEntity userEntity) {
        this.userEntity = userEntity;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // 사용자의 특정 권한을 return
        // DB에 저장할 때 지정했던 role 값

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return userEntity.getRole();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    // 일단 개발 과정에서는 만료되지 않았다고 지정 (그래야 사용할 수 있음) 
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

```
