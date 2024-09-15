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
        boolean isUser = userRepository.existsByUsername(joinDto.getUsername());
        if (isUser) { // 동일한 회원 이면
            return; // 함수 종료
        }

        UserEntity data = new UserEntity();

        data.setUsername(joinDto.getUsername());
        data.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }

}
