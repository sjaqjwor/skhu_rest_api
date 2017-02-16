package kr.ac.skhu.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import kr.ac.skhu.model.security.User;


public interface UserRepository extends JpaRepository<User, Integer> {
    User findByName(String name);
    User findByLoginId(String loginId);
}
