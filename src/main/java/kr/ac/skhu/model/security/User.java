package kr.ac.skhu.model.security;

import java.util.List;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

import kr.ac.skhu.security.service.UserService;
import lombok.*;

@Entity @Data
@Getter @Setter
@Builder @NoArgsConstructor
@AllArgsConstructor
@Table(name = "\"USER\"")
public class User {
    @Id
    @Column(name = "u_id")
    @NotNull
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private String id;

    @Column(name = "u_loginid")
    @NotNull
    private String loginId;

    @Column(name = "u_password")
    @NotNull
    private String password;

    @Column(name = "u_name")
    @NotNull
    private String name;

    @Column(name = "u_cnumber")
    private String cNumber;

    @Column(name = "u_status")
    private String status;

    @Column(name = "u_birth")
    private java.sql.Date birth;

    @Column(name = "u_phone")
    private String phone;

    @Column(name = "u_email")
    private String email;

    @Column(name = "u_address")
    private String address;

    @Column(name = "u_jobname")
    private String jobName;

    @Column(name = "u_jobphone")
    private String jobPhone;

    @Column(name = "u_jobstatus")
    private String jobStatus;

    @Column(name = "u_photo")
    private Boolean photo;

    @Column(name = "u_openbirth")
    private Boolean openBirth;

    @Column(name = "u_openphone")
    private Boolean openPhone;

    @Column(name = "u_openemail")
    private Boolean openEmail;

    @Column(name = "u_openaddress")
    private Boolean openAddress;

    @Column(name = "u_openjobname")
    private Boolean openJobName;

    @Column(name = "u_openjobphone")
    private Boolean openJobPhone;

    @Column(name = "u_openjobstatus")
    private Boolean openJobStatus;

    @Column(name = "u_openphoto")
    private Boolean openPhoto;

    @Column(name = "u_count")
    private Boolean count;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "\"USER_AUTHORITY\"",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "u_id")},
            inverseJoinColumns = {@JoinColumn(name = "authority_ID", referencedColumnName = "id")})
    private List<Authority> authorities;
    /* 암호를 인코딩 시켜 반환시키는, 웹 디비와 맞추기 위해.. */
    public String getPassword(){
        return UserService.passwordEncoding(this.password);
    }
}