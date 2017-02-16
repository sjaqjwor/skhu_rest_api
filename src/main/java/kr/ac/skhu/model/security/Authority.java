package kr.ac.skhu.model.security;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.List;

import lombok.*;

@Entity @Data
@Getter @Setter
@Builder @NoArgsConstructor
@AllArgsConstructor
@Table(name = "\"AUTHORITY\"")
public class Authority {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "authority_seq")
    @SequenceGenerator(name = "authority_seq", sequenceName = "authority_seq", allocationSize = 1)
    private int id;

    @Column(name = "name", length = 50)
    @NotNull
    @Enumerated(EnumType.STRING)
    private AuthorityName name;

    @ManyToMany(mappedBy = "authorities", fetch = FetchType.LAZY)
    private List<User> users;
}