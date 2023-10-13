package com.slim.candidat.model;


import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.hibernate.FetchMode;
import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.Fetch;

import javax.persistence.*;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
@Entity
@Table(name = "candidate")

public class Candidate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(unique = true)
    private Integer userId;
    private String firstName;
    private String lastName;
    private String address;
    private String email;
    private String phoneNumber;
    private Date birthDate;

    @ElementCollection
    @MapKeyColumn(name = "skill")
    @Column(name = "level")
    private Map<String, Level> skills;

    @ElementCollection
    @MapKeyEnumerated(EnumType.STRING)
    @MapKeyColumn(name = "language")
    @Column(name = "level")
    private Map<Language, Level> languageLevel;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "candidate", fetch = FetchType.LAZY)
    private List<Experience> experiences;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "candidate", fetch = FetchType.LAZY)
    private List<Education> educationHistory;

//    @JsonIgnore
//    @OneToOne(cascade = CascadeType.ALL)
//    private FileData cv;
//
//    @JsonIgnore
//    @OneToOne(cascade = CascadeType.ALL)
//    private FileData profilePicture;

}
