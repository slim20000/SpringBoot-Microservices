package com.slim.candidat.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Entity
public class Experience {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonIgnore
    private Long id;
    private String companyName;
    private String poste;
    private String position;
    private Date startDate;
    private Date endDate;
    private String description;
    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "candidate_id")
    private Candidate candidate;
}
