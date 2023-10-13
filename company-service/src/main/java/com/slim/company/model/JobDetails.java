package com.slim.company.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;
import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
@Entity
@Table(name = "job_detail")
public class JobDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer jobId;
    private String jobTitle;
    private Integer peopleNumber;
    private String location;
    @Enumerated(EnumType.STRING)
    private JobType jobType;
    private Integer nbrHours;
    private Date startDate;
    private Integer salary;
    private String description;

    @ManyToOne
    private CompanyDetails companyDetails;
}
