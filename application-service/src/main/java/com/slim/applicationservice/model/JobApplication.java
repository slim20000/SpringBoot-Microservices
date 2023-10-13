package com.slim.applicationservice.model;

import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
@Entity
@Table(name = "job_application")
public class JobApplication {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer applicationId;
    private Integer jobId;
    @Column(name = "candidate_id")
    private Integer userId;
    @Column(name = "resume_path")
    private String resumePath;
    private ApplicationStatus status;
    private LocalDateTime applicationTimestamp;
    public enum ApplicationStatus {
        APPLIED, REVIEWED, INTERVIEWED, ACCEPTED, REJECTED
    }
}
