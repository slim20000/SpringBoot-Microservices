package com.slim.candidat.dto;

import lombok.*;

import java.util.Date;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class CandidateDTO {

    private String firstName;
    private String lastName;
    private String email;
    private String phoneNumber;
    private Date birthDate;
    private List<ExperienceDTO> experiences;
    private List<EducationDTO> educationHistory;


    public static class ExperienceDTO {
        private String companyName;
        private String poste;
        private String position;
        private Date startDate;
        private Date endDate;
        private String description;

    }

    public static class EducationDTO {
        private String school;
        private Date startDate;
        private Date endDate;
        private String degree;

    }
}