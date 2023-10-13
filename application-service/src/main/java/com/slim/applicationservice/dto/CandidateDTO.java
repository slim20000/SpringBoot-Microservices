package com.slim.applicationservice.dto;

import lombok.*;

import javax.persistence.Entity;
import java.util.Date;
import java.util.Map;
@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
@Data
public class CandidateDTO {

    private Integer id;
    private Integer userId;
    private String firstName;
    private String lastName;
    private String address;
    private String email;
    private String phoneNumber;
    private Date birthDate;
    private Map<String, String> skills;
    private Map<String, String> languageLevel;

//    private List<ExperienceDTO> experiences;
//    private List<EducationDTO> educationHistory;


}