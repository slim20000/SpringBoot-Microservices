package com.slim.company.dto;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class JobDetailsDTO {
    private Integer jobId;
    private String jobTitle;
}
