package com.slim.candidat.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor

@Table(name = "fileData")
public class FileData {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonIgnore

    private Long fileId;

    @Column(name = "fileName", columnDefinition = "varchar(255)")
    private String fileName;

    @Column(name = "fileContent", columnDefinition = "LONGBLOB")
    private byte[] fileContent;
    @Column(unique = true)
    private Integer userId;

    @Enumerated(EnumType.STRING)
    private FileType fileType;

    public enum FileType {
        IMAGE, PDF
    }

    public void setFileType(FileType fileType) {
        this.fileType = fileType;
    }
//    @OneToOne(mappedBy = "cv")
//    private Candidate candidateCV;
//
//    @OneToOne(mappedBy = "profilePicture")
//    private Candidate candidatePicture;
//
//    private Integer companyId;

}