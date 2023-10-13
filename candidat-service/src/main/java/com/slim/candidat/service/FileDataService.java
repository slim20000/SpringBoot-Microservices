package com.slim.candidat.service;

import com.slim.candidat.client.IdentityServiceClient;
import com.slim.candidat.client.UserResponse;
import com.slim.candidat.model.FileData;
import com.slim.candidat.repository.CandidateRepository;
import com.slim.candidat.repository.FileDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Optional;

@Service
public class FileDataService {

    @Autowired
    private FileDataRepository fileDataRepository;
    @Autowired
    private CandidateRepository candidateRepository;
    @Autowired
    IdentityServiceClient identityServiceClient;


    public String uploadFile(MultipartFile file, Integer userId, FileData.FileType fileType) {
        ResponseEntity<UserResponse> userResponse = identityServiceClient.getUserById(userId);
        if (userResponse.getStatusCode() != HttpStatus.OK) {
            return "User dont exist";
        }

        try {
            String fileName = StringUtils.cleanPath(file.getOriginalFilename());

            FileData fileData = new FileData();
            fileData.setFileName(fileName);
            fileData.setFileContent(file.getBytes());
            fileData.setUserId(userId);
            fileData.setFileType(fileType);

            fileDataRepository.save(fileData);

            return "File submitted successfully";
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public ResponseEntity<byte[]> downloadFile(Long fileId) {
        try {
            Optional<FileData> fileDataOptional = fileDataRepository.findById(fileId);

            if (fileDataOptional.isPresent()) {
                FileData fileData = fileDataOptional.get();
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
                headers.setContentDispositionFormData("attachment", fileData.getFileName());

                return new ResponseEntity<>(fileData.getFileContent(), headers, HttpStatus.OK);
            } else {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public ResponseEntity<byte[]> downloadPDF(Integer userId) {
        try {
            Optional<FileData> pdfFileOptional = fileDataRepository.findByUserIdAndFileType(userId, FileData.FileType.PDF);
            if (pdfFileOptional.isPresent()) {
                FileData pdfFile = pdfFileOptional.get();
                HttpHeaders headers = new HttpHeaders();
                headers.setContentDispositionFormData("attachement", pdfFile.getFileName());
                return new ResponseEntity<>(pdfFile.getFileContent(), headers, HttpStatus.OK);
            } else {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    public ResponseEntity<byte[]> downloadImage(Integer userId) {
        try {
            Optional<FileData> imageFileOptional = fileDataRepository.findByUserIdAndFileType(userId, FileData.FileType.IMAGE);
            if (imageFileOptional.isPresent()) {
                FileData imageFile = imageFileOptional.get();
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.IMAGE_PNG);
                headers.setContentDispositionFormData("attachemnt", imageFile.getFileName());
                return new ResponseEntity<>(imageFile.getFileContent(), headers, HttpStatus.OK);

            }else {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
        } catch (Exception exception){
            throw  new RuntimeException(exception);
        }
    }
//    public String uploadFile(MultipartFile request) {
//        String fileName = StringUtils.cleanPath(request.getOriginalFilename());
//
//        try {
//            FileData fileData = new FileData();
//            fileData.setFileName(fileName);
//            fileData.setFileContent(request.getBytes());
//
//            fileDataRepository.save(fileData);
//            return "File submitted successfully";
//        } catch (IOException ex) {
//            throw new RuntimeException(ex);
//        }
//
//    }
//
//    public byte[] downloadFile(String fileName) {
//        FileData fileData = fileDataRepository.findByFileName(fileName);
//        return fileData.getFileContent();
//    }
//    @Transactional(readOnly = true)
//    public byte[] downloadCV(Integer candidateId) {
//        Candidate candidate = candidateRepository.findById(candidateId)
//                .orElseThrow(() -> new EntityNotFoundException("Candidate not found"));
//
//        if (candidate.getCv() != null) {
//            return candidate.getCv().getFileContent();
//        } else {
//            return null;
//        }
//    }
//
//    public String uploadCV(MultipartFile cvFile, Integer candidateId) {
//        try {
//            Candidate candidate = candidateRepository.findById(candidateId)
//                    .orElseThrow(() -> new EntityNotFoundException("Candidate not found"));
//
//            String fileName = StringUtils.cleanPath(cvFile.getOriginalFilename());
//
//            FileData cv = new FileData();
//            cv.setFileName(fileName);
//            cv.setFileContent(cvFile.getBytes());
//
//            candidate.setCv(cv);
//            candidateRepository.save(candidate);
//
//            return "CV submitted successfully for candidate with ID: " + candidateId;
//        } catch (IOException ex) {
//            throw new RuntimeException(ex);
//        }
//    }

//    public String uploadPicture(MultipartFile pictureFile, Integer candidateId) {
//        try {
//            Candidate candidate = candidateRepository.findById(candidateId)
//                    .orElseThrow(() -> new EntityNotFoundException("Candidate not found"));
//
//            String fileName = StringUtils.cleanPath(pictureFile.getOriginalFilename());
//
//            FileData profilePicture = new FileData();
//            profilePicture.setFileName(fileName);
//            profilePicture.setFileContent(pictureFile.getBytes());
//
//            candidate.setProfilePicture(profilePicture);
//            candidateRepository.save(candidate);
//
//            return "Profile picture submitted successfully for candidate with ID: " + candidateId;
//        } catch (IOException ex) {
//            throw new RuntimeException(ex);
//        }
//    }
//    @Transactional(readOnly = true)
//    public byte[] downloadPic(Integer candidateId) {
//        Candidate candidate = candidateRepository.findById(candidateId)
//                .orElseThrow(() -> new EntityNotFoundException("Candidate not found"));
//
//        if (candidate.getProfilePicture() != null) {
//            return candidate.getProfilePicture().getFileContent();
//        } else {
//            return null;
//        }
//    }
//    public String uploadCompanyPic(MultipartFile pictureFile, Integer companyId) {
//        try {
//            String fileName = StringUtils.cleanPath(pictureFile.getOriginalFilename());
//
//            FileData companyPicture = new FileData();
//            companyPicture.setFileName(fileName);
//            companyPicture.setFileContent(pictureFile.getBytes());
//            companyPicture.setCompanyId(companyId);
//
//            fileDataRepository.save(companyPicture);
//
//            return "companyId: " + companyId;
//        } catch (IOException ex) {
//            throw new RuntimeException(ex);
//        }
//    }
//    public byte[] downloadCompanyPic(Integer companyId) {
//        FileData companyPicture = fileDataRepository.findByCompanyId(companyId);
//
//        if (companyPicture != null) {
//            return companyPicture.getFileContent();
//        } else {
//            return null;
//        }
//    }
//
//    public String uploadPicture(MultipartFile pictureFile, Integer userId) {
//        try {
//            ResponseEntity<UserResponse> userResponse = identityServiceClient.getUserById(userId);
//
//            if (userResponse.getStatusCode() == HttpStatus.OK) {
//                UserResponse user = userResponse.getBody();
//
//                if (user != null) {
//                    String fileName = StringUtils.cleanPath(pictureFile.getOriginalFilename());
//
//                    FileData profilePicture = new FileData();
//                    profilePicture.setFileName(fileName);
//                    profilePicture.setFileContent(pictureFile.getBytes());
//
//                    // You may want to associate the profile picture with the user here
//                    // user.setProfilePicture(profilePicture);
//
//                    fileDataRepository.save(profilePicture);
//
//                    return "Profile picture submitted successfully for user with ID: " + userId;
//                } else {
//                    throw new EntityNotFoundException("User not found with ID: " + userId);
//                }
//            } else {
//                throw new RuntimeException("Failed to fetch user from identity service");
//            }
//        } catch (IOException ex) {
//            throw new RuntimeException(ex);
//        }
//    }

}

