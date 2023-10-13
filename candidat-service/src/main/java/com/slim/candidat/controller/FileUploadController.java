package com.slim.candidat.controller;


import com.slim.candidat.model.FileData;
import com.slim.candidat.service.CandidateService;
import com.slim.candidat.service.FileDataService;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;


@RestController
@RequestMapping("/file")
public class FileUploadController {


   @Autowired
   FileDataService fileDataService;
   @Autowired
   CandidateService candidateService;


    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(
            @RequestParam("userId") Integer userId,
            @RequestParam("fileType") FileData.FileType fileType,
            @RequestParam("file") MultipartFile file) {
        try {
            String response = fileDataService.uploadFile(file, userId, fileType);
            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to upload file: " + ex.getMessage());
        }
    }

    @GetMapping("/{fileId}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable Long fileId) {
        ResponseEntity<byte[]> responseEntity = fileDataService.downloadFile(fileId);
        return responseEntity;
    }

    @GetMapping("/downloadPDF/{userId}")
    public ResponseEntity<byte[]> downloadPDF(@PathVariable Integer userId){
        ResponseEntity<byte[]> responseEntity = fileDataService.downloadPDF(userId);
        return responseEntity;
    }
    @GetMapping("/downloadImage/{userId}")
    public  ResponseEntity<byte[]> downloadImage(@PathVariable Integer userId) {
        ResponseEntity<byte[]> responseEntity = fileDataService.downloadImage(userId);
        return responseEntity;
    }
//    @PostMapping("/upload")
//    public ResponseEntity<String> uploadAssignment(@RequestParam("file") MultipartFile file){
//        String response = fileDataService.uploadFile(file);
//        return ResponseEntity.status(HttpStatus.OK).body(response);
//
//    }
//
//    @GetMapping("/download/{fileName}")
//    public ResponseEntity downloadFile(@PathVariable String fileName) {
//
//        byte[] response = fileDataService.downloadFile(fileName);
//
//        return ResponseEntity.ok()
//                .contentType(MediaType.parseMediaType("application/pdf"))
//                .header(
//                        HttpHeaders.CONTENT_DISPOSITION,
//                        "attachment; filename=\"" + fileName + "\""
//                )
//                .body(response);
//    }
//    @PostMapping("/{candidateId}/upload-cv")
//    public ResponseEntity<String> uploadCV(
//            @PathVariable Integer candidateId,
//            @RequestParam("file") MultipartFile cvFile
//    ) {
//        String message = fileDataService.uploadCV(cvFile, candidateId);
//        return ResponseEntity.ok(message);
//    }
////    @PostMapping("/{candidateId}/upload-picture")
////    public ResponseEntity<String> uploadPicture(
////            @PathVariable Integer candidateId,
////            @RequestParam("file") MultipartFile pictureFile
////    ) {
////        String message = fileDataService.uploadPicture(pictureFile, candidateId);
////        return ResponseEntity.ok(message);
////    }
//
//    @GetMapping("/{candidateId}/download-cv")
//    public ResponseEntity<byte[]> downloadCV(@PathVariable Integer candidateId) {
//        byte[] cvContent = fileDataService.downloadCV(candidateId);
//
//        if (cvContent != null) {
//            return ResponseEntity.ok()
//                    .contentType(MediaType.APPLICATION_PDF)
//                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cv.pdf\"")
//                    .body(cvContent);
//        } else {
//            return ResponseEntity.notFound().build();
//        }
//    }
//    @GetMapping("/{candidateId}/download-pic")
//    public ResponseEntity<byte[]> downloadPic(@PathVariable Integer candidateId) {
//        byte[]pic = fileDataService.downloadPic(candidateId);
//
//        if (pic != null) {
//            return ResponseEntity.ok()
//                    .contentType(MediaType.IMAGE_PNG)
//                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cv.png\"")
//                    .body(pic);
//        } else {
//            return ResponseEntity.notFound().build();
//        }
//    }
//    @PostMapping("/{companyId}/CompanyPic")
//    public ResponseEntity<String> uploadCompanyPic(
//            @PathVariable Integer companyId,
//            @RequestParam("file") MultipartFile pictureFile
//    ) {
//        String message = fileDataService.uploadCompanyPic(pictureFile, companyId);
//        return ResponseEntity.ok(message);
//    }
//    @GetMapping("/{companyId}/CompanyPic")
//    public ResponseEntity<byte[]> downloadCompanyPic(@PathVariable Integer companyId) {
//        byte[] companyPicture = fileDataService.downloadCompanyPic(companyId);
//
//        if (companyPicture != null) {
//            return ResponseEntity.ok()
//                    .contentType(MediaType.IMAGE_PNG)
//                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"company.png\"")
//                    .body(companyPicture);
//        } else {
//            return ResponseEntity.notFound().build();
//        }
//    }
//    @PostMapping("/uploadPicture")
//    public ResponseEntity<String> uploadPicture(
//            @RequestParam("userId") Integer userId,
//            @RequestParam("pictureFile") MultipartFile pictureFile) {
//        try {
//            String response = fileDataService.uploadPicture(pictureFile, userId);
//            return ResponseEntity.ok(response);
//        } catch (Exception ex) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                    .body("Failed to upload profile picture: " + ex.getMessage());
//        }
//    }
}