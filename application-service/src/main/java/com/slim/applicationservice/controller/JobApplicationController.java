package com.slim.applicationservice.controller;


import com.slim.applicationservice.model.JobApplication;
import com.slim.applicationservice.service.JobApplicationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/applications")
public class JobApplicationController {

    @Autowired
    JobApplicationService jobApplicationService;

    @PostMapping
    public ResponseEntity<JobApplication> applyForJob(@RequestBody JobApplication jobApplication) {
        JobApplication savedApplication = jobApplicationService.applyForJob(jobApplication);
        return new ResponseEntity<>(savedApplication, HttpStatus.CREATED);
    }

    @GetMapping("/{applicationId}")
    public ResponseEntity<JobApplication> getApplicationById(@PathVariable Integer applicationId) {
        return jobApplicationService.getApplicationById(applicationId)
                .map(application -> new ResponseEntity<>(application, HttpStatus.OK))
                .orElse(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @GetMapping
    public ResponseEntity<List<JobApplication>> getApplicationsByCandidateId(@RequestParam Integer id) {
        List<JobApplication> applications = jobApplicationService.getApplicationsByCandidateId(id);
        if (applications.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(applications, HttpStatus.OK);
    }

    @PutMapping("/{applicationId}/status")
    public ResponseEntity<JobApplication> updateApplicationStatus(
            @PathVariable Integer applicationId,
            @RequestParam JobApplication.ApplicationStatus status) {

        try {
            JobApplication updatedApplication = jobApplicationService.updateApplicationStatus(applicationId, status);
            return new ResponseEntity<>(updatedApplication, HttpStatus.OK);
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    @GetMapping("/getByJobId/{jobId}")
    public ResponseEntity<List<JobApplication>> getAllApplicationsByJobId(@PathVariable Integer jobId) {
        List<JobApplication> applications = jobApplicationService.getApplicationsByJobId(jobId);

        if (applications.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }

        return new ResponseEntity<>(applications, HttpStatus.OK);
    }
    @PostMapping("/upload")
    public ResponseEntity<JobApplication> applyForJobWithUpload(@RequestParam("resume") MultipartFile resume,
                                                                @RequestParam("jobId") Integer jobId,
                                                                @RequestParam("userId") Integer userId) {
        try {
            String resumePath = jobApplicationService.storeFile(resume);

            JobApplication jobApplication = new JobApplication();
            jobApplication.setJobId(jobId);
            jobApplication.setUserId(userId);
            jobApplication.setResumePath(resumePath);
            jobApplication.setStatus(JobApplication.ApplicationStatus.APPLIED);
            jobApplication.setApplicationTimestamp(LocalDateTime.now());

            JobApplication savedApplication = jobApplicationService.applyForJob(jobApplication);
            return ResponseEntity.ok(savedApplication);
        } catch (IOException e) {
            return ResponseEntity.badRequest().build();
        }
    }

}
