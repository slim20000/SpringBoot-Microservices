package com.slim.applicationservice.service;

import com.slim.applicationservice.model.JobApplication;
import com.slim.applicationservice.repository.JobApplicationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;

@Service
public class JobApplicationService {
    @Value("${file.upload-dir}")
    private String uploadDir;
    private static final String COMPANY_SERVICE_URL = "http://localhost:4444/jobs/{jobId}";
    private static final String CANDIDATE_SERVICE_URL = "http://localhost:3333/candidate/getCandidateByUserId/{userId}";
    @Autowired
    private CandidateRestService candidateRestService;
    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private EmailService emailService;
    @Autowired
    JobApplicationRepository jobApplicationRepository;

    public JobApplication applyForJob(JobApplication jobApplication) {
        if (!jobIdValid(jobApplication.getJobId()) || !candidateIdValid(jobApplication.getUserId())) {
            throw new IllegalArgumentException("Invalid jobId or candidateId");
        }
        emailService.applicationConfirmEmail(jobApplication.getUserId());
        return jobApplicationRepository.save(jobApplication);
    }

    public Optional<JobApplication> getApplicationById(Integer applicationId) {
        return jobApplicationRepository.findByApplicationId(applicationId);
    }

    public List<JobApplication> getApplicationsByCandidateId(Integer userId) {
        return jobApplicationRepository.findAllByUserId(userId);
    }

    public JobApplication updateApplicationStatus(Integer applicationId, JobApplication.ApplicationStatus status) {
        Optional<JobApplication> jobApplicationOptional = jobApplicationRepository.findByApplicationId(applicationId);
        if (jobApplicationOptional.isPresent()) {
            JobApplication jobApplication = jobApplicationOptional.get();
            jobApplication.setStatus(status);
            jobApplicationRepository.save(jobApplication);
            emailService.sendStatusUpdateEmail(jobApplication.getUserId(), status);
            return jobApplication;
        }
        throw new IllegalArgumentException("No job application found with Id: " + applicationId);
    }

    public List<JobApplication> getApplicationsByJobId(Integer jobId) {
        return jobApplicationRepository.findAllByJobId(jobId);
    }
    private boolean jobIdValid(Integer jobId) {
        try {
            ResponseEntity<Void> response = restTemplate.getForEntity(COMPANY_SERVICE_URL, Void.class, jobId);
            return response.getStatusCode() == HttpStatus.OK;
        } catch (HttpClientErrorException.NotFound ex) {
            return false;
        }
    }

    private boolean candidateIdValid(Integer userId) {
        try {
            ResponseEntity<Void> response = restTemplate.getForEntity(CANDIDATE_SERVICE_URL, Void.class, userId);
            return response.getStatusCode() == HttpStatus.OK;
        } catch (HttpClientErrorException.NotFound ex) {
            return false;
        }
    }


    public String storeFile(MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IOException("Failed to store empty file.");
        }

        Path uploadPath = Paths.get(uploadDir);
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        String filename = System.currentTimeMillis() + "_" + file.getOriginalFilename();
        Path filePath = uploadPath.resolve(filename);
        file.transferTo(filePath);

        return filename;
    }

}