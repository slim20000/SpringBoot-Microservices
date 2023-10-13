package com.slim.company.controller;


import com.slim.company.model.JobDetails;
import com.slim.company.repository.CompanyDetailsRepository;
import com.slim.company.repository.JobDetailsRepository;
import com.slim.company.service.JobDetailsService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
@RequestMapping("/jobs")
public class JobsController {
    @Autowired
    private JobDetailsRepository jobDetailsRepository;
    @Autowired
    CompanyDetailsRepository companyDetailsRepository;
    @Autowired
    JobDetailsService jobDetailsService;

    @GetMapping("/all-jobs")
    public ResponseEntity<List<JobDetails>> getAllJobs(){
        List<JobDetails> jobDetails = jobDetailsService.getAllJobs();
        return new ResponseEntity<>(jobDetails, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<JobDetails> createJob(@RequestBody JobDetails jobDetails ){
        JobDetails createdJob = jobDetailsService.saveJobDetails(jobDetails);
        return new ResponseEntity<>(HttpStatus.OK);
    }
    @PutMapping("/{jobId}")
    public ResponseEntity<JobDetails> updateJob(@PathVariable Integer jobId, @RequestBody JobDetails updatedJob){
        updatedJob.setJobId(jobId);
        JobDetails savedJob = jobDetailsService.updateJob(updatedJob);
        if (savedJob != null){
            return new ResponseEntity<>(HttpStatus.OK);
        }else{
            return  new ResponseEntity<>(HttpStatus.OK);
        }
    }
    @GetMapping("/{jobId}")
    public ResponseEntity<JobDetails> getJobById(@PathVariable Integer jobId){
        Optional<JobDetails> job = jobDetailsService.findJobById(jobId);
        if(job.isPresent()){
            return new ResponseEntity<>(job.get(),HttpStatus.OK);
        }else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    @PostMapping("/{companyId}")
    public ResponseEntity<JobDetails> addCompanyJob(@PathVariable Integer companyId , @RequestBody JobDetails jobDetails ){
        try {
            JobDetails savedJob = jobDetailsService.addCompanyJob(companyId,jobDetails);
            return ResponseEntity.ok(savedJob);
        }
        catch (IllegalArgumentException e){
            return ResponseEntity.notFound().build();
        }
    }
    @GetMapping("/company/{companyId}")
    public ResponseEntity<List<JobDetails>> getAllJobsByCompanyId(@PathVariable Integer companyId) {
        List<JobDetails> jobs = jobDetailsService.getAllJobsByCompanyId(companyId);

        if (jobs.isEmpty()) {
            return ResponseEntity.noContent().build();
        } else {
            return ResponseEntity.ok(jobs);
        }
    } @DeleteMapping("/{jobId}")
    public ResponseEntity<Void> deleteJob(@PathVariable Integer jobId){
        jobDetailsService.deleteJob(jobId);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
