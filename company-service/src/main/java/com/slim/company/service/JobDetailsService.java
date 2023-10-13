package com.slim.company.service;

import com.slim.company.model.CompanyDetails;
import com.slim.company.model.JobDetails;
import com.slim.company.repository.CompanyDetailsRepository;
import com.slim.company.repository.JobDetailsRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
@NoArgsConstructor
@Transactional
public class JobDetailsService {
    @Autowired
    private JobDetailsRepository jobDetailsRepository;
    @Autowired
    private CompanyDetailsRepository companyDetailsRepository;

    public JobDetails saveJobDetails(JobDetails jobDetails){
        return jobDetailsRepository.save(jobDetails);
    }
    public List<JobDetails> getAllJobs(){
        return  jobDetailsRepository.findAll();
    }
    public Optional<JobDetails> findJobById(Integer id){
        return jobDetailsRepository.findById(id);
    }

    public JobDetails updateJob(JobDetails updatedJob){
        return jobDetailsRepository.save(updatedJob);
    }

    public JobDetails addCompanyJob(Integer companyId, JobDetails jobDetails){
        Optional<CompanyDetails> companyOptional = companyDetailsRepository.findById(companyId);
        if (companyOptional.isPresent()){
          CompanyDetails companyDetails = companyOptional.get();
          jobDetails.setCompanyDetails(companyDetails);
          JobDetails savedJob = jobDetailsRepository.save(jobDetails);
            companyDetails.getJobDetails().add(savedJob);
            companyDetailsRepository.save(companyDetails);
            return savedJob;
        }else {
            throw new IllegalArgumentException("company : "+ companyId + "Not found");
        }
    }
    public List<JobDetails> getAllJobsByCompanyId(Integer companyId) {
        return jobDetailsRepository.findAllByCompanyDetails_CompanyId(companyId);
    }

    public void deleteJob(Integer jobId) {
        jobDetailsRepository.deleteById(jobId);
    }

}

