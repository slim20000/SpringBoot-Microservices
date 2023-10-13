package com.slim.applicationservice.repository;

import com.slim.applicationservice.model.JobApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface JobApplicationRepository extends JpaRepository<JobApplication, Long> {
    List<JobApplication> findAllByUserId(Integer userId);
    List<JobApplication> findAllByJobId(Integer jobId);
    Optional<JobApplication> findSingleByUserId(Integer userId);
    Optional<JobApplication> findByApplicationId(Integer applicationId);
}

