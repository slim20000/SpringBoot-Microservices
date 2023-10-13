package com.slim.company.repository;

import com.slim.company.model.JobDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface JobDetailsRepository extends JpaRepository<JobDetails, Integer> {
    List<JobDetails> findAllByCompanyDetails_CompanyId(Integer companyId);

}
