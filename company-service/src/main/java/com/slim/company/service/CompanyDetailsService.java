package com.slim.company.service;


import com.slim.company.client.IdentityServiceClient;
import com.slim.company.client.UserResponse;
import com.slim.company.model.CompanyDetails;
import com.slim.company.repository.CompanyDetailsRepository;
import com.slim.company.repository.JobDetailsRepository;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
@NoArgsConstructor
@Transactional
@Getter
@Setter
public class CompanyDetailsService {
    @Autowired
    private IdentityServiceClient identityServiceClient;

    @Autowired
    private JobDetailsRepository jobDetailsRepository;
    @Autowired
    private CompanyDetailsRepository companyDetailsRepository;

    public CompanyDetails saveCompany(CompanyDetails companyDetails) {
        Optional<CompanyDetails> existingCompany = companyDetailsRepository.findByUserId(companyDetails.getUserId());
        if(existingCompany.isPresent()) {
            throw new IllegalArgumentException("Company with the same userId already exists");
        }
        return companyDetailsRepository.save(companyDetails);
    }
    public List<CompanyDetails> getAllCompanies() {
        return companyDetailsRepository.findAll();
    }

    public Optional<CompanyDetails> findCompanyById(Integer Id) {
        return companyDetailsRepository.findById(Id);
    }

    public CompanyDetails updateCompany(CompanyDetails updatedCompany) {
        return companyDetailsRepository.save(updatedCompany);
    }

    public void deleteCompany(Integer id) {
        companyDetailsRepository.deleteById(id);
    }


    public Optional<CompanyDetails> getCompanyByUserId(Integer userId) {
        return companyDetailsRepository.findByUserId(userId);
    }

    public CompanyDetails saveCompanyUserID(CompanyDetails companyDetails, Integer userId) {
        ResponseEntity<UserResponse> response = identityServiceClient.getUserById(userId);
        UserResponse userResponse = response.getBody();
        if(userResponse != null) {
            companyDetails.setCompanyId(userResponse.getId());
        }
        return companyDetailsRepository.save(companyDetails);
    }

}