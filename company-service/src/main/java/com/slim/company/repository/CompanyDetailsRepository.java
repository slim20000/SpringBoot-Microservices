package com.slim.company.repository;

import com.slim.company.model.CompanyDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CompanyDetailsRepository extends JpaRepository<CompanyDetails, Integer> {
    Optional<CompanyDetails> findByUserId(Integer userId);

}
