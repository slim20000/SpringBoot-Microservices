package com.slim.company.controller;


import com.slim.company.model.CompanyDetails;
import com.slim.company.repository.CompanyDetailsRepository;
import com.slim.company.service.CompanyDetailsService;
import com.slim.company.service.FileService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@RestController
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
@RequestMapping("/company")
public class CompanyController {
    @Autowired
    CompanyDetailsRepository companyDetailsRepository;
    @Autowired
    CompanyDetailsService companyDetailsService;
    @Autowired
    FileService fileService;
    private static final Logger logger = LoggerFactory.getLogger(CompanyController.class);

    @GetMapping
    public ResponseEntity<List<CompanyDetails>> getAllCompanies(){
        List<CompanyDetails> companyDetails = companyDetailsService.getAllCompanies();
        return new ResponseEntity<>(companyDetails, HttpStatus.OK);
    }

//    public CompanyDetails saveCompany(CompanyDetails companyDetails) {
//        logger.info("Attempting to save company with userId: {}", companyDetails.getUserId());
//        Optional<CompanyDetails> existingCompany = companyDetailsRepository.findByUserId(companyDetails.getUserId());
//        if(existingCompany.isPresent()) {
//            logger.error("Company with userId: {} already exists!", companyDetails.getUserId());
//            throw new IllegalArgumentException("Company with the same userId already exists");
//        }
//        return companyDetailsRepository.save(companyDetails);
//    }
//
//    @ExceptionHandler(IllegalArgumentException.class)
//    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
//        return new ResponseEntity<>(ex.getMessage(), HttpStatus.BAD_REQUEST);
//    }
//@PostMapping("/company")
//public ResponseEntity<?> createCompany(@RequestPart("company") CompanyDetails companyDetails,
//                                       @RequestPart("image") MultipartFile file) {
//    String fileName = fileService.storeFile(file);
//    companyDetails.setPicture(fileName);
//
//    CompanyDetails savedCompany = companyDetailsService.saveCompany(companyDetails);
//    return new ResponseEntity<>(savedCompany, HttpStatus.CREATED);
//}
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCompany(@PathVariable Integer id){
        companyDetailsService.deleteCompany(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }
    @PutMapping("/{companyId}")
    public ResponseEntity<CompanyDetails> updateCompany(@PathVariable Integer companyId, @RequestBody CompanyDetails updatedCompany){
        updatedCompany.setCompanyId(companyId);
        CompanyDetails savedCompany = companyDetailsService.updateCompany(updatedCompany);
        if(savedCompany != null){
            return new ResponseEntity<>(savedCompany, HttpStatus.OK);
        }else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
@GetMapping("/{companyId}")
    public ResponseEntity<CompanyDetails> getCompanieById(@PathVariable Integer companyId){
    Optional<CompanyDetails> company = companyDetailsService.findCompanyById(companyId);
    if(company.isPresent()){
        return new ResponseEntity<>(company.get(),HttpStatus.OK);
    }else {
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
}
    @GetMapping("/search/findByUserId")
    public ResponseEntity<CompanyDetails> getCompanyByUserId(@RequestParam("userId") Integer userId) {
        Optional<CompanyDetails> companyDetailsOptional = companyDetailsService.getCompanyByUserId(userId);

        if (companyDetailsOptional.isPresent()) {
            CompanyDetails companyDetails = companyDetailsOptional.get();
            return new ResponseEntity<>(companyDetails, HttpStatus.OK);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

//    @PostMapping("/save")
//    public ResponseEntity<CompanyDetails> saveCandidate(@RequestBody CompanyDetails companyDetails, @RequestParam Integer userId) {
//        CompanyDetails companyUserID = companyDetailsService.saveCompanyUserID(companyDetails, userId);
//        return new ResponseEntity<>(companyUserID, HttpStatus.CREATED);
//    }


    @PostMapping("/save")
    public ResponseEntity<?> createCompanyDetails(@RequestBody CompanyDetails companyDetails) {
        try {
            CompanyDetails createdCompany = companyDetailsService.saveCompany(companyDetails);
            return new ResponseEntity<>(createdCompany, HttpStatus.CREATED);
        } catch(RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

}
