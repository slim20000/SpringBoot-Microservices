package com.slim.candidat.controller;


import com.slim.candidat.dto.APIResponse;
import com.slim.candidat.model.Candidate;

import com.slim.candidat.model.Education;
import com.slim.candidat.model.Experience;
import com.slim.candidat.repository.CandidateRepository;
import com.slim.candidat.service.CandidateService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RestController
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
@RequestMapping("/candidate")
public class CandidateController {
    @Autowired
    CandidateService candidateService;
    @Autowired
    CandidateRepository candidateRepository;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping
    public ResponseEntity<List<Candidate>> getAllCandidates() {
        List<Candidate> candidates = candidateService.getAllCandidates();
        return new ResponseEntity<>(candidates, HttpStatus.OK);
    }

    @PostMapping("/create")
    public ResponseEntity<?> createCandidate(@RequestBody Candidate candidate) {
        try {
            Candidate createdCandidate = candidateService.saveCandidate(candidate);
            return new ResponseEntity<>(createdCandidate, HttpStatus.CREATED);
        } catch(RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCandidate(@PathVariable Integer id) {
        candidateService.deleteCandidate(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
    @GetMapping("/{id}")
    public ResponseEntity<Candidate> getCandidateById(@PathVariable Integer id) {
        Optional<Candidate> candidate = candidateService.getCandidateById(id);

        if (candidate.isPresent()) {
            return new ResponseEntity<>(candidate.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    @GetMapping("/getCandidateByUserId/{userId}")
    public ResponseEntity<Candidate> getCandidateByUserId(@PathVariable Integer userId) {
        Optional<Candidate> candidate = candidateService.getCandidateByUserId(userId);

        if (candidate.isPresent()) {
            return new ResponseEntity<>(candidate.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    @PutMapping("/updateCandidateByUserID/{userId}")
    public ResponseEntity<Candidate> updateCandidateByUserID(@PathVariable Integer userId, @RequestBody Candidate updatedCandidate) {
        Candidate updated = candidateService.updateCandidateByUserId(userId, updatedCandidate);
        return new ResponseEntity<>(updated, HttpStatus.OK);
    }
    @GetMapping("/email/{email}")
    public ResponseEntity<Candidate> getCandidateByEmail(@PathVariable String email) {
        Optional<Candidate> candidate = candidateService.getCandidateByEmail(email);

        if (candidate.isPresent()) {
            return new ResponseEntity<>(candidate.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    @GetMapping("/search/findByUserId2")
    public ResponseEntity<Candidate> getCandidateByUserId2(@RequestParam("userId") Integer userId) {
        Optional<Candidate> candidate = candidateService.getCandidateByUserId(userId);

        if (candidate.isPresent()) {
            return new ResponseEntity<>(candidate.get(), HttpStatus.OK);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    @GetMapping("/getExperiencesByUserId")
    public ResponseEntity<List<Experience>> getExperiencesByUserId(@RequestParam("userId") Integer userId) {
        List<Experience> experiences = candidateService.getExperiencesByUserId(userId);
        return new ResponseEntity<>(experiences, HttpStatus.OK);
    }
//    @GetMapping("/search/findByUserId")
//    public ResponseEntity<Candidate> getCandidateByUserId(@RequestParam("userId") Integer userId) {
//        Candidate candidate = candidateService.getCandidateWithExperiences(userId);
//
//        if (candidate != null) {
//            return new ResponseEntity<>(candidate, HttpStatus.OK);
//        } else {
//            return ResponseEntity.notFound().build();
//        }
//    }
    @GetMapping("/getEducationHistoryByUserId")
    public ResponseEntity<List<Education>> getEducationHistoryByUserId(@RequestParam("userId") Integer userId) {
        List<Education> educationHistory = candidateService.getEducationHistoryByUserId(userId);
        return new ResponseEntity<>(educationHistory, HttpStatus.OK);
    }
    @PutMapping("/update/{id}")
    public ResponseEntity<Candidate> updateCandidate(@PathVariable Integer id, @RequestBody Candidate updatedCandidate) {
        updatedCandidate.setId(id);

        Candidate savedCandidate = candidateService.updateCandidate(updatedCandidate);

        if (savedCandidate != null) {
            return new ResponseEntity<>(savedCandidate, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    @GetMapping("/sort/{field}")
    private APIResponse<List<Candidate>> getCandidatesWithSort(@PathVariable String field) {
        List<Candidate> allCandidates = candidateService.findCandidatesWithSorting(field);
        return new APIResponse<>(allCandidates.size(), allCandidates);
    }

    @GetMapping("/pagination/{offset}/{pageSize}")
    private APIResponse<Page<Candidate>> getProductsWithPagination(@PathVariable int offset, @PathVariable int pageSize) {
        Page<Candidate> candidatetsWithPagination = candidateService.findcandidatesPagination(offset, pageSize);
        return new APIResponse<>(candidatetsWithPagination.getSize(), candidatetsWithPagination);

    }

    @GetMapping("/paginationAndSort/{offset}/{pageSize}/{field}")
    private APIResponse<Page<Candidate>> getCandidatesWithPaginationAndSort(@PathVariable int offset, @PathVariable int pageSize,@PathVariable String field) {
        Page<Candidate> candidatesWithPagination = candidateService.findcandidatesPaginationSort(offset, pageSize, field);
        return new APIResponse<>(candidatesWithPagination.getSize(), candidatesWithPagination);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/adminEndpoint")
    public ResponseEntity<String> adminAccessOnly() {
        return ResponseEntity.ok("00000000000000000000000000000000");
    }

    @PostMapping("/save")
    public ResponseEntity<Candidate> saveCandidate(@RequestBody Candidate candidate, @RequestParam Integer userId) {
        Candidate savedCandidate = candidateService.saveCandidateID(candidate, userId);
        return new ResponseEntity<>(savedCandidate, HttpStatus.CREATED);
    }
    @GetMapping("/{id}/email")
    public ResponseEntity<String> getCandidateEmail(@PathVariable Integer id) {
        Candidate candidate = candidateRepository.findById(id).orElse(null);
        if (candidate == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(candidate.getEmail());
    }
}
