package com.slim.candidat.service;


import com.slim.candidat.client.IdentityServiceClient;
import com.slim.candidat.client.UserResponse;
import com.slim.candidat.model.Candidate;
import com.slim.candidat.model.Education;
import com.slim.candidat.model.Experience;
import com.slim.candidat.repository.CandidateRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import javax.persistence.EntityGraph;
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
@NoArgsConstructor
@Transactional
public class CandidateService {
    @Autowired
    CandidateRepository candidateRepository;
    @Autowired
    private IdentityServiceClient identityServiceClient;

    public List<Candidate> getAllCandidates() {
        return candidateRepository.findAll();
    }

    public Optional<Candidate> getCandidateById(Integer id) {
        return candidateRepository.findById(id);
    }

    public Optional<Candidate> getCandidateByEmail(String email) {
        return candidateRepository.findByEmail(email);
    }

    public Optional<Candidate> getCandidateByUserId(Integer userId) {
        return candidateRepository.findByUserId(userId);
    }
    public Candidate saveCandidate(Candidate candidate) {
        Optional<Candidate> existingCandidateOpt = candidateRepository.findByUserId(candidate.getUserId());
        if (existingCandidateOpt.isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Candidate with this userId already exists.");
        }
        candidate.getExperiences().forEach(experience -> experience.setCandidate(candidate));
        candidate.getEducationHistory().forEach(education -> education.setCandidate(candidate));

        return candidateRepository.save(candidate);
    }

    public void deleteCandidate(Integer id) {
        candidateRepository.deleteById(id);
    }

    public Candidate updateCandidate(Candidate updatedCandidate) {
        return candidateRepository.save(updatedCandidate);
    }
    public Candidate updateCandidateByUserId(Integer userId, Candidate updatedCandidate) {
        Optional<Candidate> existingCandidateOptional = candidateRepository.findByUserId(userId);
        if (existingCandidateOptional.isPresent()) {
            Candidate existingCandidate = existingCandidateOptional.get();
            existingCandidate.setFirstName(updatedCandidate.getFirstName());
            existingCandidate.setLastName(updatedCandidate.getLastName());
            existingCandidate.setAddress(updatedCandidate.getAddress());
            existingCandidate.setEmail(updatedCandidate.getEmail());
            existingCandidate.setPhoneNumber(updatedCandidate.getPhoneNumber());
            existingCandidate.setBirthDate(updatedCandidate.getBirthDate());
            existingCandidate.setExperiences(updatedCandidate.getExperiences());
            existingCandidate.setLanguageLevel(updatedCandidate.getLanguageLevel());
            existingCandidate.setEducationHistory(updatedCandidate.getEducationHistory());
            existingCandidate.setSkills(updatedCandidate.getSkills());

            return candidateRepository.save(existingCandidate);
        } else {
            throw new IllegalArgumentException("Candidate not found for userId: " + userId);
        }
    }

    public Candidate saveCandidateID(Candidate candidate, Integer userId) {
        ResponseEntity<UserResponse> response = identityServiceClient.getUserById(userId);
        candidate.getExperiences().forEach(experience -> experience.setCandidate(candidate));
        candidate.getEducationHistory().forEach(education -> education.setCandidate(candidate));
        UserResponse userResponse = response.getBody();
        if(userResponse != null) {
            candidate.setId(userResponse.getId());
        }
        return candidateRepository.save(candidate);
    }

    public List<Experience> getExperiencesByUserId(Integer userId) {
        Optional<Candidate> candidateOptional = candidateRepository.findByUserId(userId);

        if (candidateOptional.isPresent()) {
            Candidate candidate = candidateOptional.get();
            return candidate.getExperiences();
        }

        return Collections.emptyList();
    }

    public List<Education> getEducationHistoryByUserId(Integer userId) {
        Optional<Candidate> candidateOptional = candidateRepository.findByUserId(userId);

        if (candidateOptional.isPresent()) {
            Candidate candidate = candidateOptional.get();
            return candidate.getEducationHistory();
        }

        return Collections.emptyList();
    }

    public Candidate getCandidateWithExperiences(Integer userId) {
        return candidateRepository.findCandidateWithExperiences(userId);
    }


    public List<Candidate> findCandidatesWithSorting(String field){
        return  candidateRepository.findAll(Sort.by(Sort.Direction.ASC,field));
    }

    public Page<Candidate> findcandidatesPagination(int offset, int pageSize){
        Page<Candidate> candidates = candidateRepository.findAll(PageRequest.of(offset, pageSize));
        return  candidates;
    }

    public Page<Candidate> findcandidatesPaginationSort(int offset,int pageSize,String field){
        Page<Candidate> candidates = candidateRepository.findAll(PageRequest.of(offset, pageSize).withSort(Sort.by(field)));
        return  candidates;
    }


}
