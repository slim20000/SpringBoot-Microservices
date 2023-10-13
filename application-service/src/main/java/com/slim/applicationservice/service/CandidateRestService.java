package com.slim.applicationservice.service;


import com.slim.applicationservice.dto.CandidateDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class CandidateRestService {
    @Autowired
    private RestTemplate restTemplate;


    private static final String CANDIDATE_SERVICE_URL = "http://localhost:3333/candidate/getCandidateByUserId/";

    public String getCandidateEmail(Integer userId) {
        String url = CANDIDATE_SERVICE_URL + userId;
        CandidateDTO candidate = restTemplate.getForObject(url, CandidateDTO.class);
        return candidate != null ? candidate.getEmail() : null;
    }
}
