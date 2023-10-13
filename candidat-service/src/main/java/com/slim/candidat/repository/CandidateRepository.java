package com.slim.candidat.repository;

import com.slim.candidat.model.Candidate;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CandidateRepository extends JpaRepository<Candidate, Integer> {
    Optional<Candidate> findByEmail(String email);
    Optional<Candidate> findByUserId(Integer userId);
    @EntityGraph(attributePaths = {"experiences", "educationHistory"})
    Optional<Candidate> findOneByUserId(Integer userId);
    @Query("SELECT c FROM Candidate c LEFT JOIN FETCH c.experiences WHERE c.userId = :userId")
    Candidate findCandidateWithExperiences(@Param("userId") Integer userId);

}
