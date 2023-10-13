package com.slim.candidat.repository;

import com.slim.candidat.model.FileData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository

public interface FileDataRepository extends JpaRepository<FileData,Long> {
    Optional<FileData> findById(Long fileId);
    Optional<FileData> findByUserIdAndFileType(Integer userId, FileData.FileType fileType);
}