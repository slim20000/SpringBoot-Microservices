package com.slim.applicationservice.service;


import com.slim.applicationservice.model.JobApplication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    @Autowired
    private CandidateRestService candidateRestService;

    @Autowired
    private JavaMailSender mailSender;

    public void sendStatusUpdateEmail(Integer id, JobApplication.ApplicationStatus status) {
        String candidateEmail = candidateRestService.getCandidateEmail(id);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(candidateEmail);
        message.setSubject("Job Application Status");
        message.setText("Your job application status has been updated to: " + status);
        mailSender.send(message);
    }
    public void applicationConfirmEmail(Integer id) {
        String candidateEmail = candidateRestService.getCandidateEmail(id);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(candidateEmail);
        message.setSubject("Job Application Confirmation");
        message.setText("we received your job application.");
        mailSender.send(message);
    }
}
