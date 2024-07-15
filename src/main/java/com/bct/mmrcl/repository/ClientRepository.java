package com.bct.mmrcl.repository;
import com.bct.mmrcl.model.Client;

import org.springframework.data.jpa.repository.JpaRepository;


public interface ClientRepository extends JpaRepository<Client, Long> {
	Client findByClientName(String clientName);
}