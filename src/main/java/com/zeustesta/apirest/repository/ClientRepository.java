package com.zeustesta.apirest.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.zeustesta.apirest.model.Client;


@Repository
public interface ClientRepository extends JpaRepository<Client, UUID>{
  public Optional<Client> findByEmail(String email);

  public List<Client> findAll();

  @Modifying()
  @Query(value = "UPDATE Client c SET c.first_name =:firstName, c.last_name =:lastName WHERE c.client_id =:id", nativeQuery = true)
  public void updateClient(@Param(value = "id") UUID client_id, @Param(value = "firstName") String first_name, @Param(value = "lastName") String last_name
  );
}
