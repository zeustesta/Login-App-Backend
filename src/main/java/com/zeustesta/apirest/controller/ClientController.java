package com.zeustesta.apirest.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.zeustesta.apirest.client.ClientRequest;
import com.zeustesta.apirest.client.ClientResponse;
import com.zeustesta.apirest.dto.ClientDTO;
import com.zeustesta.apirest.service.ClientService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/client")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:4200"})
public class ClientController {
  private final ClientService clientServ;

  @GetMapping(value = "{idBuscado}")
  public ResponseEntity<ClientDTO> getClient(@PathVariable UUID idBuscado) {
    ClientDTO clientDTO = clientServ.getClient(idBuscado);
    if (clientDTO == null) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(clientDTO);
  }

  @GetMapping(value = "all")
  public ResponseEntity<List<ClientDTO>> getClients() {
    List<ClientDTO> clientDTOs = clientServ.getClients();
    if (clientDTOs == null) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(clientDTOs);
  }

  @PutMapping(value =  "update")
  public ResponseEntity<ClientResponse> updateClient(@RequestBody ClientRequest clientRequest) {
    return ResponseEntity.ok(clientServ.updateClient(clientRequest));
  }
}
