package com.zeustesta.apirest.service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.zeustesta.apirest.client.ClientRequest;
import com.zeustesta.apirest.client.ClientResponse;
import com.zeustesta.apirest.dto.ClientDTO;
import com.zeustesta.apirest.entity.Client;
import com.zeustesta.apirest.entity.Role;
import com.zeustesta.apirest.repository.ClientRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ClientService {
  private final ClientRepository clientRep;

  public ClientDTO getClient(UUID clientId) {
    Client client = clientRep.findById(clientId).orElse(null);

    if (client != null) {
      ClientDTO clientDTO = ClientDTO.builder()
        .userId(clientId)
        .firstName(client.getFirstName())
        .lastName(client.getLastName())
        .email(client.getEmail())
        .build();

      return clientDTO;
    }
    return null;
  }

  public List<ClientDTO> getClients() {
    List<Client> clients = clientRep.findAll();
    List<ClientDTO> clientDTOs = new ArrayList<>();

    for (Client client: clients) {
      ClientDTO clientDTO = ClientDTO.builder()
      .userId(client.getUserId())
      .email(client.getEmail())
      .firstName(client.getFirstName())
      .lastName(client.getLastName())
      .build();

      clientDTOs.add(clientDTO);
    }

    return clientDTOs;
  }

  @Transactional
  public ClientResponse updateClient(ClientRequest clientRequest) {
    Client client = Client.builder()
      .userId(clientRequest.getUserId())
      .email(clientRequest.getEmail())
      .firstName(clientRequest.getFirstName())
      .lastName(clientRequest.getLastName())
      .role(Role.USER)
      .build();
    
    clientRep.updateClient(client.getUserId(), client.getFirstName(), client.getLastName());

    return new ClientResponse("Usuario actualizado correctamente");
  }
}
