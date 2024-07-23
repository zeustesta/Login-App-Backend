package com.zeustesta.apirest.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.zeustesta.apirest.model.Client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
  public static final long JWT_EXPIRATION_TOKEN = 300000;
  public static final String SECRET_KEY = "bd976708cf429dac62c15d98502baebcbdab93b0231b22aa9acee870a6da0e27";

  public String getUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public String getToken(Client client) {
    UserDetails userDetails = client;
    return getToken(new HashMap<>(), userDetails);
  }

  public String getToken(Map<String, Object> extraClaims, UserDetails user) {
    return Jwts
      .builder()
      .setClaims(extraClaims)
      .setSubject(user.getUsername())
      .setIssuedAt(new Date(System.currentTimeMillis()))
      .setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRATION_TOKEN))
      .signWith(getKey())
      .compact();
  }

  private Key getKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts
      .parserBuilder()
      .setSigningKey(getKey())
      .build()
      .parseClaimsJws(token)
      .getBody();  
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = getUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }

  public boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }
}
