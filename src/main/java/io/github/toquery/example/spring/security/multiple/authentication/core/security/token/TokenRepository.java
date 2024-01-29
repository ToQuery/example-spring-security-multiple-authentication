package io.github.toquery.example.spring.security.multiple.authentication.core.security.token;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class TokenRepository {

  private static final Set<Token> TOKENS = new HashSet<>();



  public void saveOrUpdate(Token token) {
    Optional<Token> tokenOptional = TOKENS.stream()
            .filter(t -> t.getToken().equals(token.getToken()))
            .findFirst();
    tokenOptional.ifPresent(TOKENS::remove);
    TOKENS.add(token);
  }

  public void saveOrUpdate(List<Token> tokens) {
    tokens.forEach(this::saveOrUpdate);
  }

  public Optional<Token> findByToken(String token) {
    return TOKENS.stream().filter(t -> t.getToken().equals(token)).findFirst();
  }

  public List<Token> findAllValidTokenByUser(String username) {
    return TOKENS.stream().filter(t -> t.getUsername().equals(username)).collect(Collectors.toList());
  }

  public Optional<Token> findByUsername(String username) {
    return TOKENS.stream().filter(t -> t.getUsername().equals(username)).findFirst();
  }
}
