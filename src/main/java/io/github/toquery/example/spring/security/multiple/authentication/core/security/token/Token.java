package io.github.toquery.example.spring.security.multiple.authentication.core.security.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Token {

  public String username;

  public String token;

  public boolean revoked;

  public boolean expired;
}
