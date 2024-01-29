package io.github.toquery.example.spring.security.multiple.authentication.core.security.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenJwtService {

    private final String secretKey = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private final long jwtExpiration = 1000 * 60 * 60 * 24 * 7;
    private final long refreshExpiration = 1000 * 60 * 60 * 24 * 7;

    public String generateToken(String username) {
        return buildToken(username, jwtExpiration);
    }

    public String generateRefreshToken(String username) {
        return buildToken(username, refreshExpiration);
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public boolean isTokenValid(String token, String username) {
        String usernameJWT = extractAllClaims(token).getSubject();
        return (usernameJWT.equals(username)) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpirationTime().before(new Date());
    }


    @SneakyThrows
    private String buildToken(String username, long expiration) {
        JWSSigner signer = new MACSigner(secretKey);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + expiration))
                .build();

        // 创建 JWT 并签名
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);

        return signedJWT.serialize();

    }

    @SneakyThrows
    private JWTClaimsSet extractAllClaims(String token) {
        SignedJWT signedJWT = SignedJWT.parse(token);

        // 验证 JWT
        JWSVerifier verifier = new MACVerifier(secretKey);
        if (!signedJWT.verify(verifier)) {
            throw new Exception("Token cannot be trusted");
        }

        return signedJWT.getJWTClaimsSet();
    }


}
