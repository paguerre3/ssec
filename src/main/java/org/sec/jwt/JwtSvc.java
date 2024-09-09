package org.sec.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class JwtSvc {
    // Secret shouldn't be injected in code under production environment, instead is recommended to place it under
    // a secured location like a secret service or storage (Obtained from JwtSecretMakerTest#createSecretKey()):
    private static final String SECRET = "0EC883F6764514CDC5C260EEC01E6BB94034430E0BC99867506EAF77FBFC511A30B7A459030673CE2391EA9973349F4298F4EE99C2DE822D157EB7E52CD112E1";
    private static final String ISSUER = "https://github.com/paguerre3";
    private static final long EXPIRATION_IN_MILLIS = TimeUnit.MINUTES.toMillis(30);

    public String generateToken(final UserDetails userDetails) {
        final var NOW = Instant.now();
        return Jwts.builder()
                // only one claim added:
                .claim("iss", ISSUER)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(NOW))
                .expiration(Date.from(NOW.plusMillis(EXPIRATION_IN_MILLIS)))
                .signWith(this.buildSecretKey())
                // convert to json format:
                .compact();
    }

    private SecretKey buildSecretKey() {
        byte[] decodedKey = Base64.getDecoder().decode(SECRET);
        return Keys.hmacShaKeyFor(decodedKey);
    }
}


