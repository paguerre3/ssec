package org.sec;

import io.jsonwebtoken.Jwts;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;
import org.springframework.util.Assert;

public class JwtSecretMakerTest {
    @Test
    public void createSecretKey() {
        var key = Jwts.SIG.HS512.key().build();
        // Converter available for test package only:
        String secret = DatatypeConverter.printHexBinary(key.getEncoded());
        Assert.notNull(secret, "secret shouldn't be null");
        System.out.printf("\nKey=[%s]\n", secret);
    }
}
