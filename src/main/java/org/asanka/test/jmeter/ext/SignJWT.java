package org.asanka.test.jmeter.ext;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.asanka.test.jmeter.ext.exception.JmeterJWTExtException;

public class SignJWT {

    public String getJWTSignedValue(JWTClaimsSet jwtClaimsSet, Algorithm signatureAlgorithm, String jmeterHome) throws JmeterJWTExtException {
        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm)) {
            return new SignJWTWithRSA(jmeterHome).getJWTValue(jwtClaimsSet);
        } else if (JWSAlgorithm.HS256.equals(signatureAlgorithm) || JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            throw new JmeterJWTExtException("Given signature algorithm " + signatureAlgorithm + " is not supported ");
        } else if (JWSAlgorithm.ES256.equals(signatureAlgorithm) || JWSAlgorithm.ES384.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES512.equals(signatureAlgorithm)) {
            throw new JmeterJWTExtException("Given signature algorithm " + signatureAlgorithm + " is not supported ");
        } else {
            throw new JmeterJWTExtException("Given signature algorithm " + signatureAlgorithm + " is not supported ");
        }
    }
}
