package org.asanka.test.jmeter.ext;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.asanka.test.jmeter.ext.exception.JmeterJWTExtException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;

public class

SignJWTWithRSA {
    private Certificate certificate = null;
    private final String jwtExtResourcesPath;
    private PropertyMapper propertyMapper;
    private final Log log = LogFactory.getLog(JWTBuilder.class);

    protected SignJWTWithRSA(String jwtExtResourcesPath) throws JmeterJWTExtException {
        this.jwtExtResourcesPath = jwtExtResourcesPath;
        propertyMapper = new PropertyMapper(this.jwtExtResourcesPath);
    }


    protected String getJWTValue(JWTClaimsSet jwtClaimsSet) throws JmeterJWTExtException {
        try {
            char[] keyStorePassword = propertyMapper.getKeyStorePassword();
            String keyStoreDomainName = propertyMapper.getKeyStoreDomainName();
            String keyStoreName = propertyMapper.getKeyStoreName();

            Key privateKey = getPrivateKey(keyStorePassword, keyStoreDomainName, keyStoreName);

            JWSSigner signer = null;
            if (privateKey instanceof RSAPrivateKey) {
                signer = new RSASSASigner((RSAPrivateKey) privateKey);

                JWSHeader jwsHeader = null;
                Algorithm algorithm = propertyMapper.getSignatureAlgorithm();
                if (algorithm instanceof JWSAlgorithm) {
                    jwsHeader = new JWSHeader.Builder(
                            (JWSAlgorithm) algorithm).keyID(getThumbPrint()).build();


                    SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
                    signedJWT.sign(signer);
                    String key = signedJWT.serialize();

                    if (log.isDebugEnabled()) {
                        log.debug("Signed JWT key: " + key);
                    }
                    return key;
                }
            }
        } catch (JOSEException e) {
            log.error("Error occurred at Key Signing", e);
            throw new JmeterJWTExtException("Error occurred at Key Signing", e);
        }
        return null;
    }

    private String getThumbPrint() throws JmeterJWTExtException {
        Certificate certificate = this.certificate;

        MessageDigest digestValue;
        try {
            digestValue = MessageDigest.getInstance("SHA-256");
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();

            String publicCertThumbprint = hexify(digestInBytes);
            if (log.isDebugEnabled()) {
                log.debug("Thumb print is: " + publicCertThumbprint);
            }
            return publicCertThumbprint;
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            log.error("Error in ThumbPrint", e);
            throw new JmeterJWTExtException("Error in ThumbPrint", e);
        }
    }

    private Key getPrivateKey(char[] keyStorePassword, String keyStoreDomainName, String keyStoreName) throws JmeterJWTExtException {
        String keyStorePath = Paths.get(this.jwtExtResourcesPath, keyStoreName).toAbsolutePath()
                .toString();

        try (InputStream fis = new FileInputStream(keyStorePath)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore.PrivateKeyEntry pkEntry;

            ks.load(fis, keyStorePassword);
            pkEntry = (KeyStore.PrivateKeyEntry) ks.
                    getEntry(keyStoreDomainName, new KeyStore.PasswordProtection(keyStorePassword));


            if (pkEntry != null) {
                certificate = pkEntry.getCertificate();
                return pkEntry.getPrivateKey();
            } else {
                throw new JmeterJWTExtException("Getting PrivateKey from the keystore failed.");
            }


        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | CertificateException e) {
            log.error("Error while reading private key file" , e);
            throw new JmeterJWTExtException("Error while reading private key file", e);
        }

    }

    private static String hexify(byte[] bytes) {
        if (bytes == null) {
            String errorMsg = "Invalid byte array: 'NULL'";
            throw new IllegalArgumentException(errorMsg);
        } else {
            char[] hexDigits = new char[]{'0', '1', '2', '3', '4', '5', '6',
                    '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            StringBuilder buf = new StringBuilder(bytes.length * 2);

            for (byte aByte : bytes) {
                buf.append(hexDigits[(aByte & 240) >> 4]);
                buf.append(hexDigits[aByte & 15]);
            }
            return buf.toString();
        }
    }

}
