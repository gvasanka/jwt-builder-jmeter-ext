package org.asanka.test.jmeter.ext;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.asanka.test.jmeter.ext.exception.JmeterJWTExtException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.Properties;

public class PropertyMapper {
    private final String jwtExtResourcesPath;
    private final Properties properties = new Properties();
    private final Log log = LogFactory.getLog(PropertyMapper.class);
    private String clientId;
    private String tokenAPIURL;
    private char[] keyStorePassword;
    private String keyStoreDomainName;
    private String keyStoreName;
    private Algorithm signatureAlgorithm;


    public PropertyMapper(String jwtExtResourcesPath) throws JmeterJWTExtException {

        String propertiesPath = null;
        if (jwtExtResourcesPath != null) {
            this.jwtExtResourcesPath = jwtExtResourcesPath;
            propertiesPath = Paths.get(this.jwtExtResourcesPath, "jwtbuilder.properties")
                    .toAbsolutePath().toString();
        } else {
            log.error("Provided path location is not valid");
            throw new JmeterJWTExtException("Provided path location is not valid");
        }

        try (InputStream input = new FileInputStream(propertiesPath)) {
            properties.load(input);
            clientId = properties.getProperty(JmeterExtConstants.CLIENTID);
            tokenAPIURL = properties.getProperty(JmeterExtConstants.TOKENAPIURL);
            keyStorePassword = properties.getProperty(JmeterExtConstants.KEYSTOREPASSWORD).toCharArray();
            keyStoreDomainName = properties.getProperty(JmeterExtConstants.KEYSTOREDOMAINNAME);
            keyStoreName = properties.getProperty(JmeterExtConstants.KEYSTORENAME);

            String algorithm = properties.getProperty(JmeterExtConstants.ALGORITHM);

            if (JWSAlgorithm.RS256.getName().equalsIgnoreCase(algorithm)) {
                signatureAlgorithm = JWSAlgorithm.RS256;
            } else if ("RS384".equalsIgnoreCase(algorithm)) {
                signatureAlgorithm = JWSAlgorithm.RS384;
            } else if ("RS512".equalsIgnoreCase(algorithm)) {
                signatureAlgorithm = JWSAlgorithm.RS512;
            } else {
                log.error("Provided signature algorithm on properties file is not supported");
                throw new JmeterJWTExtException("Provided signature algorithm " + algorithm + " is not supported ");
            }
        } catch (IOException e) {
            log.error("Error reading properties file" , e);
            throw new JmeterJWTExtException("Error reading properties file", e);
        }
    }

    public String getClientId() {
        return clientId;
    }

    public String getTokenAPIURL() {
        return tokenAPIURL;
    }


    char[] getKeyStorePassword() {
        return keyStorePassword;
    }

    String getKeyStoreDomainName() {
        return keyStoreDomainName;
    }

    public String getKeyStoreName() {
        return keyStoreName;
    }

    public Algorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }


}
