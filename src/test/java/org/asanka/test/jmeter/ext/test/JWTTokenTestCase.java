package org.asanka.test.jmeter.ext.test;

import org.asanka.test.jmeter.ext.JWTBuilder;
import org.asanka.test.jmeter.ext.PropertyMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;

public class JWTTokenTestCase {
    private Path jwtExtResourcesPath;
    private PropertyMapper propertyMapper;
    private final Log log = LogFactory.getLog(JWTTokenTestCase.class);

    @BeforeClass()
    public void initTest()throws Exception {
        jwtExtResourcesPath = Paths.get(Paths.get("").toAbsolutePath().toString(), "src", "main","jwtExtResources").toAbsolutePath();
        propertyMapper = new PropertyMapper(jwtExtResourcesPath.toString());
    }


    @Test()
    public void createJWTTokenWithoutCustomData() {
        String jwtKey = null;
        try {
            jwtKey = new JWTBuilder(jwtExtResourcesPath.toString()).getPrivateKeyJWT();
        } catch (Exception e) {
            log.error("Exception Occurred" + e.getMessage(), e);
        }
        Assert.assertNotNull(jwtKey);
    }

    @Test()
    public void createJWTTokenWithCustomDates() {
        Date expiationTime = new Date(System.currentTimeMillis() + 900000000);
        Date issueTime = new Date(System.currentTimeMillis());
        String jtiValue = Long.toString(System.currentTimeMillis());
        String jwtKey = null;
        try {
            jwtKey = new JWTBuilder(jwtExtResourcesPath.toString()).getPrivateKeyJWT(expiationTime, issueTime, jtiValue);
        } catch (Exception e) {
            log.error("Exception Occurred" + e.getMessage(), e);
        }
        Assert.assertNotNull(jwtKey);
    }

    @Test()
    public void createJWTTokenWithCustomData() {
        Date expiationTime = new Date(System.currentTimeMillis() + 900000000);
        Date issueTime = new Date(System.currentTimeMillis());
        String jtiValue = Long.toString(System.currentTimeMillis());
        String issuerID = propertyMapper.getClientId();
        String subjectID = propertyMapper.getClientId();
        String audience = propertyMapper.getTokenAPIURL();
        String jwtKey = null;
        try {
            jwtKey = new JWTBuilder(jwtExtResourcesPath.toString()).getPrivateKeyJWT(issuerID, subjectID, audience, expiationTime,
                    issueTime, jtiValue);
        } catch (Exception e) {
            log.error("Exception Occurred" + e.getMessage(), e);
        }
        Assert.assertNotNull(jwtKey);
    }

    @Test()
    public void createJWTTokenWithRequestObject() {
        String REQUEST_BODY = "{\n" +
                "  \"aud\": \"https://api.alphanbank.com\",\n" +
                "  \"iss\": \"s6BhdRkqt3\",\n" +
                "  \"response_type\": \"code id_token\",\n" +
                "  \"client_id\": \"nwU59qy9AsDqftmwLcfmkvOhvuYa\",\n" +
                "  \"redirect_uri\": \"https://aaa.com/\",\n" +
                "  \"scope\": \"payments OB_PAYMENT_CONSENT:fcdd00fc-6f50-45ee-8df4-5bcc4d5ef3f0 openid\",\n" +
                "  \"state\": \"YWlzcDozMTQ21\",\n" +
                "  \"nonce\": \"n-0S6_WzA2Mj\",\n" +
                "  \"max_age\": 86400,\n" +
                "  \"claims\": {\n" +
                "    \"userinfo\": {\n" +
                "      \"openbanking_intent_id\": {\n" +
                "        \"value\": \"urn:alphabank:intent:58923\",\n" +
                "        \"essential\": true\n" +
                "      }\n" +
                "    },\n" +
                "    \"id_token\": {\n" +
                "      \"openbanking_intent_id\": {\n" +
                "        \"value\": \"fcdd00fc-6f50-45ee-8df4-5bcc4d5ef3f0\",\n" +
                "        \"essential\": true\n" +
                "      },\n" +
                "      \"acr\": {\n" +
                "        \"essential\": true,\n" +
                "        \"values\": [\n" +
                "          \"urn:openbanking:psd2:sca\",\n" +
                "          \"urn:openbanking:psd2:ca\"\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";

        String jwtKey = null;
        try {
            jwtKey = new JWTBuilder(jwtExtResourcesPath.toString()).getCustomRequestJWT(REQUEST_BODY);
        } catch (Exception e) {
            log.error("Exception Occurred" + e.getMessage(), e);
        }
        Assert.assertNotNull(jwtKey);
    }

    @Test()
    public void getAccountOpenBankOrgUKRequestJWT() {
        String accountId = "A222222";
        String jwtKey = null;
        try {
            jwtKey = new JWTBuilder(jwtExtResourcesPath.toString()).getAccountOpenBankOrgUKRequestJWT(accountId);
        } catch (Exception e) {
            log.error("Exception Occurred" + e.getMessage(), e);
        }
        Assert.assertNotNull(jwtKey);
    }

    @Test()
    public void getPaymentOpenBankOrgUKRequestJWT() {
        String paymentId = "A222222";
        String jwtKey = null;
        try {
            jwtKey = new JWTBuilder(jwtExtResourcesPath.toString()).getPaymentOpenBankOrgUKRequestJWT(paymentId);
        } catch (Exception e) {
            log.error("Exception Occurred" + e.getMessage(), e);
        }
        Assert.assertNotNull(jwtKey);
    }

}
