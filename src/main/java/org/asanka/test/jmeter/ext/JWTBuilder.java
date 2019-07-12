package org.asanka.test.jmeter.ext;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.asanka.test.jmeter.ext.exception.JmeterJWTExtException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.text.ParseException;
import java.util.Date;

public class JWTBuilder {
    private final String jwtExtResourcesPath;
    private final Log log = LogFactory.getLog(JWTBuilder.class);
    private final PropertyMapper propertyMapper;

    public JWTBuilder(String jmeterHome) throws JmeterJWTExtException {
        this.jwtExtResourcesPath = jmeterHome;
        propertyMapper = new PropertyMapper(this.jwtExtResourcesPath);
    }

    public String getPrivateKeyJWT() throws JmeterJWTExtException {
        String issuerID = propertyMapper.getClientId();
        String subjectID = propertyMapper.getClientId();
        String audience = propertyMapper.getTokenAPIURL();
        Date expiationTime = new Date(System.currentTimeMillis() + 900000000);
        Date issueTime = new Date(System.currentTimeMillis());
        String jtiValue = Long.toString(System.currentTimeMillis());

        JWTClaimsSet jwtClaimsSet = createPrivateKeyJWTAssertionClaimSet(issuerID, subjectID, audience, expiationTime,
                issueTime, jtiValue);
        Algorithm algorithm = propertyMapper.getSignatureAlgorithm();
        return new SignJWT().getJWTSignedValue(jwtClaimsSet, algorithm, this.jwtExtResourcesPath);
    }

    public String getPrivateKeyJWT(Date expiationTime, Date issueTime, String jtiValue) throws JmeterJWTExtException {
        String issuerID = propertyMapper.getClientId();
        String subjectID = propertyMapper.getClientId();
        String audience = propertyMapper.getTokenAPIURL();

        JWTClaimsSet jwtClaimsSet = createPrivateKeyJWTAssertionClaimSet(issuerID, subjectID, audience, expiationTime,
                issueTime, jtiValue);
        Algorithm algorithm = propertyMapper.getSignatureAlgorithm();
        return new SignJWT().getJWTSignedValue(jwtClaimsSet, algorithm, this.jwtExtResourcesPath);

    }

    public String getPrivateKeyJWT(String issuerID, String subjectID, String audience, Date expiationTime, Date
            issueTime, String jtiValue) throws JmeterJWTExtException {
        JWTClaimsSet jwtClaimsSet = createPrivateKeyJWTAssertionClaimSet(issuerID, subjectID, audience, expiationTime,
                issueTime, jtiValue);
        Algorithm algorithm = propertyMapper.getSignatureAlgorithm();
        return new SignJWT().getJWTSignedValue(jwtClaimsSet, algorithm, this.jwtExtResourcesPath);

    }

    public String getCustomRequestJWT(String requestBody) throws JmeterJWTExtException {
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(requestBody);
        Algorithm algorithm = propertyMapper.getSignatureAlgorithm();
        return new SignJWT().getJWTSignedValue(jwtClaimsSet, algorithm, this.jwtExtResourcesPath);

    }

    public String getAccountOpenBankOrgUKRequestJWT(String accountInitiationId) throws JmeterJWTExtException {
        String scope = "accounts OB_ACCOUNT_CONSENT:" + accountInitiationId + " openid";
        return getOpenBankOrgUKRequestJWT(accountInitiationId, scope);

    }

    public String getPaymentOpenBankOrgUKRequestJWT(String paymentInitiationId) throws JmeterJWTExtException {
        String scope = "payments OB_PAYMENT_CONSENT:" + paymentInitiationId + " openid";
        return getOpenBankOrgUKRequestJWT(paymentInitiationId, scope);

    }

    private String getOpenBankOrgUKRequestJWT(String initiationId, String scope) throws JmeterJWTExtException {
        org.json.JSONObject jsonObject = new org.json.JSONObject(MessageFormats.OB_ORG_UK_REQUEST_OBJECT_BODY);
        jsonObject.put("scope", scope);
        jsonObject.getJSONObject("claims").getJSONObject("userinfo").getJSONObject("openbanking_intent_id").
                put("value", initiationId);
        jsonObject.getJSONObject("claims").getJSONObject("id_token").getJSONObject("openbanking_intent_id").
                put("value", initiationId);

        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(jsonObject.toString());
        Algorithm algorithm = propertyMapper.getSignatureAlgorithm();
        return new SignJWT().getJWTSignedValue(jwtClaimsSet, algorithm, this.jwtExtResourcesPath);

    }

    private JWTClaimsSet createPrivateKeyJWTAssertionClaimSet(String issuerID, String subjectID, String audience, Date
            expiationTime, Date issueTime, String jtiValue) {
        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
        claimsSet.issuer(issuerID);
        claimsSet.subject(subjectID);
        claimsSet.audience(audience);
        claimsSet.jwtID(jtiValue);
        claimsSet.expirationTime(expiationTime);
        claimsSet.issueTime(issueTime);
        return claimsSet.build();
    }

    private JWTClaimsSet createJWTClaimSet(String jsonObject) {
        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = JWTClaimsSet.parse(jsonObject);
        } catch (ParseException e) {
            log.error("Occurred Parser exception with passed JSON object");
        }
        return claimsSet;
    }
}


