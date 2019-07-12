package org.asanka.test.jmeter.ext;

public final class MessageFormats {

    public static final String OB_ORG_UK_REQUEST_OBJECT_BODY = "{\n" +
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


}
