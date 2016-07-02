package com.github.nilscoding.twilio.validatereq;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Validates request data from Twilio
 * @author NilsCoding
 */
public class TwilioRequestValidator {
    
    protected String authToken;
    
    /**
     * Creates a validator instance with your authentication token
     * @param authToken     your authenticaion token
     */
    public TwilioRequestValidator(String authToken) {
        this.authToken = authToken;
    }
    
    /**
     * Checks if the incoming data is valid according to Twilio's signing
     * @param url   complete url
     * @param data  data
     * @param expectedSignature expected signature from http request (header: X-Twilio-Signature)
     * @return  true if data is valid, false if invalid
     */
    public boolean isRequestValid(String url, Map<String, String> data, String expectedSignature) {
        if ((url == null) || (expectedSignature == null) || (url.isEmpty() == true) || (expectedSignature.isEmpty() == true)) {
            return false;
        }
        List<String> dataKeys = new ArrayList<>();
        if ((data != null) && (data.isEmpty() == false)) {
            dataKeys.addAll(data.keySet());
            Collections.sort(dataKeys);
        }
        StringBuilder buffer = new StringBuilder();
        buffer.append(url);
        if ((dataKeys.isEmpty() == false) && (data != null)) {
            for (String oneKey : dataKeys) {
                buffer.append(oneKey);
                String oneValue = data.get(oneKey);
                if (oneValue != null) {
                    buffer.append(oneValue);
                }
            }
        }
        String calculatedHash = Utils.calculateHmacSHA1inBase64(buffer.toString(), this.authToken);
        boolean isValid = Utils.areEqual(calculatedHash, expectedSignature);
        return isValid;
    }
    
}
