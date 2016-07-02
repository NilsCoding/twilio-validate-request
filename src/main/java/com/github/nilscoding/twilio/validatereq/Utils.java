package com.github.nilscoding.twilio.validatereq;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * Some utility methods
 * @author NilsCoding
 */
public class Utils {
    
    private Utils() { }
    
    /**
     * Parses a query string into its parts, adapted from
     * http://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
     *
     * @param queryString query string
     * @return parsed query string
     */
    public static Map<String, List<String>> splitQueryString(String queryString) {
        final Map<String, List<String>> queryPairs = new LinkedHashMap<>();
        if ((queryString == null) || (queryString.isEmpty())) {
            return queryPairs;
        }
        final String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            try {
                final int idx = pair.indexOf("=");
                final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
                if (!queryPairs.containsKey(key)) {
                    queryPairs.put(key, new LinkedList<String>());
                }
                final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
                queryPairs.get(key).add(value);
            } catch (UnsupportedEncodingException ex) {
            }
        }
        return queryPairs;
    }

    /**
     * Returns a list containing all entries from the given Enumeration
     * @param <T>   type of elements
     * @param en    Enumeration
     * @return  list with all entries
     */
    public static <T> List<T> getAsList(Enumeration<T> en) {
        List<T> l = new LinkedList<>();
        if (en == null) {
            return l;
        }
        while (en.hasMoreElements()) {
            l.add(en.nextElement());
        }
        return l;
    }
    
    /**
     * Converts the given data to Base64 format
     * @param data  data to encode
     * @return  encoded data
     */
    public static String encodeBase64(byte[] data) {
        if (data == null) {
            return null;
        }
        // works with Java 1.6+ 
        // thanks to http://www.adam-bien.com/roller/abien/entry/base64_encoding_with_jdk_1
        return DatatypeConverter.printBase64Binary(data);
    }
    
    /**
     * Calculates the HMAC-SHA1 of the given string using the given key, result is in Base64 format
     * @param str   string to calculate hash
     * @param key   key
     * @return  Base64 encoded HMAC-SHA1 or null on error
     */
    public static String calculateHmacSHA1inBase64(String str, String key) {
        if ((str == null) || (key == null)) {
            return null;
        }
        try {
            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);
            byte[] tmpResult = mac.doFinal(str.getBytes("UTF-8"));
            return encodeBase64(tmpResult);
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Time insensitive compare
     * @param s1    first string
     * @param s2    second string
     * @return  true if equals, false if not equal
     */
    public static boolean areEqual(String s1, String s2) {
        if ((s1 == null) && (s2 == null)) {
            return true;
        }
        if ((s1 == null) || (s2 == null)) {
            return false;
        }
        if (s1 == s2) {
            return true;
        }
        if (s1.length() != s2.length()) {
            return false;
        }
        
        boolean result = true;
        for (int i = 0; i < s1.length(); i++) {
            if (s1.charAt(i) != s2.charAt(i)) {
                result = false;
            }
        }
        
        return result;
    }
    
}
