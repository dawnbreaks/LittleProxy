package org.littleshoot.proxy.impl;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.littleshoot.proxy.ProxyAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DigestProxyAuthenticator implements ProxyAuthenticator {

	private static final Logger LOG = LoggerFactory.getLogger(DigestProxyAuthenticator.class);

	private static final String authMethod = "auth";
	private static final String userName = "lubin";
	private static final String password = "lubin";
	private static final String realm = "proxy08.xiaoman.cn";

	private static String nonce = calculateNonce();
	
	@Override
    public boolean authenticate(HttpRequest request) {
    	
    	 List<String> values = request.headers().getAll(HttpHeaders.Names.PROXY_AUTHORIZATION);
         String authHeader = values.iterator().next().trim();
         
        if (authHeader.startsWith("Digest")) {
            // parse the values of the Authentication header into a hashmap
            HashMap<String, String> headerValues = parseHeader(authHeader);
            String method = request.getMethod().name();
            String ha1 = DigestUtils.md5Hex(userName + ":" + realm + ":" + password);
            String qop = headerValues.get("qop");
            String reqURI = headerValues.get("uri");
            String ha2 = DigestUtils.md5Hex(method + ":" + reqURI);

            String serverResponse;
            if (StringUtils.isBlank(qop)) {
                serverResponse = DigestUtils.md5Hex(ha1 + ":" + nonce + ":" + ha2);
            } else {
                String domain = headerValues.get("realm");
                String nonceCount = headerValues.get("nc");
                String clientNonce = headerValues.get("cnonce");
                serverResponse = DigestUtils.md5Hex(ha1 + ":" + nonce + ":" + nonceCount + ":" + clientNonce + ":" + qop + ":" + ha2);
            }
            String clientResponse = headerValues.get("response");
            if (serverResponse.equals(clientResponse)) {
                return true;
            }
        }
        return false;
    }
	@Override
	public String getAuthenticateHeader() {
        String header = "";
        header += "Digest realm=\"" + realm + "\",";
        if (!StringUtils.isBlank(authMethod)) {
            header += "qop=" + authMethod + ",";
        }
        header += "nonce=\"" + nonce + "\",";
        header += "domain=\"https://proxy08.xiaoman.cn:1443/ http://proxy08.xiaoman.cn:1443/ https://*.*:*/ http://*.*:*/ \",";
        header += "opaque=\"" + getOpaque(realm, nonce) + "\"";

        return header;
    }
	
    /**
     * Gets the Authorization header string minus the "AuthType" and returns a
     * hashMap of keys and values
     *
     * @param headerString
     * @return
     */
    private static HashMap<String, String> parseHeader(String headerString) {
        // seperte out the part of the string which tells you which Auth scheme is it
        String headerStringWithoutScheme = headerString.substring(headerString.indexOf(" ") + 1).trim();
        HashMap<String, String> values = new HashMap<String, String>();
        String keyValueArray[] = headerStringWithoutScheme.split(",");
        for (String keyval : keyValueArray) {
            if (keyval.contains("=")) {
                String key = keyval.substring(0, keyval.indexOf("="));
                String value = keyval.substring(keyval.indexOf("=") + 1);
                values.put(key.trim(), value.replaceAll("\"", "").trim());
            }
        }
        return values;
    }


    /**
     * Calculate the nonce based on current time-stamp upto the second, and a
     * random seed
     *
     * @return
     */
    public static String calculateNonce() {
        Date d = new Date();
        SimpleDateFormat f = new SimpleDateFormat("yyyy:MM:dd:hh:mm:ss");
        String fmtDate = f.format(d);
        Random rand = new Random(100000);
        Integer randomInt = rand.nextInt();
        return DigestUtils.md5Hex(fmtDate + randomInt.toString());
    }

    private static String getOpaque(String domain, String nonce) {
        return DigestUtils.md5Hex(domain + nonce);
    }

}
