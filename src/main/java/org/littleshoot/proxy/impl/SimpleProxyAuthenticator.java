package org.littleshoot.proxy.impl;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;

import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.littleshoot.proxy.ProxyAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleProxyAuthenticator implements ProxyAuthenticator {

	private static final Logger LOG = LoggerFactory.getLogger(SimpleProxyAuthenticator.class);
	
	@Override
	public boolean authenticate(HttpRequest request) {
		try{
			List<String> values = request.headers().getAll(HttpHeaders.Names.PROXY_AUTHORIZATION);
			String fullValue = values.iterator().next();
			if(fullValue.startsWith("Basic")){
				String value = StringUtils.substringAfter(fullValue, "Basic ").trim();
				byte[] decodedValue = Base64.decodeBase64(value);
				String decodedString = new String(decodedValue, "UTF-8");
				String userName = StringUtils.substringBefore(decodedString,":");
				String password = StringUtils.substringAfter(decodedString, ":");
				if(userName.equals("lubin") && password.equals("lubin")){
					return true;
				}
			}else{
				return HttpDigestAuthUtil.authenticate(request);
			}
		}catch(Exception e){
			LOG.error("SimpleProxyAuthenticator|authenticate failed.", e);
		}
		return false;
	}


}
