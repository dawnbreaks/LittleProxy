package org.littleshoot.proxy;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;

import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

/**
 * Tests a single proxy that requires username/password authentication.
 */
public class UsernamePasswordAuthenticatingProxyTest extends BaseProxyTest
        implements ProxyAuthenticator {
    @Override
    protected void setUp() {
        this.proxyServer = bootstrapProxy()
                .withPort(proxyServerPort)
                .withProxyAuthenticator(this)
                .start();
    }

    @Override
    protected String getUsername() {
        return "user1";
    }

    @Override
    protected String getPassword() {
        return "user2";
    }

    @Override
    public boolean authenticate(HttpRequest request) {
    	List<String> values = request.headers().getAll(HttpHeaders.Names.PROXY_AUTHORIZATION);
		String fullValue = values.iterator().next();
		if(fullValue.startsWith("Basic")){
			String value = StringUtils.substringAfter(fullValue, "Basic ").trim();
			byte[] decodedValue = Base64.decodeBase64(value);
			String decodedString = new String(decodedValue);
			String userName = StringUtils.substringBefore(decodedString,":");
			String password = StringUtils.substringAfter(decodedString, ":");
			return getUsername().equals(userName) && getPassword().equals(password);
		}
        return false;
    }

    @Override
    protected boolean isAuthenticating() {
        return true;
    }
}
