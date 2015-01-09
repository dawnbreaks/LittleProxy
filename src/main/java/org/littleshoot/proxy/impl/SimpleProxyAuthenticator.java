package org.littleshoot.proxy.impl;

import org.littleshoot.proxy.ProxyAuthenticator;

public class SimpleProxyAuthenticator implements ProxyAuthenticator {
	@Override
	public boolean authenticate(String userName, String password) {
		if(userName.equals("lubin") && password.equals("lubin")){
			return true;
		}
		return false;
	}

}
