package com.security;

import com.security.SQLi;
import com.security.SecurityType;
import com.security.XSS;

public class ConcreteSecureStrategyFactory implements AbstractSecureStrategyFactory{

	

	@Override
	public SecurityStrategy getSQLiStrategy() {
		
		return new SQLi();
	}

	@Override
	public SecurityStrategy getXSSStrategy() {
		
		return new XSS();
	}
	
	
	
	
}
