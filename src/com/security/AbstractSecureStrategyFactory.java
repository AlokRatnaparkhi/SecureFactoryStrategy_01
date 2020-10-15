package com.security;

public interface AbstractSecureStrategyFactory {
	
	
	public  abstract SecurityStrategy getSQLiStrategy();
	public  abstract SecurityStrategy getXSSStrategy();

}
