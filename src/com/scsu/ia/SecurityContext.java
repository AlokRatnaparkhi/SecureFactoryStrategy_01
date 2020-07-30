package com.scsu.ia;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class SecurityContext {
	
	private SecurityStrategy strategy;
	
	public SecurityContext(SecurityStrategy strategy)
	{
		this.strategy=strategy;
	
		
	}
	public void executeSecurityStrategy(HttpServletRequest request, HttpServletResponse response)
	{
		strategy.IsVulnerabilityPresent(request,response);
	}

}
