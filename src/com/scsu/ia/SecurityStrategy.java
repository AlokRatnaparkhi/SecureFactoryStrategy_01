package com.scsu.ia;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface SecurityStrategy {

	
	abstract void IsVulnerabilityPresent(HttpServletRequest request, HttpServletResponse response);
	
	
	
	
}
