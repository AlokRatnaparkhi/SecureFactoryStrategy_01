package com.scsu.ia;

import com.security.SQLi;
import com.security.SecurityType;
import com.security.XSS;

public class SecurityFactory {

	public static SecurityStrategy getStrategy(SecurityType type)
	{	SecurityStrategy strategy=null;
		
		switch(type)
		{
			case SQLi: strategy=new SQLi();
						break;
			case XSS: 	strategy=new XSS();
						break;
		}
		
		return strategy;
		
	}
}
