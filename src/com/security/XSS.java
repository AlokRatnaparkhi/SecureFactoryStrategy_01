package com.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.scsu.ia.SecurityStrategy;

public class XSS implements SecurityStrategy {

	@Override
	public void IsVulnerabilityPresent(HttpServletRequest request, HttpServletResponse response) {
		//Algorithm for XSS detection
		
	boolean flag = false;
	
	
	System.out.println("**********************************************");
	System.out.println("Starting XSS detection engine.....");
	
	List<String> attr=new ArrayList<>();
			
	HttpServletRequest req = (HttpServletRequest) request;
			
	Enumeration<?> e = request.getParameterNames();
		
		while (e.hasMoreElements())
		{
		    String name = (String) e.nextElement();
		    attr.add(name);
		    //System.out.println(name);
		   
		    
		}
		
		for(String a: attr)
		{	String para=req.getParameter(a);
			
			System.out.println("Parameter:"+para);
			if(para.toLowerCase().contains("<")||para.toLowerCase().contains(">")||para.toLowerCase().contains("%")||para.toLowerCase().contains("script")||para.toLowerCase().contains("document")||para.toLowerCase().contains("/")||para.toLowerCase().contains("session")||para.toLowerCase().contains("inner")||para.toLowerCase().contains("html")||para.toLowerCase().contains("alert")||para.toLowerCase().contains("body")||para.toLowerCase().contains("session")||para.toLowerCase().contains(".")||para.toLowerCase().contains("(")||para.toLowerCase().contains(")"))
			{
				flag= true;
				
				
				
			}
						
			
		}
		
		if(flag)
		{
			System.out.println("Web Request contains possible XSS attack intention");
			try {
				request.getRequestDispatcher("/error.html").forward(request, response);
			} catch (ServletException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		else
		{	System.out.println("Request is secure from XSS");
			
			System.out.println("**********************************************");
		}
		
		
	}

	
	
	
	
}
