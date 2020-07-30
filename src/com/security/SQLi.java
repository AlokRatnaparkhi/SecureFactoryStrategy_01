package com.security;



import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.scsu.ia.SecurityStrategy;

public class SQLi implements SecurityStrategy {

	@Override
	public void IsVulnerabilityPresent(HttpServletRequest request, HttpServletResponse response) {
		
		System.out.println("**********************************************");
		System.out.println("Starting SQLi detection engine.....");
		boolean flag = false;
		List<String> attr=new ArrayList<>();
		
		
		//Algorithm for SQLi detection
		/* For case study purpose, implementation contains trivial keyword matching however
		 * it is not reliable solution as there are ways to bypass keyword matching. 
		 * Purpose of this study is the design. In future, reliable SQLi detection algorithm should be 
		 * plugged in the design
		 */
		
		
		
		HttpServletRequest req = (HttpServletRequest) request;
		
		
		String uri=req.getQueryString()==null?req.getRequestURI().toString():req.getRequestURI().toString()+"?"+req.getQueryString().toString();
		System.out.println("URI: "+uri);
		if(uri.toLowerCase().contains("union")||uri.toLowerCase().contains("select")||uri.toLowerCase().contains("--")||uri.toLowerCase().contains("'")||uri.toLowerCase().contains("where")||uri.toLowerCase().contains("from")||uri.toLowerCase().contains("insert")||uri.toLowerCase().contains("delete")||uri.toLowerCase().contains("update")||uri.toLowerCase().contains("drop")||uri.toLowerCase().contains("truncate")||uri.toLowerCase().contains("alter")||uri.toLowerCase().contains("from")||uri.toLowerCase().contains("join"))
		{
			System.out.println("URI contains possible SQLi attack");
			try {
				request.getRequestDispatcher("/error.html").forward(request,response);
			} catch (ServletException e) {
				
				e.printStackTrace();
			} catch (IOException e) {
				
				e.printStackTrace();
			}
			
			
			
		}
		
		else
		{	
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
				if(para.toLowerCase().contains("union")||para.toLowerCase().contains("select")||para.toLowerCase().contains("  or ")||para.toLowerCase().contains("'")||para.toLowerCase().contains("where")||para.toLowerCase().contains("from")||para.toLowerCase().contains("insert")||para.toLowerCase().contains("delete")||para.toLowerCase().contains("update")||para.toLowerCase().contains("drop")||para.toLowerCase().contains("truncate")||para.toLowerCase().contains("alter")||para.toLowerCase().contains("from")||para.toLowerCase().contains("join"))
				{
					flag= true;
					
					
					
				}
							
				
			}
			
			if(flag)
			{
				System.out.println("Web Request contains possible SQLi attack intention");
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
			{	System.out.println("Request is secure. NO possible SQLI attack");
				
				System.out.println("**********************************************");
			}
			
			
		}

				
		
	}



	
	
	
	
}
