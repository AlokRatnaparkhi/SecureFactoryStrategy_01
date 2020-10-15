package com.scsu.ia;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
 
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.security.AbstractSecureStrategyFactory;
import com.security.ConcreteSecureStrategyFactory;
import com.security.SQLi;
import com.security.SecurityContext;
import com.security.SecurityStrategy;
import com.security.SecurityType;
import com.security.XSS;

/**
 * @purpose UserInformation Servlet is in charge of communicate with Client side
 * @author Darren
 */
public class UserInformation extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public UserInformation() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request,response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String userId = request.getParameter("userName");
		String userPass = request.getParameter("userPass");
		String protection = request.getParameter("protection");
		 
		SecurityContext context;
		AbstractSecureStrategyFactory factory=new ConcreteSecureStrategyFactory();
		
		List<SecurityStrategy> strategy=new ArrayList<>(); 
		
		strategy.add(factory.getSQLiStrategy());
		strategy.add(factory.getXSSStrategy());
		
		for(SecurityStrategy s:strategy) { 
			context=new SecurityContext(s);
		  	context.executeSecurityStrategy(request, response);
		  
		  }
			
		PrintWriter out = response.getWriter();
        response.setContentType("text/html");
        response.setHeader("Cache-control", "no-cache, no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "-1");
 
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        response.setHeader("Access-Control-Max-Age", "86400");
 
        JsonObject myObj = null;
        if("without".equals(protection)){
        	myObj = new DBManager().getInfo(userId,userPass);
        }else{
        	myObj = new DBManager().getInfoProtection(userId,userPass);
        }
        System.out.println(myObj.toString());
        out.println(myObj.toString());
        System.out.println("end of the Servlet!");
        out.close();
	}

	
}
