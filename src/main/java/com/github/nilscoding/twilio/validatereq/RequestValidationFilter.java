package com.github.nilscoding.twilio.validatereq;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Simple Filter implementation to validate a request from Twilio<br>
 * Currently works only with POST requests!<br>
 * Required init parameter: authToken - your primary auth token<br>
 * Optional init parameters: removeUrlPart - string part which will be removed from url (useful when behind proxy)
 * @author NilsCoding
 */
public class RequestValidationFilter implements Filter {

    protected FilterConfig filterConfig;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest)request;
        // enforcing UTF-8 encoding for parameter handling
        // note: if this is not the first filter which accesses the parameters, then the first filter needs to set this, too
        httpReq.setCharacterEncoding("UTF-8");
        HttpServletResponse httpResp = (HttpServletResponse)response;
        
        // your auth token, see your Twilio account settings
        String authToken = this.filterConfig.getInitParameter("authToken");
        // optional: this string will be removed from the URL
        String removeUrlPart = this.filterConfig.getInitParameter("removeUrlPart");
        
        // auth token is required, so deny access if not specified
        if ((authToken == null) || (authToken.isEmpty() == true)) {
            this.denyAccess(httpReq, httpResp, chain);
            return;
        }
        
        StringBuilder urlBuffer = new StringBuilder();
        // full request url
        String reqUrl = httpReq.getRequestURL().toString();
        if ((removeUrlPart != null) && (removeUrlPart.isEmpty() == false)) {
            // optionally remove url part
            reqUrl = reqUrl.replace(removeUrlPart, "");
        }
        urlBuffer.append(reqUrl);
        String queryString = httpReq.getQueryString();
        Map<String, List<String>> queryStringMap;
        if (queryString != null) {
            urlBuffer.append('?').append(queryString);
            queryStringMap = Utils.splitQueryString(queryString);
        } else {
            queryStringMap = new HashMap<>();
        }
        // all parameter names
        List<String> paramNames = Utils.getAsList(httpReq.getParameterNames());
        // remove those names that are part of the query string
        paramNames.removeAll(queryStringMap.keySet());
        
        // convert parameters to simple map
        Map<String, String> data = new HashMap<>();
        if (paramNames.isEmpty() == false) {
            for (String oneParamName : paramNames) {
                String oneParamValue = httpReq.getParameter(oneParamName);
                data.put(oneParamName, oneParamValue);
            }
        }
        
        // get Twilio signature header value
        String headerHash = httpReq.getHeader("X-Twilio-Signature");
        
        // validate request data
        TwilioRequestValidator validator = new TwilioRequestValidator(authToken);
        boolean signatureValid = validator.isRequestValid(urlBuffer.toString(), data, headerHash);
        
        if (signatureValid == false) {
            this.denyAccess(httpReq, httpResp, chain);
            return;
        }
        
        chain.doFilter(request, response);
    }
    
    /**
     * Method to be invoked when request is not signed properly<br>
     * Default implementation sends 403 error but derived classes might do something different
     * @param httpReq   http servlet request
     * @param httpResp  http servlet response
     * @param chain     filter chain
     * @throws java.io.IOException  I/O Exception
     */
    protected void denyAccess(HttpServletRequest httpReq, HttpServletResponse httpResp, FilterChain chain) throws IOException {
        httpResp.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    @Override
    public void destroy() {
    }
    
}
