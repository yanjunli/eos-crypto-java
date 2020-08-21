package com.cmcc.eosdemo.jwt.utils;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class JwtTool {
    
    private static final String ISSUER = "issuer";
    private static final int EXPIRATION = 30 * 60 * 1000;
    private static final String HASH_CODE = "hashcode";
    
    /**
     * generate jws using key
     * */
    public static String generateToken(Key key, String subject, String hashcode) {
        String issuer = ISSUER;
        Date expiration = new Date(System.currentTimeMillis()+EXPIRATION);
        String jws = Jwts.builder()
                .setHeaderParam("type", "JWT")
                .setIssuer(issuer)
                .setSubject(subject)
                .setExpiration(expiration)
                .claim(HASH_CODE, hashcode)
                .signWith(key)
                .compact();
        return jws;
    }
    
    /**
     * verify jws using key, true valid, false invalid
     * */
    public static boolean verifyToken(String jws, Key key) {
        try {
            Jwts.parser().setSigningKey(key).requireIssuer(ISSUER).parseClaimsJws(jws);
            return true;
        } catch (Exception e) {
            System.err.println("jws verity token faild, due to " + e.getMessage());
            return false;
        }
    }
    
    public static String getClaim(String name, String jws, Key key) {
        try {
            return Jwts.parser().setSigningKey(key).requireIssuer(ISSUER).parseClaimsJws(jws).getBody().get(name, String.class);
        } catch(ExpiredJwtException e) {
            return e.getClaims().get(name, String.class);
        }
    }
    
    public static String getAccount(String jws, Key key) {
        try {
            return Jwts.parser().setSigningKey(key).requireIssuer(ISSUER).parseClaimsJws(jws).getBody().getSubject();
        } catch(ExpiredJwtException e) {
            return e.getClaims().getSubject();
        }
    }

    public static String copy(Key key, String jws) {
        String subject = getAccount(jws,key);
        String hashcode = getClaim(HASH_CODE,jws,key);
        return generateToken(key,subject,hashcode);
    }

    public static boolean needRefresh(Key key, String jws) {
        try {
            Jwts.parser().setSigningKey(key).requireIssuer(ISSUER).parseClaimsJws(jws);
        } catch (ExpiredJwtException e) {
            Instant needRefreshTime = e.getClaims().getExpiration().toInstant().plus(30, ChronoUnit.MINUTES);
            Instant now = Instant.now();
            if(now.isBefore(needRefreshTime)) {
                return true;
            }
        }
        return false;
    }
}
