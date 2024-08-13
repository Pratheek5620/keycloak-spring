package com.example.MediumSample.Demo.Security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    private final JwtConverterProperties properties;
    private final JwkProvider jwkProvider;

    public JwtConverter(JwtConverterProperties properties) throws Exception {
        this.properties = properties;
        this.jwkProvider = new JwkProviderBuilder(new URL("http://localhost:8080/realms/Exter-Battery-Swapping/protocol/openid-connect/certs")).build();
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        if (!verifyToken(jwt.getTokenValue())) {
            throw new JWTVerificationException("Token verification failed");
        }

        // Extract the exterClientID from the JWT token
        String exterClientID = jwt.getClaim("exterClientID");
        System.out.println("Extracted exterClientID: " + exterClientID);

        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()).collect(Collectors.toSet());

        // Returning a JwtAuthenticationToken with the extracted exterClientID as a principal claim
        return new JwtAuthenticationToken(jwt, authorities, getPrincipalClaimName(jwt));
    }

    private String getPrincipalClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (properties.getPrincipalAttribute() != null) {
            claimName = properties.getPrincipalAttribute();
        }
        return jwt.getClaim(claimName);
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        if (resourceAccess == null
                || (resource = (Map<String, Object>) resourceAccess.get(properties.getResourceId())) == null
                || (resourceRoles = (Collection<String>) resource.get("roles")) == null) {
            return Set.of();
        }
        return resourceRoles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

    public boolean verifyToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            System.out.println("Token decoded: " + decodedJWT);  // Print the decoded token information

            String keyId = decodedJWT.getKeyId();
            Jwk jwk = jwkProvider.get(keyId);

            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(properties.getIssuer())
                    .withAudience(properties.getAudience())
                    .build();

            verifier.verify(decodedJWT);
            return true;
        } catch (JWTVerificationException e) {
            System.err.println("Token verification failed: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.err.println("Error occurred during token verification: " + e.getMessage());
            return false;
        }
    }
}
