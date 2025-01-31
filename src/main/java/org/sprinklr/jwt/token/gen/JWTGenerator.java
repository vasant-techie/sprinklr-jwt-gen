package org.sprinklr.jwt.token.gen;

import java.io.DataInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class JWTGenerator {

    private String signJWTToken() {
        String header = "{\"alg\":\"RS256\"}";
        String claimTemplate = "{\"iss\": \"{0}\", \"sub\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\"}";

        StringBuilder token = new StringBuilder();

        try {
            // Encode the JWT Header
            token.append(Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(header.getBytes(StandardCharsets.UTF_8)));

            // Separate with a period (.)
            token.append(".");

            // Create the JWT Claims Object
            String[] claimArray = new String[4];
            claimArray[0] = "3MWG90XtyEMC03gNpPjzqkeKZxmnaG1xV40hH9AKL_rSK-BoSVPGZHQuK7vjzRg5uQqGn75NL7yfkQcy7";
            claimArray[1] = "JWT_SUB";
            claimArray[2] = "JWT_AUD";
            claimArray[3] = Long.toString(System.currentTimeMillis() / 1000 + EXP_DURATION);

            Formatter claims = new Formatter();
            String payload = claims.format(claimTemplate, (Object[]) claimArray).toString();

            // Add the encoded claims object
            token.append(Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(payload.getBytes(StandardCharsets.UTF_8)));

            // Load the private key
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("encryption/private.der");
            DataInputStream dis = new DataInputStream(inputStream);
            byte[] keyBytes = new byte[dis.available()];
            dis.readFully(keyBytes);
            dis.close();

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(spec);

            // Sign the JWT Header + Claims Object
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(token.toString().getBytes(StandardCharsets.UTF_8));

            String signedPayload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signature.sign());

            // Separate with a period
            token.append(".");
            // Add the encoded signature
            token.append(signedPayload);

        } catch (Exception e) {
            System.err.println("Error while creating JWT token: " + e.getMessage());
        }

        return token.toString();
    }

    private static final int EXP_DURATION = 3600; // Expiration time in seconds (1 hour)

    public static void main(String[] args) {
        JWTGenerator generator = new JWTGenerator();
        String jwtToken = generator.signJWTToken();
        System.out.println("Generated JWT Token: " + jwtToken);
    }
}