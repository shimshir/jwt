package jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {
  public static void main(String... args) throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");

    RSAPrivateKey privateKey = generatePrivateKey(readResourceAsString("/private_key.pem"), kf);
    RSAPublicKey publicKey = generatePublicKey(readResourceAsString("/public_key.pem"), kf);

    // Create and encode a JWT using the private and public key
    Algorithm encodingAlgorithm = Algorithm.RSA256(publicKey, privateKey);
    String token =
      JWT.create()
        .withClaim("coolest_actor", "Clint Eastwood")
        .sign(encodingAlgorithm);

    // Decode and read the JWT using only the public key
    Algorithm decodingAlgorithm = Algorithm.RSA256(publicKey, null);
    JWTVerifier verifier = JWT.require(decodingAlgorithm).build();
    DecodedJWT jwt = verifier.verify(token);
    System.out.println(jwt.getClaim("coolest_actor").asString());

    // Show how, by using a "forged" private key, the verification of the JWT will fail
    RSAPrivateKey forgedPrivateKey =
      generatePrivateKey(readResourceAsString("/forged_private_key.pem"), kf);

    Algorithm forgedEncodingAlgorithm = Algorithm.RSA256(publicKey, forgedPrivateKey);
    String forgedToken =
      JWT.create()
        .withClaim("coolest_actor", "Alec Baldwin")
        .sign(forgedEncodingAlgorithm);

    try {
      String stillReadableClaim = JWT.decode(forgedToken).getClaim("coolest_actor").asString();
      System.out.println(stillReadableClaim);
      // throws an exception
      verifier.verify(forgedToken);
    } catch (Exception e) {
      System.out.println(
        "if this code gets called then an exception was rightfully thrown due to the private key being incorrect"
      );
    }
  }

  /* This function would be unnecessary as the keys could be stored in vault and provided to the application
     via an environment variable */
  private static String readResourceAsString(String resourcePath) throws Exception {
    return
      new String(
        Files.readAllBytes(
          Paths.get(
            Main.class.getResource(resourcePath).toURI()
          )
        )
      );
  }

  private static RSAPrivateKey generatePrivateKey(String keyContent, KeyFactory kf) throws Exception {
    String trimmedContent =
      keyContent
        .replaceAll("\\n", "")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "");
    PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(trimmedContent));
    return (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);
  }

  private static RSAPublicKey generatePublicKey(String keyContent, KeyFactory kf) throws Exception {
    String trimmedContent =
      keyContent
        .replaceAll("\\n", "")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "");
    X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(trimmedContent));
    return (RSAPublicKey) kf.generatePublic(keySpecX509);
  }
}
