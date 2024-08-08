package ch.cyberduck.core.auth;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Frame;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.Callable;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jets3t.service.security.ProviderCredentials;
import org.json.JSONObject;

import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSSessionCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;

import ch.cyberduck.core.Credentials;
import ch.cyberduck.core.CredentialsConfigurator;
import ch.cyberduck.core.Host;
import ch.cyberduck.core.LoginOptions;
import ch.cyberduck.core.TemporaryAccessTokens;
import ch.cyberduck.core.exception.LoginCanceledException;



public class AWSCredentialsConfigurator implements CredentialsConfigurator {
    private static final Logger log = LogManager.getLogger(AWSCredentialsConfigurator.class);

    private final AWSCredentialsProvider[] providers;

    // added static variable for base url
    private static String baseDomain;
   // added credentials for OIDC configuration
    private static  String clientId = "recallng";
    private static  String clientSecret = null;
    private static final List<String> scopes = Arrays.asList("openid", "offline_access", "profile", "email");
    private static final String redirectUri = "urn:ietf:wg:oauth:2.0:oob";
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    private static final NetHttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static String environmentName;
    private static String configFilePath = System.getenv("APPDATA") + "/oidc_config.txt";

  

    public AWSCredentialsConfigurator(final AWSCredentialsProvider... providers) {
        this.providers = providers;
    }

    @Override
    public Credentials configure(final Host host) {

        try {
            Credentials credentials = null;
            // read offline token directory from file
            String offlineTokenPath = readOfflineTokendirectory();
           
            if (offlineTokenPath == null || offlineTokenPath.isEmpty()) {
                log.info("using OIDC flow to get s3 credentials");
                credentials = fetchS3CredentialsWithOIDC(host);
            } else {
                log.info("using offline token flow to get s3 credentials");
                credentials = fetchS3CredentialsWithOfflineToken(host);
            }
            
            if (credentials != null) {
                return credentials;
            } else {
                return new Credentials(host.getCredentials());
            }
        } catch (Exception e) {
            log.error("Error fetching S3 credentials: " + e.getMessage());
        }

        log.info("starting configure s3");

        if(!host.getCredentials().validate(host.getProtocol(), new LoginOptions(host.getProtocol()).password(false))) {
            final Credentials credentials = new Credentials(host.getCredentials());
            // Lookup from default profile if no access key is set in bookmark
            for(AWSCredentialsProvider provider : providers) {
                try {
                    final AWSCredentials c = provider.getCredentials();
                    if(log.isDebugEnabled()) {
                        log.debug(String.format("S3 Configure %s with %s", host, c));
                    }

                    credentials.setUsername(c.getAWSAccessKeyId());
                    credentials.setPassword(c.getAWSSecretKey());
                    if(c instanceof AWSSessionCredentials) {
                        credentials.setToken(((AWSSessionCredentials) c).getSessionToken());
                        log.debug("Set session token: {}", ((AWSSessionCredentials) c).getSessionToken());
                    }
                    break;
                }
                catch(SdkClientException e) {
                    log.debug(String.format("Ignore failure loading credentials from provider %s", provider));

                    // Continue searching with next provider
                }
            }
            log.info("Returning configured credentials: {}", credentials);
            return credentials;
        }
        log.info("Using credentials from host configuration");
        return CredentialsConfigurator.DISABLED.configure(host);
    }

    // read offline token directory from appdata file
    public static String readOfflineTokendirectory() throws IOException {
        String configFilePath = System.getenv("APPDATA") + "/offline_token_config.txt";
        
        // check if the file exists
        if (!Files.exists(Paths.get(configFilePath))) {
            log.info("Configuration file does not exist: " + configFilePath);
            return null;
        }

        String path = new String(Files.readAllBytes(Paths.get(configFilePath))).trim();

        // If the file is empty, path will be an empty string
        if (path.isEmpty()) {
            log.info("Configuration file is empty: " + configFilePath);
            return null; 
        }

        String formattedDirectoryPath = path.replace("\\", "\\\\");
        log.info("formatted offline token directory:" + formattedDirectoryPath);
        return formattedDirectoryPath;
    }

    // read offline token content form csv file
    public String readTokenfromCsv(String filePath) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            return br.readLine().split(",")[1];
        }
    }

   // add deleting offline token path file
   public void deleteOfflineTokenFile(String filePath) {
        try {
            Files.deleteIfExists(Paths.get(filePath));
            log.info("offline token file deleted:" + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // add deleting downloaded offline token file
    private static void deleteOfflineTokenConfigFile() {
        try {
            String configFilePath = System.getenv("APPDATA") + "/offline_token_config.txt";
            Files.deleteIfExists(Paths.get(configFilePath));
            log.info("Offline token config file deleted.");
        } catch (IOException e) {
            log.error("Failed to delete offline token config file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /*
     *  decode from downloaded offline token and  extract base url
     *  only for particular url, may need to modify.
     */

    // decode offline token to get base url
    public static void decodeToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length == 3) {
            String header = new String(Base64.getUrlDecoder().decode(parts[0]));
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            JSONObject headerJson = new JSONObject(header);
            JSONObject payloadJson = new JSONObject(payload);

            String aud = payloadJson.getString("iss");
            log.info("aud:" + aud);

            // extract base url
            baseDomain = extractDomainSegment(aud);

        } else {
            log.error("Invalid JWT token");
        }
    }

    // method to extract base url
    public static String extractDomainSegment(String url) {
        // Assuming the index starts from 19 and ends at 60
        if (url.length() >= 60) {
            return url.substring(19, 63);
        } else {
            log.debug("URL length is shorter than expected. Cannot extract domain segment.");
            return "";
        }
    }
    /*
     * 
     */

    // adding get s3 credentials method
    public String getAccessToken(String refreshToken) throws Exception {
        String accessTokenURL = "https://dssecurity." + baseDomain + "/auth/realms/DecisionSpace_Integration_Server/protocol/openid-connect/token";
    
        URL url = new URL(accessTokenURL);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); //enalble output stream
        connection.setDoOutput(true);

        String requestBody = "grant_type=refresh_token" +
                             "&refresh_token=" + URLEncoder.encode(refreshToken, "UTF-8") + 
                             "&client_id=enterprise-search"; 
                    
        
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = requestBody.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
                // process the response
            try (Scanner scanner = new Scanner(connection.getInputStream(), "UTF-8")) {
                String responseBody = scanner.useDelimiter("\\A").next();

                JSONObject jsonResponse = new JSONObject(responseBody);

                return jsonResponse.getString("access_token");

            }
        } else {
                //handle error message
            try (Scanner scanner = new Scanner(connection.getErrorStream(), "UTF-8")) {
                String errorBody = scanner.useDelimiter("\\A").next();
                throw new Exception("Error: " + responseCode + ", Response: " + errorBody);
            }
        }

    }

    // added read environment name from the file
    public String readEnvirmentNamefromConfigFile(String filePath) throws IOException {
    try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
        String line = br.readLine();
        if (line != null && line.contains("=")) {
            return line.split("=")[1].trim();
        }
    }
    return null; 
    } 

    public Credentials getS3Token(String accessToken, String S3CredentialsURL) throws Exception {
        log.info("Getting S3 token with access token: {}", accessToken);
    
        URL url = new URL(S3CredentialsURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + accessToken);

        int responseCode = connection.getResponseCode();
        log.debug("Response code: {}", responseCode);

        // System.out.println("responseCode:" + responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) {
                // process the response
                try (Scanner scanner = new Scanner(connection.getInputStream(), "UTF-8")) {
                    String responseBody = scanner.useDelimiter("\\A").next();

                    JSONObject jsonResponse = new JSONObject(responseBody);

                    // extract nested JSON string
                    String tokenJsonString = jsonResponse.getJSONObject("response").getString("token");

                    // parse nested JSON string
                    JSONObject tokenJson = new JSONObject(tokenJsonString);
                    JSONObject credentials = tokenJson.getJSONObject("Credentials");

                    String accessKeyId = credentials.getString("AccessKeyId");
                    String secretAccessKey = credentials.getString("SecretAccessKey");
                    String sessionToken = credentials.getString("SessionToken");
                    
                    log.info("S3 credentials obtained successfully");
                    return new Credentials(accessKeyId, secretAccessKey, sessionToken);

                }
        } else {
                //handle error message
            try (Scanner scanner = new Scanner(connection.getErrorStream(), "UTF-8")) {
                String errorBody = scanner.useDelimiter("\\A").next();
                log.error("Error obtaining S3 token: {}", errorBody);
                throw new Exception("Error: " + responseCode + ", Response: " + errorBody);
            }
        }

    }

    /**
     * modify to the OAuth flow
     */
    // get authorization code
    public String getAuthorizationCode(String authorizationUrl, String tokenUrl, String clientId, String clientSecret, List<String> scopes, boolean pkce, String codeChallenge) throws IOException, URISyntaxException {
         // Build the authorization code flow
        AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
            BearerToken.authorizationHeaderAccessMethod(),
            HTTP_TRANSPORT, JSON_FACTORY,
            new GenericUrl(tokenUrl),
            new ClientParametersAuthentication(clientId, clientSecret),
            clientId, authorizationUrl);

        if (pkce) {
            flowBuilder.enablePKCE();
        }

        flowBuilder.setScopes(scopes);
        flowBuilder.setDataStoreFactory(new MemoryDataStoreFactory());
        AuthorizationCodeFlow flow = flowBuilder.build();

         // Generate the authorization URL
        AuthorizationCodeRequestUrl authorizationUrlBuilder = flow.newAuthorizationUrl();
        String redirectUri = "urn:ietf:wg:oauth:2.0:oob";
        authorizationUrlBuilder.setRedirectUri(redirectUri);
        authorizationUrlBuilder.set("code_challenge", codeChallenge);
        authorizationUrlBuilder.set("code_challenge_method", "S256");

        String authUrl = authorizationUrlBuilder.build();
    
         // Open the authorization URL in the default browser
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().browse(new URI(authUrl));
        } else {
            log.info("Please manually open the URL in your browser.");
        }

        // create a prompt window to allow user to paste authorization code into it
        final String[] code = {null};
        SwingUtilities.invokeLater(() -> {
            JDialog dialog = new JDialog((Frame) null, "Authorization Code", true);
            dialog.setAlwaysOnTop(true);
            dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
            dialog.setSize(400, 200);
            dialog.setLayout(new BorderLayout());

            JLabel label = new JLabel("Enter the authorization code:", SwingConstants.CENTER);
            JTextField textField = new JTextField();
            JButton submitButton = new JButton("Submit");

            submitButton.addActionListener(e -> {
                code[0] = textField.getText();
                dialog.dispose();
            });

            dialog.add(label, BorderLayout.NORTH);
            dialog.add(textField, BorderLayout.CENTER);
            dialog.add(submitButton, BorderLayout.SOUTH);

            dialog.setVisible(true);
        });

        // Wait for user input
        while (code[0] == null) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                throw new IOException("Interrupted while waiting for authorization code", e);
            }
        }

        if (code[0].isEmpty()) {
            throw new IOException("Authorization code is required");
        }
        
        return code[0];
        
    }

    // exchange for accesstoken
    public static String exchangeAuthorizationCodeForTokens(String authorizationCode, String codeVerifier, String tokenUrl, String clientId, String clientSecret) throws IOException {
        DataStoreFactory dataStoreFactory = new MemoryDataStoreFactory();

        AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
                BearerToken.authorizationHeaderAccessMethod(),
                HTTP_TRANSPORT,
                JSON_FACTORY,
                new GenericUrl(tokenUrl),
                new ClientParametersAuthentication(clientId, clientSecret),
                clientId,
                tokenUrl)
                .setScopes(scopes)
                .setDataStoreFactory(dataStoreFactory)
                .build();

        AuthorizationCodeTokenRequest tokenRequest = flow.newTokenRequest(authorizationCode);
        tokenRequest.setRedirectUri(redirectUri);
        tokenRequest.set("code_verifier", codeVerifier);

        return tokenRequest.execute().getAccessToken();

    }

    // create pke
    public static String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    public static String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        byte[] bytes = codeVerifier.getBytes();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    //added fetch s3 credentials function with OIDC flow
    private Credentials fetchS3CredentialsWithOIDC(Host host) throws Exception {
        log.info("start calling get credentials method");
        
        environmentName = readEnvirmentNamefromConfigFile(configFilePath);
        log.info("environment name:" + environmentName);
    

        boolean pkce = true;
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        // OIDC flow url addresses
        String authorizationUrl = "https://dssecurity.distteam." + environmentName + ".landmarksoftware.io/auth/realms/DecisionSpace_Integration_Server/protocol/openid-connect/auth";
        String tokenUrl = "https://dssecurity.distteam." + environmentName + ".landmarksoftware.io/auth/realms/DecisionSpace_Integration_Server/protocol/openid-connect/token";
        String s3EP = "https://bhdm-server.distteam." + environmentName + ".landmarksoftware.io/BHDM/v1/FileUtilities/SasToken?SessionName=test";

        String authorizationCode = getAuthorizationCode(authorizationUrl, tokenUrl, clientId, clientSecret, scopes, pkce, codeChallenge);
        String accessToken = exchangeAuthorizationCodeForTokens(authorizationCode, codeVerifier, tokenUrl, clientId, clientSecret);
        ;
        int maxRetries = 3;
        int delay = 2000;

        Credentials s3Credentials = retry(() -> getS3Token(accessToken, s3EP), maxRetries, delay);
        log.info("modified flow s3 credentials:" + s3Credentials);


        if (s3Credentials != null) {
            log.info("starting store credentials to the host object");

            host.getCredentials().setUsername(s3Credentials.getUsername());
            host.getCredentials().setPassword(s3Credentials.getPassword());
            host.getCredentials().setToken(s3Credentials.getToken());

            log.info("S3 credentials successfully fetched and set to Host object.");

            // write credentials to .aws/credentials file
            log.info("start to write the credentials to the .aws/credentials.");
            writeCredentialsToFile(host.getCredentials().getUsername(), host.getCredentials().getPassword(), host.getCredentials().getToken());
            log.info("successfully write the credentials to the .aws/credentials.");

            // return the credentials with tokens
            Credentials credentials = new Credentials()
                                            .withTokens(new TemporaryAccessTokens(
                                                s3Credentials.getUsername(),
                                                s3Credentials.getPassword(),
                                                s3Credentials.getToken(),
                                                -1L))
                                            .withUsername(s3Credentials.getUsername())
                                            .withPassword(s3Credentials.getPassword());

            return credentials;
            

        } else {
            log.error("Failed to fetch S3 credentials after multiple attempts.");
            return null;
        }
    }

      //added fetch s3 credentials function with offline token flow
      private Credentials fetchS3CredentialsWithOfflineToken(Host host) throws Exception {
        log.info("start calling get credentials method");
        
        Credentials s3Credentials = null;
        String offlineTokenPath = readOfflineTokendirectory();

        // Map<String, String> config = readS3EPConfigureation();
        // String s3EP = config.get("S3EPURL");
        String s3EP = "https://bhdm-server.distteam." + environmentName + ".landmarksoftware.io/BHDM/v1/FileUtilities/SasToken?SessionName=test";

        try {
            String offlineToken = readTokenfromCsv(offlineTokenPath);
            decodeToken(offlineToken);
    
            String accessToken = getAccessToken(offlineToken);
    
            int maxRetries = 3;
            int delay = 2000;
    
            s3Credentials = retry(() -> getS3Token(accessToken, s3EP), maxRetries, delay); 
        } catch (Exception e) {
            log.error("Failed to fetch S3 credentials: " + e.getMessage());
            e.printStackTrace();
        } finally {
            log.info("Attempting to delete offline token file...");
            deleteOfflineTokenConfigFile();
            log.info("Offline token file deleted.");
        }

        if (s3Credentials != null) {
            log.info("starting store credentials to the host object");

            host.getCredentials().setUsername(s3Credentials.getUsername());
            host.getCredentials().setPassword(s3Credentials.getPassword());
            host.getCredentials().setToken(s3Credentials.getToken());
      
            log.info("accessKeyId: " + host.getCredentials().getUsername());
            log.info("secretAccessKey: " + host.getCredentials().getPassword());
            log.info("sessionToken: " + host.getCredentials().getToken());
            log.info("S3 credentials successfully fetched and set to Host object.");

            // write credentials to .aws/credentials file
            log.info("start to write the credentials to the .aws/credentials.");
            writeCredentialsToFile(host.getCredentials().getUsername(), host.getCredentials().getPassword(), host.getCredentials().getToken());
            log.info("successfully write the credentials to the .aws/credentials.");

            // return the credentials with tokens
            Credentials credentials = new Credentials()
                                            .withTokens(new TemporaryAccessTokens(
                                                s3Credentials.getUsername(),
                                                s3Credentials.getPassword(),
                                                s3Credentials.getToken(),
                                                -1L))
                                            .withUsername(s3Credentials.getUsername())
                                            .withPassword(s3Credentials.getPassword());
           
            return credentials;
            

        } else {
            log.error("Failed to fetch S3 credentials after multiple attempts.");
            return null;
        }
    }
   

    // added retry method in case of failling calling api
     private Credentials retry(Callable<Credentials> callable, int maxRetries, int delay) throws Exception {
        int attempts = 0;
        while (attempts < maxRetries) {
            try {
                return callable.call();
            } catch (Exception e) {
                attempts++;
                if (attempts < maxRetries) {
                    Thread.sleep(delay);
                } else {
                    throw e;
                }
            }
        }
        return null;
     }

    // added write credentials to .aws/credentials file
    public void writeCredentialsToFile(String accessKeyId, String secretAccessKey, String sessionToken) {
        String credentialsFilePath = System.getProperty("user.home") + "/.aws/credentials";
        String profileName = "default";

        String credentialsContent = String.format(
            "[%s]%naws_access_key_id = %s%naws_secret_access_key = %s%naws_session_token = %s%n",
            profileName, accessKeyId, secretAccessKey, sessionToken
        );

        try {
            // Ensure the .aws directory exists
            Files.createDirectories(Paths.get(System.getProperty("user.home"), ".aws"));

            // Write the credentials to the file
            FileWriter writer = new FileWriter(credentialsFilePath);
            writer.write(credentialsContent);
            writer.close();

            System.out.println("Credentials written to " + credentialsFilePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public CredentialsConfigurator reload() throws LoginCanceledException {
        if(log.isDebugEnabled()) {
            log.debug(String.format("Reload from %s", Arrays.toString(providers)));
        }
        for(AWSCredentialsProvider provider : providers) {
            provider.refresh();
        }
        return this;
    }

    public static AWSCredentialsProvider toAWSCredentialsProvider(final ProviderCredentials credentials) {
        return credentials instanceof org.jets3t.service.security.AWSSessionCredentials ?
            new AWSSessionCredentialsProvider() {
                @Override
                public AWSSessionCredentials getCredentials() {
                    return new AWSSessionCredentials() {
                        @Override
                        public String getSessionToken() {
                            return ((org.jets3t.service.security.AWSSessionCredentials) credentials).getSessionToken();
                        }

                        @Override
                        public String getAWSAccessKeyId() {
                            return credentials.getAccessKey();
                        }

                        @Override
                        public String getAWSSecretKey() {
                            return credentials.getSecretKey();
                        }
                    };
                }

                @Override
                public void refresh() {
                    // Not supported
                }
            } :
            new AWSStaticCredentialsProvider(new AWSCredentials() {
                @Override
                public String getAWSAccessKeyId() {
                    return credentials.getAccessKey();
                }

                @Override
                public String getAWSSecretKey() {
                    return credentials.getSecretKey();
                }
            });
    }
}
