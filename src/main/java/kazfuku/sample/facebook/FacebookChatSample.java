package kazfuku.sample.facebook;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;

import org.jivesoftware.smack.Chat;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.sasl.SASLMechanism;

public class FacebookChatSample
{
    public static void main( String[] args )
    {
        String accessToken = "AAACjg0Eh1N8BAFuhUFZAN0EteV6pjZAsZAI46i8oV3iVmyLdaKiwaBcM5DPFjbEZAq9LZAZAA0qXsvaXkKB7SqnhubzlUAK7tmr3UYLaeQgaXSJ6EZCKn2G";
        String consumerKey = "179784128779487";
        long targetFacebookId = 100003231787457L;
        String message = "MESSAGE";

        XMPPConnection connection = createXMPPConnection();
        try
        {
            connection.connect();
            connection.login( consumerKey, accessToken );

            String to = String.format( "-%d@chat.facebook.com",
                    Long.valueOf( targetFacebookId ) );
            Chat chat = connection.getChatManager().createChat( to, null );
            chat.sendMessage( message );
        }
        catch( XMPPException e )
        {
            throw new RuntimeException( e );
        }
        finally
        {
            connection.disconnect();
        }
    }

    private static synchronized XMPPConnection createXMPPConnection()
    {
        SASLAuthentication.registerSASLMechanism(
                SASLXFacebookPlatformMechanism.NAME,
                SASLXFacebookPlatformMechanism.class );
        SASLAuthentication.supportSASLMechanism(
                SASLXFacebookPlatformMechanism.NAME, 0 );

        ConnectionConfiguration configuration = new ConnectionConfiguration(
                "chat.facebook.com", 5222 );
        configuration.setSASLAuthenticationEnabled( true );

        return new XMPPConnection( configuration );
    }

    public static class SASLXFacebookPlatformMechanism extends SASLMechanism
    {
        public static final String NAME = "X-FACEBOOK-PLATFORM";

        public SASLXFacebookPlatformMechanism(
                SASLAuthentication saslAuthentication )
        {
            super( saslAuthentication );
        }

        private String apiKey = "";

        private String accessToken = "";

        @Override
        protected void authenticate() throws IOException, XMPPException
        {
            AuthMechanism stanza = new AuthMechanism( getName(), null );
            getSASLAuthentication().send( stanza );
        }

        @SuppressWarnings( "hiding" )
        @Override
        public void authenticate( String apiKey, String host, String accessToken )
                throws IOException, XMPPException
        {
            if( apiKey == null || accessToken == null )
            {
                throw new IllegalStateException( "Invalid parameters!" );
            }

            this.apiKey = apiKey;
            this.accessToken = accessToken;
            this.hostname = host;

            String[] mechanisms = { "DIGEST-MD5" };
            Map<String, String> props = new HashMap<String, String>();
            this.sc = Sasl.createSaslClient( mechanisms, null, "xmpp", host,
                    props, this );
            authenticate();
        }

        @Override
        public void authenticate( String username, String host,
                CallbackHandler cbh ) throws IOException, XMPPException
        {
            String[] mechanisms = { "DIGEST-MD5" };
            Map<String, String> props = new HashMap<String, String>();
            this.sc = Sasl.createSaslClient( mechanisms, null, "xmpp", host,
                    props, cbh );
            authenticate();
        }

        @Override
        protected String getName()
        {
            return NAME;
        }

        @Override
        public void challengeReceived( String challenge ) throws IOException
        {
            byte response[] = null;
            if( challenge != null )
            {
                String decodedResponse = new String(
                        org.jivesoftware.smack.util.Base64.decode( challenge ) );
                Map<String, String> parameters = getQueryMap( decodedResponse );

                String version = "1.0";
                String nonce = parameters.get( "nonce" );
                String method = parameters.get( "method" );

                Long callId = Long.valueOf( System.currentTimeMillis() );

                String composedResponse = String
                        .format(
                                "method=%s&nonce=%s&access_token=%s&api_key=%s&call_id=%s&v=%s",
                                URLEncoder.encode( method, "UTF-8" ),
                                URLEncoder.encode( nonce, "UTF-8" ),
                                URLEncoder.encode( this.accessToken, "UTF-8" ),
                                URLEncoder.encode( this.apiKey, "UTF-8" ),
                                callId, URLEncoder.encode( version, "UTF-8" ) );
                response = composedResponse.getBytes();
            }

            String authenticationText = "";

            if( response != null )
            {
                authenticationText = org.jivesoftware.smack.util.Base64
                        .encodeBytes(
                                response,
                                org.jivesoftware.smack.util.Base64.DONT_BREAK_LINES );
            }

            Response stanza = new Response( authenticationText );

            getSASLAuthentication().send( stanza );
        }

        private Map<String, String> getQueryMap( String query )
        {
            String[] params = query.split( "&" );
            Map<String, String> map = new HashMap<String, String>();
            for( String param : params )
            {
                String name = param.split( "=" )[0];
                String value = param.split( "=" )[1];
                map.put( name, value );
            }
            return map;
        }
    }
}
