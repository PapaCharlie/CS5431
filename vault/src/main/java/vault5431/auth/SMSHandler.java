package vault5431.auth;

import com.twilio.sdk.TwilioRestClient;
import com.twilio.sdk.TwilioRestException;
import com.twilio.sdk.resource.factory.MessageFactory;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import vault5431.Sys;

import java.util.ArrayList;
import java.util.List;

import static vault5431.Vault.test;

/**
 * Created by papacharlie on 2016-05-08.
 */
public class SMSHandler {

    private static final String ACCOUNT_SID = "AC0fde3a15c4eb806040031e5994a6f987";
    private static final String AUTH_TOKEN = "a8113b81179e3832fc3b780590a29b4e";
    private static final String ADMIN_PHONE_NUMBER = "+16072755431";

    public static void sendSms(String to, String body) throws TwilioRestException {
        TwilioRestClient client = new TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN);
        List<NameValuePair> params = new ArrayList<>(3);
        params.add(new BasicNameValuePair("To", to));
        params.add(new BasicNameValuePair("From", ADMIN_PHONE_NUMBER));
        params.add(new BasicNameValuePair("Body", body));
        MessageFactory msgFactory = client.getAccount().getMessageFactory();
        Sys.info(String.format("Sending SMS to %s", to));
        if (!test) {
            msgFactory.create(params);
        } else {
            System.out.println(body);
        }
    }

}
