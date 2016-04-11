package vault5431.twilio;

/**
 * Created by cyj on 4/7/16.
 */

import com.twilio.sdk.resource.instance.lookups.PhoneNumber;
import com.twilio.sdk.LookupsClient;
import com.twilio.sdk.TwilioRestClient;
import com.twilio.sdk.TwilioRestException;
import com.twilio.sdk.resource.factory.MessageFactory;
import com.twilio.sdk.resource.instance.Message;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

public class MessageSender {
    /* Find your sid and token at twilio.com/user/account */
    private static final String ACCOUNT_SID = "AC0fde3a15c4eb806040031e5994a6f987";
    private static final String AUTH_TOKEN = "a8113b81179e3832fc3b780590a29b4e";

    public static Integer sendAuthMessage(String toNum, String msg) {
        TwilioRestClient client = new TwilioRestClient(ACCOUNT_SID, AUTH_TOKEN);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("To", toNum));
        params.add(new BasicNameValuePair("From", "+14848689228"));
        params.add(new BasicNameValuePair("Body", msg));

        MessageFactory msgFactory = client.getAccount().getMessageFactory();
        Message sms = null;
        try {
            sms = msgFactory.create(params);
        } catch (TwilioRestException t) {
            System.out.println("Error creating message: " + t.getErrorMessage());
            System.out.println("Additional Info: " + t.getMoreInfo());
            return 0;
        }

        return sms.getErrorCode();
    }

}
