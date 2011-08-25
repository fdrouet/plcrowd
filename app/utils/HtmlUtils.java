package utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.atlassian.crowd.exception.ApplicationPermissionException;

public class HtmlUtils {

    public static String extractBodyOfHtmlPage(String htmlPage) {
        String htmlBody = null;
        Pattern extractBody = Pattern.compile("<body>(.*)</body>");
        Matcher matcher = extractBody.matcher(htmlPage);
        while (matcher.find()) {
            htmlBody = matcher.group(1);
        }
        return htmlBody;
    }

    public static String extractHtmlMessageFromCrowdHtmlException(ApplicationPermissionException exception) {
        String errorMessage = HtmlUtils.extractBodyOfHtmlPage(exception.getLocalizedMessage());
        errorMessage = errorMessage.replaceAll("(<\\/?)h1>", "$1h2>");
        errorMessage = errorMessage.replaceAll("<\\/?h3>", "");
        errorMessage = errorMessage.replaceAll("<\\/?u>", "");

        return errorMessage;
    }
}
