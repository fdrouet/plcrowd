/**
 * 
 */
package controllers;

import java.util.ArrayList;

import net.sf.oval.constraint.NotEmpty;
import play.Logger;
import play.mvc.Before;
import play.mvc.Controller;
import utils.CrowdUtils;
import utils.HtmlUtils;

import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.CrowdClient;

import exceptions.ConfigurationException;

/**
 * @author fdrouet
 */
public abstract class CrowdSecurity extends Controller {
    private static final String CROWD_USER_SSO_TOKEN = "crowd-sso-token";
    private static final String CROWD_USER_LOGIN = "crowd-user-login";
    private static final String CROWD_USER_DISPLAY_NAME = "crowd-user-display-name";

    @Before(unless = { "login", "authenticate", "logout", "getCrowdClient" })
    static void checkAuthenticated() {
        CrowdClient crowdClient = CrowdUtils.getCrowdClient();
        flash.put("url", "GET".equals(request.method) ? request.url : "/");
        if (session.contains("crowd-sso-token")) {
            try {
                crowdClient.validateSSOAuthentication(session.get(CROWD_USER_SSO_TOKEN), new ArrayList<ValidationFactor>());
                // redirectToOriginalURL();
            } catch (OperationFailedException e) {
                flash.error("Oops. Authentication failed (%s)", e.getLocalizedMessage());
                Logger.warn(e, "An authentication failed");
                flash.keep("url");
                cleanupSession();
                login();
            } catch (InvalidAuthenticationException e) {
                flash.error("Oops. Authentication failed (%s)", e.getLocalizedMessage());
                Logger.warn(e, "An authentication failed");
                flash.keep("url");
                cleanupSession();
                login();
            } catch (ApplicationPermissionException e) {
                // this exception raise html markup
                flash.error("<h1>Authentication has failed</h1>\n%s", HtmlUtils.extractHtmlMessageFromCrowdHtmlException(e));
                Logger.warn(e, "An authentication failed");
                flash.keep("url");
                cleanupSession();
                login();
            } catch (InvalidTokenException e) {
                session.remove(CROWD_USER_SSO_TOKEN);
                flash.error("Oops. Authentication has failed (expired session)");
                Logger.warn(e, "An authentication with an invalid token was attempted");
                flash.keep("url");
                cleanupSession();
                login();
            }
        } else {
            login();
        }
    }

    /**
     * Get a ready to use CrowdClient.
     * 
     * @return a CrowdClient already initialized
     */
    protected static CrowdClient getCrowdClient() {
        CrowdClient client = null;
        try {
            client = CrowdUtils.getCrowdClient();
        } catch (ConfigurationException e) {
            // send an HTTP ERROR 500
            error(e);
        }
        return client;
    }

    public static void login() {
        if (session.contains("crowd-sso-token")) {
            redirect("/");
        } else {
            flash.keep("url");
            render();
        }
    }

    public static void logout() {
        try {
            getCrowdClient().invalidateSSOToken(session.get(CROWD_USER_SSO_TOKEN));
        } catch (OperationFailedException e) {
            Logger.warn(e, "SSO Token invalidation failed !");
        } catch (InvalidAuthenticationException e) {
            Logger.warn(e, "SSO Token invalidation failed !");
        } catch (ApplicationPermissionException e) {
            Logger.warn(e, "SSO Token invalidation failed !");
        } finally {
            cleanupSession();
            redirect("/");
        }
    }

    public static void authenticate(@NotEmpty String login, @NotEmpty String password) {

        Logger.info("login %s", login);
        Logger.info("url 2 redirect : %s", flash.get("url"));

        CrowdClient crowdClient = getCrowdClient();
        UserAuthenticationContext ctx = new UserAuthenticationContext();
        ctx.setApplication("my.exoplatform.org");
        ctx.setName(login);
        ctx.setValidationFactors(new ValidationFactor[0]);
        ctx.setCredential(new PasswordCredential(password));
        try {
            String sso = crowdClient.authenticateSSOUser(ctx);
            User user = crowdClient.getUser(login);
            session.put(CROWD_USER_SSO_TOKEN, sso);
            session.put(CROWD_USER_DISPLAY_NAME, user.getDisplayName());
            setCurrentUserLogin(login);
            redirectToOriginalURL();
        } catch (InactiveAccountException e) {
            flash.error("Oops. Authentication has failed (inactive account)");
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            cleanupSession();
            login();
        } catch (ExpiredCredentialException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            cleanupSession();
            login();
        } catch (ApplicationPermissionException e) {
            // this exception raise html markup
            flash.error("<h1>Authentication has failed</h1>\n%s", HtmlUtils.extractHtmlMessageFromCrowdHtmlException(e));
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            cleanupSession();
            login();
        } catch (InvalidAuthenticationException e) {
            flash.error("Oops. Authentication has failed (wrong login/password)");
            Logger.warn(e, "An authentication failed (user = %s).", login);
            cleanupSession();
            login();
        } catch (OperationFailedException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            cleanupSession();
            login();
        } catch (ApplicationAccessDeniedException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            cleanupSession();
            login();
        } catch (UserNotFoundException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inexistant account was attempted (user = %s).", login);
            cleanupSession();
            login();
        }
    }

    /**
     * Get the current logged user login or null if anonymous
     * 
     * @return current user login or null
     */
    protected static String getCurrentUserLogin() {
        return session.get(CROWD_USER_LOGIN);
    }

    /**
     * Get the current logged user Display Name or null if anonymous
     * 
     * @return current user Display Name or null
     */
    protected static String getCurrentUserDisplayName() {
        return session.get(CROWD_USER_DISPLAY_NAME);
    }

    private static void setCurrentUserLogin(String userLogin) {
        session.put(CROWD_USER_LOGIN, userLogin);
    }

    private static void cleanupSession() {
        session.remove(CROWD_USER_SSO_TOKEN);
        session.remove(CROWD_USER_LOGIN);
        session.remove(CROWD_USER_DISPLAY_NAME);
    }

    static void redirectToOriginalURL() {
        String url = flash.get("url");
        if (url == null) {
            url = "/";
        }
        redirect(url);
    }

}
