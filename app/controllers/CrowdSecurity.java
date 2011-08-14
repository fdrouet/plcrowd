/**
 * 
 */
package controllers;

import java.util.ArrayList;

import net.sf.oval.constraint.NotEmpty;
import play.Logger;
import play.mvc.Before;
import play.mvc.Controller;

import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.ClientResourceLocator;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * @author fdrouet
 */
public class CrowdSecurity extends Controller {
    private static final String CROWD_TOKEN = "crowd-sso-token";
    private static CrowdClient crowdClient;
    private static Object lock = new Object();

    @Before(unless = { "login", "authenticate", "logout" })
    static void checkAuthenticated() {
        synchronized (lock) {
            if (crowdClient == null) {
                ClientProperties clientProperties = ClientPropertiesImpl
                        .newInstanceFromResourceLocator(new ClientResourceLocator("crowd.properties"));
                RestCrowdClientFactory restCrowdClientFactory = new RestCrowdClientFactory();
                crowdClient = restCrowdClientFactory.newInstance(clientProperties);
            }
        }

        flash.put("url", "GET".equals(request.method) ? request.url : "/");
        if (session.contains("crowd-sso-token")) {
            try {
                crowdClient.validateSSOAuthentication(session.get(CROWD_TOKEN), new ArrayList<ValidationFactor>());
                // redirectToOriginalURL();
            } catch (OperationFailedException e) {
                flash.error("Oops. Authentication failed (%s)", e.getLocalizedMessage());
                Logger.warn(e, "An authentication failed");
                flash.keep("url");
                login();
            } catch (InvalidAuthenticationException e) {
                flash.error("Oops. Authentication failed (%s)", e.getLocalizedMessage());
                Logger.warn(e, "An authentication failed");
                flash.keep("url");
                login();
            } catch (ApplicationPermissionException e) {
                flash.error("Oops. Authentication failed (%s)", e.getLocalizedMessage());
                Logger.warn(e, "An authentication failed");
                flash.keep("url");
                login();
            } catch (InvalidTokenException e) {
                session.remove(CROWD_TOKEN);
                flash.error("Oops. Authentication has failed (expired session)");
                Logger.warn(e, "An authentication with an invalid token was attempted");
                flash.keep("url");
                login();
            }
        } else {
            login();
        }
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
            crowdClient.invalidateSSOToken(session.get(CROWD_TOKEN));
        } catch (OperationFailedException e) {
            Logger.warn(e, "SSO Token invalidation failed !");
        } catch (InvalidAuthenticationException e) {
            Logger.warn(e, "SSO Token invalidation failed !");
        } catch (ApplicationPermissionException e) {
            Logger.warn(e, "SSO Token invalidation failed !");
        }
        session.remove(CROWD_TOKEN);
        redirect("/");
    }

    public static void authenticate(@NotEmpty String login, @NotEmpty String password) {

        Logger.info("login %s", login);
        Logger.info("url 2 redirect : %s", flash.get("url"));

        UserAuthenticationContext ctx = new UserAuthenticationContext();
        ctx.setApplication("my.exoplatform.org");
        ctx.setName(login);
        ctx.setValidationFactors(new ValidationFactor[0]);
        ctx.setCredential(new PasswordCredential(password));
        try {
            String sso = crowdClient.authenticateSSOUser(ctx);
            session.put(CROWD_TOKEN, sso);
            redirectToOriginalURL();
        } catch (InactiveAccountException e) {
            flash.error("Oops. Authentication has failed (inactive account)");
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            login();
        } catch (ExpiredCredentialException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            login();
        } catch (ApplicationPermissionException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            login();
        } catch (InvalidAuthenticationException e) {
            flash.error("Oops. Authentication has failed (wrong login/password)");
            Logger.warn(e, "An authentication failed (user = %s).", login);
            login();
        } catch (OperationFailedException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            login();
        } catch (ApplicationAccessDeniedException e) {
            flash.error("Oops. Authentication has failed (%s)", e.getLocalizedMessage());
            Logger.warn(e, "An authentication with an inavctive account was attempted (user = %s).", login);
            login();
        }
    }

    static void redirectToOriginalURL() {
        String url = flash.get("url");
        if (url == null) {
            url = "/";
        }
        redirect(url);
    }
}
