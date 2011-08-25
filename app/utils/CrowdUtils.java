/**
 * 
 */
package utils;

import play.Play;

import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.ClientResourceLocator;
import com.atlassian.crowd.service.client.CrowdClient;

import exceptions.ConfigurationException;

/**
 * @author fdrouet
 */
public class CrowdUtils {
    private static final String CONF_CROWD_PROPERTY = "plcrowd.crowd.properties";

    private static volatile CrowdClient crowdClient;
    private static final Object lock = new Object();

    /**
     * Get a ready to use CrowdClient.
     * 
     * @return a CrowdClient already initialized
     * @exception ConfigurationException
     *                if we can't find the needed configuration files for crowd
     */
    public static CrowdClient getCrowdClient() {
        if (crowdClient == null) {
            synchronized (lock) {
                if (crowdClient == null) {
                    String crowdPropertiesFile = Play.configuration.getProperty(CONF_CROWD_PROPERTY);
                    if (crowdPropertiesFile == null) {
                        throw new ConfigurationException("The " + CONF_CROWD_PROPERTY + " property must by defined in your application.conf");
                    }
                    ClientResourceLocator crl = new ClientResourceLocator(crowdPropertiesFile);
                    if (crl.getProperties() == null) {
                        throw new ConfigurationException("The " + crowdPropertiesFile + " can not be found");
                    }

                    ClientProperties clientProperties = ClientPropertiesImpl.newInstanceFromResourceLocator(crl);

                    RestCrowdClientFactory restCrowdClientFactory = new RestCrowdClientFactory();
                    crowdClient = restCrowdClientFactory.newInstance(clientProperties);
                }
            }
        }
        return crowdClient;
    }

}
