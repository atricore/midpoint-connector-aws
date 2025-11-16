package com.atricore.iam.midpoint.connector.aws;

import com.evolveum.polygon.common.GuardedStringAccessor;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import org.identityconnectors.framework.spi.StatefulConfiguration;
import software.amazon.awssdk.regions.Region;

public class AWSConfiguration extends AbstractConfiguration implements StatefulConfiguration {

    private static final Log logger = Log.getLog(AWSConfiguration.class);

    private String awsAccessKeyId;
    private GuardedString awsSecretAccessKey;
    private String awsRegion = Region.US_EAST_1.id(); // Default region if not specified

    /**
     * caching
     */
    private Long maxCacheTTL = 300000L;
    private Long ignoreCacheAfterUpdateTTL = 5000L;
    private Boolean allowCache;
    private String endpointOverride;

    @ConfigurationProperty(order = 1, displayMessageKey = "awsAccessKeyId.display",
            groupMessageKey = "basic.group", helpMessageKey = "awsAccessKeyId.help", required = true,
            confidential = false)
    public String getAwsAccessKeyId() {
        return awsAccessKeyId;
    }

    public void setAwsAccessKeyId(String awsAccessKeyId) {
        this.awsAccessKeyId = awsAccessKeyId;
    }

    @ConfigurationProperty(order = 2, displayMessageKey = "awsSecretAccessKey.display",
            groupMessageKey = "basic.group", helpMessageKey = "awsSecretAccessKey.help", required = true,
            confidential = true)
    public GuardedString getAwsSecretAccessKey() {
        return awsSecretAccessKey;
    }

    public void setAwsSecretAccessKey(GuardedString awsSecretAccessKey) {
        this.awsSecretAccessKey = awsSecretAccessKey;
    }

    @ConfigurationProperty(order = 3, displayMessageKey = "awsRegion.display",
            groupMessageKey = "basic.group", helpMessageKey = "awsRegion.help", required = false, // Optional, defaults are handled
            confidential = false)
    public String getAwsRegion() {
        return awsRegion;
    }

    public void setAwsRegion(String awsRegion) {
        this.awsRegion = awsRegion;
    }

    @ConfigurationProperty(order = 10, displayMessageKey = "allowCache.display",
            groupMessageKey = "basic.group", helpMessageKey = "allowCache.help", required = true,
            confidential = false)
    public Boolean getAllowCache() {
        return allowCache;
    }

    public void setAllowCache(Boolean allowCache) {
        this.allowCache = allowCache;
    }

    @ConfigurationProperty(order = 11, displayMessageKey = "maxCacheTTL.display",
            groupMessageKey = "basic.group", helpMessageKey = "maxCacheTTL.help", required = true,
            confidential = false)
    public Long getMaxCacheTTL() {
        return maxCacheTTL;
    }

    public void setMaxCacheTTL(Long maxCacheTTL) {
        this.maxCacheTTL = maxCacheTTL;
    }

    @ConfigurationProperty(order = 12, displayMessageKey = "getIgnoreCacheAfterUpdateTTL.display",
            groupMessageKey = "basic.group", helpMessageKey = "getIgnoreCacheAfterUpdateTTL.help", required = true,
            confidential = false)
    public Long getIgnoreCacheAfterUpdateTTL() {
        return ignoreCacheAfterUpdateTTL;
    }


    public void setIgnoreCacheAfterUpdateTTL(Long l) {
        this.ignoreCacheAfterUpdateTTL = l;
    }

    @ConfigurationProperty(order = 13, displayMessageKey = "endpointOverride.display",
            groupMessageKey = "basic.group", helpMessageKey = "endpointOverride.help", required = false,
            confidential = false)
    public String getEndpointOverride() {
        return endpointOverride;
    }

    public void setEndpointOverride(String e) {
        this.endpointOverride = e;
    }

    public void validate() {
        logger.ok("Validating configuration...");
        if (StringUtil.isBlank(awsAccessKeyId)) {
            throw new IllegalArgumentException("AWS Access Key ID cannot be null or empty.");
        }
        if (awsSecretAccessKey == null) {
            throw new IllegalArgumentException("AWS Secret Access Key cannot be null.");
        }
        // Check if secret key is empty
        GuardedStringAccessor accessor = new GuardedStringAccessor();
        awsSecretAccessKey.access(accessor);
        if (StringUtil.isBlank(accessor.getClearString())) {
            throw new IllegalArgumentException("AWS Secret Access Key cannot be empty.");
        }

        // Optional: Validate region if provided
        if (StringUtil.isNotBlank(awsRegion)) {
            try {
                Region.of(awsRegion);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid AWS Region specified: " + awsRegion);
            }
        }
        logger.ok("Configuration validated successfully.");
    }

    @Override
    public void release() {

    }


}
