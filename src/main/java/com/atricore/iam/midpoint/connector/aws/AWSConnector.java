package com.atricore.iam.midpoint.connector.aws;

import com.atricore.iam.midpoint.connector.aws.objects.GroupHandler;
import com.atricore.iam.midpoint.connector.aws.objects.PolicyHandler;
import com.atricore.iam.midpoint.connector.aws.objects.RoleHandler;
import com.atricore.iam.midpoint.connector.aws.objects.UserHandler;
import com.evolveum.polygon.common.GuardedStringAccessor;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.*;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryMode;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.IamClientBuilder;

import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * AWS IAM Connector (not Amazon Cognito)
 */
@ConnectorClass(displayNameKey = "AWS.connector.display",
        configurationClass = AWSConfiguration.class)
public class AWSConnector implements
        Connector,
        SchemaOp,
        CreateOp,
        DeleteOp,
        SearchOp<Filter>,
        TestOp,
        UpdateDeltaOp {

    private static final Log logger = Log.getLog(AWSConnector.class);

    protected AWSConfiguration configuration;
    protected IamClient client;
    protected UserHandler userHandler;
    protected GroupHandler groupHandler;
    protected PolicyHandler policyHandler;
    protected RoleHandler roleHandler;

    private Schema schema = null;

    private Throwable initError;

    // --------------------------------------------------------------------------------
    // Connector
    // https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html
    // --------------------------------------------------------------------------------

    @Override
    public Configuration getConfiguration() {
        return this.configuration;
    }

    @Override
    public void init(Configuration cfg) {

        try {
            logger.ok("Initializing AWS Connector...");
            this.configuration = (AWSConfiguration) cfg;
            configuration.validate(); // Validate configuration first

            String accessKeyId = configuration.getAwsAccessKeyId();
            GuardedString secretAccessKey = configuration.getAwsSecretAccessKey();
            String region = configuration.getAwsRegion();

            if (secretAccessKey == null) {
                throw new ConnectorException("AWS Secret Access Key is not configured.");
            }

            // Safely extract the secret key
            GuardedStringAccessor accessor = new GuardedStringAccessor();
            secretAccessKey.access(accessor);
            String clearSecretKey = accessor.getClearString();

            if (StringUtil.isBlank(clearSecretKey)) {
                throw new ConnectorException("AWS Secret Access Key is empty.");
            }

            // Create AWS credentials
            AwsCredentials credentials = AwsBasicCredentials.create(accessKeyId, clearSecretKey);
            AwsCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(credentials);

            // Start building the IAM client
            IamClientBuilder clientBuilder = IamClient.builder()
                    .credentialsProvider(credentialsProvider);

            // Set endpoint override if provided (e.g., for LocalStack testing)
            String endpointOverride = configuration.getEndpointOverride();
            if (StringUtil.isNotBlank(endpointOverride)) {
                logger.ok("Using endpoint override: {0}", endpointOverride);
                clientBuilder.endpointOverride(new URI(endpointOverride));
            }

            logger.ok("Using specified AWS region: {0}", region);
            clientBuilder.region(Region.of(region));

            // Build and configure the AWS IAM client (use adaptive retry strategy)
            this.client = clientBuilder.overrideConfiguration(o -> o.retryStrategy(RetryMode.ADAPTIVE_V2)).build();
            logger.ok("AWS IAM client created successfully.");

            // Initialize handlers
            this.userHandler = new UserHandler(client, configuration);
            this.groupHandler = new GroupHandler(client, configuration);
            this.policyHandler = new PolicyHandler(client, configuration);
            this.roleHandler = new RoleHandler(client, configuration);

        } catch (IllegalArgumentException e) {
            logger.error(e, "Configuration validation failed: {0}", e.getMessage());
            initError = e; // Store init error
            throw ConnectorException.wrap(e);
        } catch (software.amazon.awssdk.core.exception.SdkClientException e) {
            logger.error(e, "AWS SDK client exception during initialization: {0}", e.getMessage());
            initError = e; // Store init error
            throw new ConnectorException("Failed to initialize AWS SDK client: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Failed to initialize AWS IAM client: {0}", e.getMessage());
            initError = e; // Store init error
            throw ConnectorException.wrap(e);
        }
    }


    @Override
    public void dispose() {
        logger.info("Disposing AWS Connector resources...");
        // Close the IAM client if it's initialized
        if (this.client != null) {
            try {
                // Clean closing of the client
                this.client.close();
                logger.ok("Successfully closed AWS IAM client.");
            } catch (Exception e) {
                logger.warn(e, "Exception while closing AWS IAM client: {0}", e.getMessage());
            } finally {
                this.client = null;
            }
        }

        // Clear references
        this.configuration = null;
        this.userHandler = null;
        this.groupHandler = null;
        this.policyHandler = null;
        this.roleHandler = null;
        this.schema = null;
        this.initError = null;

        logger.ok("AWS Connector resources disposed.");
    }

    // --------------------------------------------------------------------------------
    // Schema Op
    @Override
    public Schema schema() {
        if (null == schema) {
            // Use the schema builder from AWSSchema to construct the schema
            schema = AWSSchema.getSchema(configuration);
        }
        return schema;
    }

    // --------------------------------------------------------------------------------
    // Test Op
    @Override
    public void test() {
        logger.info("Testing connection to AWS IAM...");

        if (client == null) {
            logger.error("AWS IAM client is not initialized.");
            // Attempt re-initialization or throw specific error
            if (initError != null) {
                throw new ConnectorException("Connector initialization failed previously: " + initError.getMessage(), initError);
            }
            throw new ConnectorException("AWS IAM client is not initialized.");
        }

        try {
            // Perform a simple read operation to verify credentials and connectivity
            // Using GetAccountSummary is a lightweight operation for testing connection
            client.getAccountSummary();
            logger.ok("Successfully connected to AWS IAM and verified credentials.");

        } catch (software.amazon.awssdk.services.iam.model.IamException e) {
            logger.error(e, "IAM service exception during connection test: {0}", e.getMessage());
            throw new ConnectorException("IAM service exception during connection test: " + e.getMessage(), e);
        } catch (software.amazon.awssdk.core.exception.SdkClientException e) {
            logger.error(e, "AWS SDK client exception during connection test: {0}", e.getMessage());
            throw new ConnectorException("AWS SDK client exception during connection test: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Unexpected exception during connection test: {0}", e.getMessage());
            throw ConnectorException.wrap(e); // Wrap unexpected exceptions
        }
    }

    // --------------------------------------------------------------------------------
    // SearchOp

    @Override
    public FilterTranslator<Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return new FilterTranslator<Filter>() {
            public List<Filter> translate(Filter filter) {
                return CollectionUtil.newList(filter);
            }
        };
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Filter query, final ResultsHandler handler,
                             OperationOptions options) {

        logger.ok("executeQuery called for ObjectClass: {0}, Filter: {1}, Options: {2}",
                objectClass, query, options);

        if (client == null) {
            throw new ConnectorException("AWS client is not initialized. Cannot execute query.");
        }

        if (objectClass == null) {
            throw new InvalidAttributeValueException("ObjectClass cannot be null");
        }

        // Handle User (ACCOUNT), Group, and Policy searches
        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            userHandler.searchUsers(handler, query, options);
        }
        else if (ObjectClass.GROUP.equals(objectClass)) {
            groupHandler.searchGroups(handler, query, options);
        }
        else if (AWSSchema.POLICY_OBJECT_CLASS.equals(objectClass)) {
            policyHandler.searchPolicies(handler, query, options);
        }
        else if (AWSSchema.ROLE_OBJECT_CLASS.equals(objectClass)) {
            roleHandler.searchRoles(handler, query, options);
        }
        else {
            logger.warn("Unsupported object class for search: {0}", objectClass);
            throw new UnsupportedOperationException("Search operation is not supported for ObjectClass: " + objectClass.getObjectClassValue());
        }
    }


    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        logger.ok("delete called for ObjectClass: {0}, Uid: {1}, Options: {2}",
                objectClass, uid, options);

        if (client == null) {
            throw new ConnectorException("AWS client is not initialized. Cannot execute delete.");
        }

        if (objectClass == null) {
            throw new InvalidAttributeValueException("ObjectClass cannot be null");
        }

        // Delegate to the appropriate handler based on ObjectClass
        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            if (userHandler == null) {
                throw new ConnectorException("UserHandler is not initialized.");
            }
            userHandler.deleteUser(objectClass, uid, options);
        }
        else if (ObjectClass.GROUP.equals(objectClass)) {
            if (groupHandler == null) {
                throw new ConnectorException("GroupHandler is not initialized.");
            }
            groupHandler.deleteGroup(objectClass, uid, options);
        }
        else if (AWSSchema.POLICY_OBJECT_CLASS.equals(objectClass)) {
            logger.warn("Delete operation is not supported for Policy objects as they are read-only");
            throw new UnsupportedOperationException("Delete operation is not supported for Policy objects as they are read-only");
        }
        else {
            logger.warn("Unsupported object class for delete: {0}", objectClass);
            throw new UnsupportedOperationException("Delete operation is not supported for ObjectClass: " + objectClass.getObjectClassValue());
        }
    }

    @Override
    public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        logger.ok("updateDelta called for ObjectClass: {0}, Uid: {1}, Modifications: {2}, Options: {3}",
                objectClass, uid, modifications, options);

        if (client == null) {
            throw new ConnectorException("AWS client is not initialized. Cannot execute updateDelta.");
        }

        if (objectClass == null) {
            throw new InvalidAttributeValueException("ObjectClass cannot be null");
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            if (userHandler == null) {
                throw new ConnectorException("UserHandler is not configured.");
            }
            // Delegate to UserHandler
            return userHandler.updateUserDelta(uid, modifications, options);
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            if (groupHandler == null) {
                throw new ConnectorException("GroupHandler is not configured.");
            }
            return groupHandler.updateDeltaGroup(uid, modifications, options);
        } else if (AWSSchema.ROLE_OBJECT_CLASS.equals(objectClass)) {
            if (roleHandler == null) {
                throw new ConnectorException("RoleHandler is not configured.");
            }
            throw new UnsupportedOperationException("UpdateDelta operation is not supported for AWSRole objects as they are read-only.");
        } else if (AWSSchema.POLICY_OBJECT_CLASS.equals(objectClass)) {
            logger.warn("UpdateDelta operation is not supported for Policy objects as they are read-only.");
            throw new UnsupportedOperationException("UpdateDelta operation is not supported for AWSPolicy objects as they are read-only.");
        } else {
            logger.warn("Unsupported object class for updateDelta: {0}", objectClass);
            throw new UnsupportedOperationException("UpdateDelta operation is not supported for ObjectClass: " + objectClass.getObjectClassValue());
        }
    }


    // ----------------------------------------------------------------------


    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
        logger.ok("create called for ObjectClass: {0}, Attributes: {1}, Options: {2}",
                objectClass, createAttributes, options);

        if (client == null) {
            throw new ConnectorException("AWS client is not initialized. Cannot execute create.");
        }

        if (objectClass == null) {
            throw new InvalidAttributeValueException("ObjectClass cannot be null");
        }

        // Delegate to the appropriate handler based on ObjectClass
        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            if (userHandler == null) {
                throw new ConnectorException("UserHandler is not initialized.");
            }
            return userHandler.createUser(objectClass, createAttributes, options);
        }
        else if (ObjectClass.GROUP.equals(objectClass)) {
            if (groupHandler == null) {
                throw new ConnectorException("GroupHandler is not initialized.");
            }
            return groupHandler.createGroup(objectClass, createAttributes, options);
        }
        else if (AWSSchema.POLICY_OBJECT_CLASS.equals(objectClass)) {
            logger.warn("Create operation is not supported for Policy objects as they are read-only");
            throw new UnsupportedOperationException("Create operation is not supported for Policy objects as they are read-only");
        }
        else {
            logger.warn("Unsupported object class for create: {0}", objectClass);
            throw new UnsupportedOperationException("Create operation is not supported for ObjectClass: " + objectClass.getObjectClassValue());
        }
    }

}
