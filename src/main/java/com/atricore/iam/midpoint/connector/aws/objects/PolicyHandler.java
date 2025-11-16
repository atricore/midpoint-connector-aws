package com.atricore.iam.midpoint.connector.aws.objects;

import com.atricore.iam.midpoint.connector.aws.AWSConfiguration;
import com.atricore.iam.midpoint.connector.aws.AWSSchema;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Policies are read-only, from the midPoint perspective they are always 'unmanaged'.
 * <p>
 * We can use policies to configure users and groups, but the list of policies is managed by AWS.
 * <p>
 * Only Search operations are available, in the future CUSTOM policy types could be managed by midPoint
 * leaving MANAGED for AWS.
 */
public class PolicyHandler extends AbstractHandler {

    private static final Log logger = Log.getLog(PolicyHandler.class);

    public PolicyHandler(IamClient client, AWSConfiguration config) {
        super(client, config);
    }

    /**
     * Searches for AWS IAM policies based on the provided filter.
     * Optimizes the search by using direct API calls when possible.
     *
     * @param handler The results handler.
     * @param query   The filter to apply to the search.
     * @param options Operation options.
     */
    public void searchPolicies(ResultsHandler handler, Filter query, OperationOptions options) {
        logger.ok("Searching for policies with filter: {0}", query);

        if (query instanceof EqualsFilter) {
            EqualsFilter equalsFilter = (EqualsFilter) query;
            Attribute attribute = equalsFilter.getAttribute();

            // Check if we're filtering by Name (PolicyName)
            if (attribute instanceof Name) {
                String policyName = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(policyName)) {
                    logger.ok("Searching for policy with NAME, using ARN: {0}", policyName);
                    getPolicyByArn(handler, policyName, options);
                    return;
                }

            }
            if (attribute instanceof Uid) {
                String policyArn = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(policyArn)) {
                    logger.ok("Searching for policy with UID, using ARN: {0}", policyArn);
                    getPolicyByArn(handler, policyArn, options);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_POLICY_ID)) {
                // Filtering by PolicyId
                String policyId = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(policyId)) {
                    logger.ok("Searching for policy with ID: {0}", policyId);
                    searchPolicyById(handler, policyId, options);
                    return;
                }

            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_ARN)) {
                // Filtering by ARN
                String arn = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(arn)) {
                    logger.ok("Searching for policy with ARN: {0}", arn);
                    getPolicyByArn(handler, arn, options);
                    return;
                }

            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_POLICY_TYPE)) {
                // Filtering by policy type
                String policyType = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(policyType)) {
                    logger.ok("Searching for policies with type: {0}", policyType);
                    searchPoliciesByType(handler, policyType, options);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_PATH)) {
                // Filtering by path
                String path = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(path)) {
                    logger.ok("Searching for policies with path: {0}", path);
                    searchPoliciesByPath(handler, path, options);
                    return;
                }
            }
        }

        // For all other filters or complex filters, we need to list all policies and filter locally
        logger.ok("Using full policy listing for query: {0}", query);
        listAllPolicies(handler, options);
    }

    /**
     * Search for a policy by its name.
     */
    private void searchPoliciesByName(ResultsHandler handler, String policyName, OperationOptions options) {
        try {
            // List policies and filter by name
            searchAllPoliciesWithFilter(handler, policy ->
                    policyName.equals(policy.policyName()), options);
        } catch (Exception e) {
            logger.error(e, "Error searching for policy by name: {0} {1}", policyName, e.getMessage());
            throw new ConnectorException("Error searching for policy by name: " + e.getMessage(), e);
        }
    }

    /**
     * Search for a policy by its ID.
     */
    private void searchPolicyById(ResultsHandler handler, String policyId, OperationOptions options) {
        try {
            // List policies and filter by ID
            searchAllPoliciesWithFilter(handler, policy ->
                    policyId.equals(policy.policyId()), options);
        } catch (Exception e) {
            logger.error(e, "Error searching for policy by ID: {0} {1}", policyId, e.getMessage());
            throw new ConnectorException("Error searching for policy by ID: " + e.getMessage(), e);
        }
    }

    /**
     * Search for a policy by its ARN.
     */
    private void getPolicyByArn(ResultsHandler handler, String arn, OperationOptions options) {
        try {
            // Try to get the policy directly by ARN
            GetPolicyRequest request = GetPolicyRequest.builder()
                    .policyArn(arn)
                    .build();

            GetPolicyResponse response = client.getPolicy(request);
            Policy policy = response.policy();

            if (policy != null) {
                ConnectorObject co = buildConnectorObject(policy, getTagStrings(policy));
                if (co != null) {
                    handler.handle(co);
                }
            }
        } catch (NoSuchEntityException e) {
            logger.info("Policy not found with ARN: {0}", arn);
            // No results, just return
        } catch (Exception e) {
            logger.error(e, "Error searching for policy by ARN: {0} {1}", arn, e.getMessage());
            throw new ConnectorException("Error searching for policy by ARN " + e.getMessage(), e);
        }
    }

    /**
     * Search for policies by type (AWS_MANAGED or CUSTOMER_MANAGED).
     */
    private void searchPoliciesByType(ResultsHandler handler, String policyType, OperationOptions options) {
        try {
            PolicyType type;
            try {
                type = PolicyType.fromValue(policyType);
            } catch (IllegalArgumentException e) {
                logger.error("Invalid policy type: {0}", policyType);
                throw new ConnectorException("Invalid policy type: " + policyType);
            }

            // List policies with the specified type
            String marker = null;
            boolean done = false;
            boolean continueProcessing = true;

            while (!done && continueProcessing) {
                ListPoliciesRequest.Builder requestBuilder = ListPoliciesRequest.builder()
                        .scope(type == PolicyType.MANAGED ? PolicyScopeType.AWS : PolicyScopeType.LOCAL);

                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                // Apply pagination options if provided
                if (options != null && options.getPageSize() != null) {
                    requestBuilder.maxItems(options.getPageSize());
                }

                ListPoliciesResponse response = client.listPolicies(requestBuilder.build());
                List<Policy> policies = response.policies();

                for (Policy policy : policies) {
                    ConnectorObject co = buildConnectorObject(policy, getTagStrings(policy));
                    if (co != null) {
                        continueProcessing = handler.handle(co);
                        if (!continueProcessing) {
                            return;
                        }
                    }
                }

                // Check for more results
                if (response.isTruncated()) {
                    marker = response.marker();
                } else {
                    done = true;
                }
            }
        } catch (Exception e) {
            logger.error(e, "Error searching for policies by type: {0} {1}", policyType,e.getMessage());
            throw new ConnectorException("Error searching for policies by type: " + e.getMessage(), e);
        }
    }

    /**
     * Search for policies by path prefix.
     */
    private void searchPoliciesByPath(ResultsHandler handler, String pathPrefix, OperationOptions options) {
        try {
            String marker = null;
            boolean done = false;
            boolean continueProcessing = true;

            while (!done && continueProcessing) {
                ListPoliciesRequest.Builder requestBuilder = ListPoliciesRequest.builder()
                        .pathPrefix(pathPrefix);

                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                // Apply pagination options if provided
                if (options != null && options.getPageSize() != null) {
                    requestBuilder.maxItems(options.getPageSize());
                }

                ListPoliciesResponse response = client.listPolicies(requestBuilder.build());
                List<Policy> policies = response.policies();
                for (Policy policy : policies) {
                    ConnectorObject co = buildConnectorObject(policy, getTagStrings(policy));
                    if (co != null) {
                        continueProcessing = handler.handle(co);
                        if (!continueProcessing) {
                            return;
                        }
                    }
                }

                // Check for more results
                if (response.isTruncated()) {
                    marker = response.marker();
                } else {
                    done = true;
                }

            }
        } catch (Exception e) {
            logger.error(e, "Error searching for policies by path: {0}", e.getMessage());
            throw new ConnectorException("Error searching for policies by path: " + e.getMessage(), e);
        }
    }

    /**
     * List all policies with optional filtering.
     */
    private void searchAllPoliciesWithFilter(ResultsHandler handler, Predicate<Policy> filter, OperationOptions options) {
        try {
            String marker = null;
            boolean done = false;
            boolean continueProcessing = true;

            // Get scope from options if provided
            PolicyScopeType scope = PolicyScopeType.ALL;
            if (options != null && options.getOptions() != null) {
                Object scopeObj = options.getOptions().get("scope");
                if (scopeObj instanceof String) {
                    String scopeStr = (String) scopeObj;
                    if ("AWS".equalsIgnoreCase(scopeStr)) {
                        scope = PolicyScopeType.AWS;
                    } else if ("LOCAL".equalsIgnoreCase(scopeStr)) {
                        scope = PolicyScopeType.LOCAL;
                    }
                }
            }

            while (!done && continueProcessing) {
                ListPoliciesRequest.Builder requestBuilder = ListPoliciesRequest.builder()
                        .scope(scope);

                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                // Apply pagination options if provided
                if (options != null && options.getPageSize() != null) {
                    requestBuilder.maxItems(options.getPageSize());
                }

                // Get path prefix from options if provided
                if (options != null && options.getOptions() != null) {
                    Object pathPrefixObj = options.getOptions().get("pathPrefix");
                    if (pathPrefixObj instanceof String) {
                        String pathPrefix = (String) pathPrefixObj;
                        if (StringUtil.isNotBlank(pathPrefix)) {
                            requestBuilder.pathPrefix(pathPrefix);
                        }
                    }
                }

                ListPoliciesResponse response = client.listPolicies(requestBuilder.build());
                List<Policy> policies = response.policies();

                logger.ok("Retrieved {0} policies from AWS IAM", policies.size());

                for (Policy policy : policies) {
                    // Apply the filter
                    if (filter.test(policy)) {
                        ConnectorObject co = buildConnectorObject(policy, getTagStrings(policy));
                        if (co != null) {
                            continueProcessing = handler.handle(co);
                            if (!continueProcessing) {
                                return;
                            }
                        }
                    }
                }

                // Check for more results
                if (response.isTruncated()) {
                    marker = response.marker();
                } else {
                    done = true;
                }
            }
        } catch (Exception e) {
            logger.error(e, "Error listing policies: {0}", e.getMessage());
            throw new ConnectorException("Error listing policies: " + e.getMessage(), e);
        }
    }

    /**
     * List all policies.
     */
    private void listAllPolicies(ResultsHandler handler, OperationOptions options) {
        searchAllPoliciesWithFilter(handler, policy -> true, options);
    }

    /**
     * Builds a ConnectorObject from an AWS Policy object.
     */
    protected ConnectorObject buildConnectorObject(Policy policy, List<String> tagStrings) {
        if (policy == null) {
            return null;
        }

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();

        // Set the Name attribute (required)
        String policyName = policy.policyName();
        if (StringUtil.isBlank(policyName)) {
            logger.warn("Policy has no name, skipping");
            return null;
        }
        builder.setName(policy.arn());
        builder.setUid(policy.arn()); // Use ARN, simplifies associations
        builder.addAttribute(AWSSchema.ATTRIBUTE_ARN, policy.arn());
        builder.addAttribute(AWSSchema.ATTRIBUTE_POLICY_ID, policy.policyId());

        // Set the object class to our custom policy object class
        builder.setObjectClass(AWSSchema.POLICY_OBJECT_CLASS);

        // Add the policy type
        if (policy.arn().contains("iam::aws:")) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_POLICY_TYPE, PolicyType.MANAGED.toString());
        } else {
            builder.addAttribute(AWSSchema.ATTRIBUTE_POLICY_TYPE, "CUSTOMER");
        }

        // Add additional AWS-specific attributes (only if not null)
        if (policy.arn() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_ARN, policy.arn());
        }

        if (policy.path() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_PATH, policy.path());
        }

        // Handle date attributes - convert to String format to avoid class cast issues
        if (policy.createDate() != null) {
            String createDateStr = policy.createDate().toString();
            builder.addAttribute(AWSSchema.ATTRIBUTE_CREATE_DATE, createDateStr);
        }

        // Add optional attributes if they have values
        if (policy.description() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_DESCRIPTION, policy.description());
        }

        if (policy.defaultVersionId() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_DEFAULT_VERSION_ID, policy.defaultVersionId());
        }

        // Add numeric attributes
        builder.addAttribute(AWSSchema.ATTRIBUTE_ATTACHMENT_COUNT, policy.attachmentCount());
        builder.addAttribute(AWSSchema.ATTRIBUTE_PERMISSIONS_BOUNDARY_USAGE_COUNT, policy.permissionsBoundaryUsageCount());

        // Add boolean attributes
        builder.addAttribute(AWSSchema.ATTRIBUTE_IS_ATTACHABLE, policy.isAttachable());


        if (!tagStrings.isEmpty()) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_TAGS, tagStrings);
        }


        return builder.build();
    }

    protected List<String> getTagStrings(Policy policy) {

        List<String> tagStrings = new ArrayList<>();
        try {

            boolean done = false;
            String marker = null;

            while (!done) {

                ListPolicyTagsRequest.Builder b = ListPolicyTagsRequest.builder()
                        .policyArn(policy.arn());

                if (marker != null) {
                    b.marker(marker);
                }
                ListPolicyTagsResponse res = client.listPolicyTags(b.build());

                if (res.isTruncated()) {
                    marker = res.marker();
                } else {
                    done = true;
                }

                if (res.hasTags()) {
                    for (Tag tag : res.tags()) {
                        logger.info("Adding tag: " + tag.key() + "=" + tag.value() + " to policy " + policy.arn());
                        tagStrings.add(tag.key() + "=" + tag.value());
                    }
                }

            }

        } catch (NoSuchEntityException e) {
            // Policy might not exist anymore, or tags are not accessible. Log and continue.
            logger.warn("Could not retrieve tags for policy ARN {0}: Policy not found or tags inaccessible.", policy.arn());
        } catch (IamException e) {
            // Log other IAM exceptions and continue.
            logger.warn(e, "Error retrieving tags for policy ARN {0}", policy.arn());
        } catch (NullPointerException e) {
            // Handle NPE gracefully in case the response is null
            logger.warn("Null response when retrieving tags for policy ARN {0}", policy.arn());
        } catch (Exception e) {
            // Catch any other exceptions to ensure policy object still gets built
            logger.warn(e, "Unexpected error retrieving tags for policy ARN {0}", policy.arn());
        }
        return tagStrings;
    }


}
