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

public class RoleHandler extends AbstractHandler {

    private static final Log logger = Log.getLog(RoleHandler.class);

    public RoleHandler(IamClient client, AWSConfiguration config) {
        super(client, config);
    }

    /**
     * Searches for AWS IAM roles based on the provided filter.
     * Optimizes the search by using direct API calls when possible.
     *
     * @param handler The results handler.
     * @param query   The filter to apply to the search.
     * @param options Operation options.
     */
    public void searchRoles(ResultsHandler handler, Filter query, OperationOptions options) {
        logger.ok("Searching for roles with filter: {0}", query);

        if (query instanceof EqualsFilter) {
            EqualsFilter equalsFilter = (EqualsFilter) query;
            Attribute attribute = equalsFilter.getAttribute();

            // Check if we're filtering by Name (RoleName)
            if (attribute instanceof Name) {
                String roleName = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(roleName)) {
                    logger.ok("Searching for role with NAME: {0}", roleName);
                    Role role = findRoleByName(roleName);
                    ConnectorObject co = buildConnectorObject(role, getAttachedPolicies(roleName));
                    handler.handle(co);
                    return;
                }

            } else if (attribute instanceof Uid) {
                // Filtering by UID
                String roleName = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(roleName)) {
                    logger.ok("Searching for role with UID, using NAME: {0}", roleName);
                    Role role = findRoleByName(roleName);
                    ConnectorObject co = buildConnectorObject(role, getAttachedPolicies(roleName));
                    handler.handle(co);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_AWS_ID)) {
                // Filtering by RoleId
                String roleId = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(roleId)) {
                    logger.ok("Searching for role with ID: {0}", roleId);
                    searchAllRolesWithFilter(handler, role -> roleId.equals(role.roleId()), options);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_PATH)) {
                // Filtering by path
                String path = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(path)) {
                    logger.ok("Searching for roles with path: {0}", path);
                    searchRolesByPath(handler, path, options);
                    return;
                }
            }
        }

        // For all other filters or complex filters, we need to list all roles and filter locally
        logger.ok("Using full role listing for query: {0}", query);
        listAllRoles(handler, options);
    }

    /**
     * Search for a pole by its name.
     */
    private Role findRoleByName(String roleName) {
        try {
            GetRoleResponse res = client.getRole(GetRoleRequest.builder().roleName(roleName).build());
            return res != null ? res.role() : null;
        } catch (Exception e) {
            logger.error(e, "Error searching for role by name: {0} {1}", roleName, e.getMessage());
            throw new ConnectorException("Error searching for role by name: " + e.getMessage(), e);
        }
    }

    /**
     * Search for a role by its ID.
     */
    private Role findRoleById(String roleId) {
        return findRoleByName(roleId);
    }

    /**
     * Search for roles by path prefix.
     */
    private void searchRolesByPath(ResultsHandler handler, String pathPrefix, OperationOptions options) {
        try {
            String marker = null;
            boolean done = false;
            boolean continueProcessing = true;

            while (!done && continueProcessing) {
                ListRolesRequest.Builder requestBuilder = ListRolesRequest.builder()
                        .pathPrefix(pathPrefix);

                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                // Apply pagination options if provided
                if (options != null && options.getPageSize() != null) {
                    requestBuilder.maxItems(options.getPageSize());
                }

                ListRolesResponse response = client.listRoles(requestBuilder.build());
                List<Role> roles = response.roles();

                for (Role role : roles) {
                    List<String> attachedPolicies = getAttachedPolicies(role.roleName());
                    ConnectorObject co = buildConnectorObject(role, attachedPolicies);
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
            logger.error(e, "Error searching for roles by path: {0} {1}", pathPrefix, e.getMessage());
            throw new ConnectorException("Error searching for roles by path: " + e.getMessage(), e);
        }
    }


    /**
     * List all roles with optional filtering.
     */
    private void searchAllRolesWithFilter(ResultsHandler handler, Predicate<Role> filter, OperationOptions options) {
        try {
            String marker = null;
            boolean done = false;
            boolean continueProcessing = true;

            ListRolesRequest.Builder requestBuilder = ListRolesRequest.builder();

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

            while (!done && continueProcessing) {

                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                ListRolesResponse response = client.listRoles(requestBuilder.build());
                List<Role> roles = response.roles();

                logger.ok("Retrieved {0} roles from AWS IAM, applying filter {1}", roles.size(), filter);

                for (Role role : roles) {
                    // Apply the filter
                    if (filter.test(role)) {
                        logger.ok("Found {0} role for filter {1}", role.roleName(), filter);
                        List<String> attachedPolicies = getAttachedPolicies(role.roleName());
                        ConnectorObject co = buildConnectorObject(role, attachedPolicies);
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
            logger.error(e, "Error listing roles: {0}", e.getMessage());
            throw new ConnectorException("Error listing roles: " + e.getMessage(), e);
        }
    }

    /**
     * List all roles.
     */
    private void listAllRoles(ResultsHandler handler, OperationOptions options) {
        searchAllRolesWithFilter(handler, role -> true, options);
    }

    /**
     * Get attached policies for this role
     *
     * @param roleName
     * @return a list of policy ARNs
     */
    private List<String> getAttachedPolicies(String roleName) {

        ListAttachedRolePoliciesRequest request =
                ListAttachedRolePoliciesRequest
                        .builder().roleName(roleName).build();
        List<String> matching_policies = new ArrayList<>();

        boolean done = false;
        while (!done) {
            ListAttachedRolePoliciesResponse response =
                    client.listAttachedRolePolicies(request);
            matching_policies.addAll(response.
                    attachedPolicies().
                    stream().
                    map(AttachedPolicy::policyArn).
                    toList());
            if (!response.isTruncated()) {
                done = true;
            }

            String m = response.marker();
            request = request.toBuilder().marker(m).build();
        }

        logger.info("Found " + matching_policies.size() + " policies for role " + roleName);

        return matching_policies;

    }

    /**
     * Builds a ConnectorObject from an AWS Role object.
     */
    protected ConnectorObject buildConnectorObject(Role role, List<String> attachedPoliciesArns) {
        if (role == null) {
            return null;
        }

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        // Set the object class to our custom pole object class
        builder.setObjectClass(AWSSchema.ROLE_OBJECT_CLASS);

        builder.setName(role.roleName());
        builder.setUid(role.roleName()); // Since AWS does not have a lookup by ID, use the name.
        builder.addAttribute(AWSSchema.ATTRIBUTE_AWS_ID, role.roleId());
        builder.addAttribute(AWSSchema.ATTRIBUTE_ARN, role.arn());

        if (role.path() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_PATH, role.path());
        }

        // Handle date attributes - convert to String format to avoid class cast issues
        if (role.createDate() != null) {
            String createDateStr = role.createDate().toString();
            builder.addAttribute(AWSSchema.ATTRIBUTE_CREATE_DATE, createDateStr);
        }

        // Add optional attributes if they have values
        if (role.description() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_DESCRIPTION, role.description());
        }

        if (attachedPoliciesArns != null && !attachedPoliciesArns.isEmpty()) {
            builder.addAttribute(AWSSchema.ASSOCIATION_POLICIES, attachedPoliciesArns);
            logger.ok("Added {0} attached policies to role {1}", attachedPoliciesArns.size(), role.roleName());
            attachedPoliciesArns.stream().forEach(s -> logger.ok("Added {0} to role {1}", s, role));
        }

        return builder.build();
    }

}
