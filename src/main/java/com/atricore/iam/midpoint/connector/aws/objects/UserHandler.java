package com.atricore.iam.midpoint.connector.aws.objects;

import com.atricore.iam.midpoint.connector.aws.AWSConfiguration;
import com.atricore.iam.midpoint.connector.aws.AWSSchema;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;
import software.amazon.awssdk.core.exception.SdkClientException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * UserHandler
 */
public class UserHandler extends AbstractHandler {

    private static final Log logger = Log.getLog(UserHandler.class);

    public UserHandler(IamClient client, AWSConfiguration config) {
        super(client, config);
    }

    /**
     * Creates a new AWS IAM user based on the provided attributes.
     *
     * @param objectClass      The object class (should be ACCOUNT).
     * @param createAttributes The set of attributes for the new user.
     * @param options          Operation options.
     * @return The Uid of the newly created user.
     */
    public Uid createUser(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
        logger.ok("createUser called for ObjectClass: {0}", objectClass);

        if (!ObjectClass.ACCOUNT.equals(objectClass)) {
            throw new IllegalArgumentException("Unsupported object class for create: " + objectClass);
        }

        String userName = null;
        String path = null; // Optional path

        // Extract attributes
        for (Attribute attr : createAttributes) {
            if (Name.NAME.equals(attr.getName())) {
                userName = AttributeUtil.getAsStringValue(attr);
            } else if (AWSSchema.ATTRIBUTE_PATH.equals(attr.getName())) {
                path = AttributeUtil.getAsStringValue(attr);
            }
            // TODO: Handle other creatable attributes like tags, permissions boundary?
        }

        // Validate required attributes
        if (StringUtil.isBlank(userName)) {
            throw new InvalidAttributeValueException("Missing required attribute: " + Name.NAME);
        }

        try {
            logger.ok("Attempting to create AWS IAM user with UserName: {0}, Path: {1}", userName, path);

            // Build the request
            CreateUserRequest.Builder requestBuilder = CreateUserRequest.builder()
                    .userName(userName);

            if (StringUtil.isNotBlank(path)) {
                requestBuilder.path(path);
            }

            // Execute the request
            CreateUserResponse response = client.createUser(requestBuilder.build());
            User newUser = response.user();

            if (newUser == null || StringUtil.isBlank(newUser.userId())) {
                logger.error("CreateUser call succeeded but returned null user or user with no UserId for UserName: {0}", userName);
                throw new ConnectorException("Failed to retrieve UserId for newly created user: " + userName);
            }

            String userId = newUser.userId();
            logger.ok("Successfully created AWS IAM user. UserName: {0}, UserId: {1}", userName, userId);

            // Handle initial group assignments if provided
            Attribute groupMembershipAttr = AttributeUtil.find(AWSSchema.ASSOCIATION_GROUPS, createAttributes);
            if (groupMembershipAttr != null && groupMembershipAttr.getValue() != null && !groupMembershipAttr.getValue().isEmpty()) {
                try {
                    // Process group assignments
                    for (Object groupNameObj : groupMembershipAttr.getValue()) {
                        String groupName = groupNameObj.toString();

                        if (StringUtil.isNotBlank(groupName)) {
                            // Add user to the group
                            addUserToGroup(groupName, userName);
                            logger.ok("Added newly created user {0} to group {1}", userName, groupName);
                        } else {
                            logger.warn("Could not find group name for group ID {0} during user creation", groupName);
                        }
                    }
                } catch (Exception e) {
                    logger.error(e, "Error assigning groups to newly created user {0}: {1}", userName, e.getMessage());

                    // The user is already created, but group assignments failed
                }
            }

            // Handle initial policy attachments if provided
            Attribute policyAttachmentAttr = AttributeUtil.find(AWSSchema.ASSOCIATION_POLICIES, createAttributes);
            if (policyAttachmentAttr != null && policyAttachmentAttr.getValue() != null && !policyAttachmentAttr.getValue().isEmpty()) {
                try {
                    for (Object policyArnObj : policyAttachmentAttr.getValue()) {
                        String policyArn = policyArnObj.toString();
                        if (StringUtil.isNotBlank(policyArn)) {
                            attachUserPolicy(userName, policyArn);
                            logger.ok("Attached policy {0} to newly created user {1}", policyArn, userName);
                        }
                    }
                } catch (Exception e) {
                    logger.error(e, "Error attaching policies to newly created user {0}: {1}", userName, e.getMessage());
                    // Don't fail the whole creation if policy attachment fails
                }
            }

            return new Uid(userId); // Return the AWS-generated UserId as the Uid

        } catch (EntityAlreadyExistsException e) {

            logger.warn("User with UserName {0} already exists.", userName);
            throw new AlreadyExistsException("User with UserName '" + userName + "' already exists", e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded during user creation for UserName: {0}", userName);
            throw new ConnectorException("AWS limit exceeded during user creation: " + e.getMessage(), e);
        } catch (InvalidInputException e) {
            logger.error(e, "Invalid input provided for user creation (UserName: {0}): {1}", userName, e.getMessage());
            throw new InvalidAttributeValueException("Invalid input for user creation: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception during CreateUser operation for UserName {0}: {1}", userName, e.getMessage());
            throw new ConnectorException("Error during CreateUser operation: " + e.getMessage(), e);
        }
    }

    /**
     * Applies attribute modifications (delta) to an AWS IAM user.
     * This operation is typically used for incremental updates, especially for multi-valued attributes.
     *
     * @param uid           The Uid of the user to update.
     * @param modifications A set of attribute deltas specifying the changes.
     * @param options       Operation options.
     * @return An empty set if the update is successful, or a set of AttributeDeltas that could not be applied.
     * For this implementation, it returns an empty set on success.
     */
    public Set<AttributeDelta> updateUserDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        logger.ok("updateUserDelta called for Uid {0}, Modifications: {1}", uid, modifications);

        if (uid == null || StringUtil.isBlank(uid.getUidValue())) {
            throw new InvalidAttributeValueException("Uid cannot be null or empty for updateDelta operation");
        }

        if (modifications == null || modifications.isEmpty()) {
            logger.ok("No modifications provided for Uid: {0}");
            return Collections.emptySet();
        }

        String userId = uid.getUidValue();

        try {
            User user = findUserById(userId); // This will throw NoSuchEntityException if not found
            if (user == null) {
                throw NoSuchEntityException.builder().message("User not found for id " + userId).build();
            }
            String currentUserName = user.userName();
            String userNameForApiCall = currentUserName; // This will be updated if username changes

            UpdateUserRequest.Builder updateUserRequestBuilder = null;
            String newUserNameHolder = null;

            // Pass 1: Handle Name and Path updates (attributes requiring UpdateUser API)
            for (AttributeDelta delta : modifications) {
                if (delta == null) continue;
                String attributeName = delta.getName();

                if (Name.NAME.equals(attributeName)) {
                    List<Object> valuesToReplace = delta.getValuesToReplace();
                    if (valuesToReplace != null && !valuesToReplace.isEmpty()) {
                        String newUserNameCandidate = valuesToReplace.get(0).toString();
                        if (StringUtil.isNotBlank(newUserNameCandidate) && !newUserNameCandidate.equals(currentUserName)) {
                            if (updateUserRequestBuilder == null) {
                                updateUserRequestBuilder = UpdateUserRequest.builder().userName(currentUserName);
                            }
                            updateUserRequestBuilder.newUserName(newUserNameCandidate);
                            newUserNameHolder = newUserNameCandidate;
                            logger.ok("Delta: Preparing to update username from {0} to {1}", currentUserName, newUserNameCandidate);
                        }
                    }
                } else if (AWSSchema.ATTRIBUTE_PATH.equals(attributeName)) {
                    List<Object> valuesToReplace = delta.getValuesToReplace();
                    if (valuesToReplace != null && !valuesToReplace.isEmpty()) {
                        String newPath = valuesToReplace.get(0).toString(); // Path can be empty string
                        if (updateUserRequestBuilder == null) {
                            updateUserRequestBuilder = UpdateUserRequest.builder().userName(currentUserName);
                        }
                        updateUserRequestBuilder.newPath(newPath);
                        logger.ok("Delta: Preparing to update path to \"{0}\" for user {1}", newPath, currentUserName);
                    }
                } else if (AWSSchema.ATTRIBUTE_ARN.equals(attributeName)) {
                    logger.warn("Delta update for ARN is not supported as ARN is an identifier. Attribute: {0}", attributeName);
                }
            }

            // Execute UpdateUser API call if there are changes to Name or Path
            if (updateUserRequestBuilder != null) {
                try {
                    logger.info("Executing UpdateUser API call for current user name: {0}", currentUserName);
                    client.updateUser(updateUserRequestBuilder.build());
                    logger.ok("Successfully updated user attributes (Name/Path) for original user name: {0}", currentUserName);
                    if (newUserNameHolder != null) {
                        userNameForApiCall = newUserNameHolder; // Update username for subsequent operations
                        logger.info("Username was changed from {0} to {1}. Subsequent operations will use new username.", currentUserName, userNameForApiCall);
                    }
                } catch (IamException e) {
                    logger.error(e, "AWS IAM Error during UpdateUser (Name/Path) for user {0}: {1}", currentUserName, e.getMessage());
                    throw new ConnectorException("Error updating user core attributes: " + e.getMessage(), e);
                }
            }

            // Pass 2: Handle associations (Group Membership, Policies)
            for (AttributeDelta delta : modifications) {
                if (delta == null) continue;
                String attributeName = delta.getName();

                if (AWSSchema.ASSOCIATION_GROUPS.equals(attributeName)) {

                    processGroupsDelta(userNameForApiCall, delta);

                } else if (AWSSchema.ASSOCIATION_POLICIES.equals(attributeName)) {

                    processPoliciesDelta(userNameForApiCall, delta);
                } else if (!Name.NAME.equals(attributeName) &&
                        !AWSSchema.ATTRIBUTE_PATH.equals(attributeName) &&
                        !AWSSchema.ATTRIBUTE_ARN.equals(attributeName)) {
                    // This attribute was not Name, Path, ARN, Group Membership, or Policies
                    logger.warn("Delta update for attribute {0} is not explicitly handled by updateUserDelta.", attributeName);
                }
            }

            logger.ok("Successfully processed delta updates for user originally identified by UserId: {0} (current/new username: {1})", userId, userNameForApiCall);
            return Collections.emptySet(); // Standard practice to return empty set on success

        } catch (NoSuchEntityException e) {
            logger.error(e, "User not found during updateDelta operation for UserId: {0}", userId);
            throw new ConnectorException("User not found for updateDelta: " + e.getMessage(), e);
        } catch (IamException e) {
            logger.error(e, "AWS IAM Exception during updateUserDelta for UserId {0}: {1}", userId, e.getMessage());
            throw new ConnectorException("AWS IAM Error during updateUserDelta: " + e.getMessage(), e);
        } catch (SdkClientException e) {
            logger.error(e, "AWS SDK Client Exception during updateUserDelta for UserId {0}: {1}", userId, e.getMessage());
            throw new ConnectorException("AWS SDK Client Error during updateUserDelta: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Unexpected exception during updateUserDelta for UserId {0}: {1}", userId, e.getMessage());
            throw new ConnectorException("Unexpected error during updateUserDelta: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes an AWS IAM user.
     * Performs complete cleanup by detaching all policies, removing from all groups,
     * and deleting any inline policies before deleting the user.
     *
     * @param objectClass The object class (should be ACCOUNT).
     * @param uid         The Uid of the user to delete.
     * @param options     Operation options.
     */
    public void deleteUser(ObjectClass objectClass, Uid uid, OperationOptions options) {
        logger.ok("deleteUser called for Uid {0}", uid);

        if (!ObjectClass.ACCOUNT.equals(objectClass)) {
            throw new IllegalArgumentException("Unsupported object class for delete: " + objectClass);
        }

        if (uid == null || StringUtil.isBlank(uid.getUidValue())) {
            throw new InvalidAttributeValueException("Uid cannot be null or empty for delete operation");
        }
        String userId = uid.getUidValue();

        try {
            // First, try to find the user by userId to get the userName
            logger.ok("Looking up UserName for UserId: {0}", userId);
            User user = findUserById(userId);
            String userName = user.userName();

            logger.ok("Starting cleanup process for user {0} before deletion", userName);

            // Step 1: Detach all managed policies from the user
            try {
                List<String> attachedPolicies = getAttachedPolicies(userName);
                logger.ok("Found {0} attached policies to detach from user {1}", attachedPolicies.size(), userName);

                for (String policyArn : attachedPolicies) {
                    try {
                        detachUserPolicy(userName, policyArn);
                        logger.ok("Successfully detached policy {0} from user {1}", policyArn, userName);
                    } catch (Exception e) {
                        logger.warn("Failed to detach policy {0} from user {1}: {2}", policyArn, userName, e.getMessage());
                        // Continue with other policies even if one fails
                    }
                }
            } catch (Exception e) {
                logger.warn("Error during policy detachment for user {0}: {1}", userName, e.getMessage());
                // Continue with deletion process
            }

            // Step 2: Remove user from all groups
            try {

                List<Group> userGroups = getGroupsByUserName(userName);
                logger.ok("Found {0} groups to remove user {1} from", userGroups.size(), userName);
                for (Group group : userGroups) {
                    try {
                        removeUserFromGroup(group.groupName(), userName);
                        logger.ok("Successfully removed user {0} from group {1}", userName, group.groupName());
                    } catch (Exception e) {
                        logger.warn("Failed to remove user {0} from group {1}: {2}", userName, group.groupName(), e.getMessage());
                        // Continue with other groups even if one fails
                    }
                }
            } catch (Exception e) {
                logger.warn("Error during group removal for user {0}: {1}", userName, e.getMessage());
                // Continue with deletion process
            }

            // Step 3: Delete all inline policies attached to the user
            try {

                List<AttachedPolicy> inlinePolicyNames = getPoliciesByUserName(userName);
                logger.ok("Found {0} inline policies to delete from user {1}", inlinePolicyNames.size(), userName);
                inlinePolicyNames.stream().forEach(p -> {
                    try {
                        DeleteUserPolicyRequest deleteInlinePolicyRequest = DeleteUserPolicyRequest.builder()
                                .userName(userName)
                                .policyName(p.policyName())
                                .build();
                        client.deleteUserPolicy(deleteInlinePolicyRequest);
                        logger.ok("Successfully deleted inline policy {0} from user {1}", p, userName);
                    } catch (Exception e) {
                        logger.warn("Failed to delete inline policy {0} from user {1}: {2}", p.policyName(), userName, e.getMessage());
                        // Continue with other policies even if one fails
                    }
                });
            } catch (Exception e) {
                logger.warn("Error during inline policy deletion for user {0}: {1}", userName, e.getMessage());
                // Continue with deletion process
            }

            // Step 4: Delete login profile if it exists
            try {
                GetLoginProfileRequest getLoginProfileRequest = GetLoginProfileRequest.builder()
                        .userName(userName)
                        .build();
                client.getLoginProfile(getLoginProfileRequest);

                // If we get here, the login profile exists, so delete it
                DeleteLoginProfileRequest deleteLoginProfileRequest = DeleteLoginProfileRequest.builder()
                        .userName(userName)
                        .build();
                client.deleteLoginProfile(deleteLoginProfileRequest);
                logger.ok("Successfully deleted login profile for user {0}", userName);
            } catch (NoSuchEntityException e) {
                // Login profile doesn't exist, which is fine
                logger.ok("No login profile found for user {0} (this is normal)", userName);
            } catch (Exception e) {
                logger.warn("Error handling login profile for user {0}: {1}", userName, e.getMessage());
                // Continue with deletion process
            }

            // Step 5: Delete access keys
            try {

                List<AccessKeyMetadata> accessKeys = getAccessKeysByUserName(userName);
                for (AccessKeyMetadata accessKey : accessKeys) {
                    try {
                        DeleteAccessKeyRequest deleteAccessKeyRequest = DeleteAccessKeyRequest.builder()
                                .userName(userName)
                                .accessKeyId(accessKey.accessKeyId())
                                .build();
                        client.deleteAccessKey(deleteAccessKeyRequest);
                        logger.ok("Successfully deleted access key {0} for user {1}", accessKey.accessKeyId(), userName);
                    } catch (Exception e) {
                        logger.warn("Failed to delete access key {0} for user {1}: {2}", accessKey.accessKeyId(), userName, e.getMessage());
                        // Continue with other access keys even if one fails
                    }
                }
            } catch (Exception e) {
                logger.warn("Error during access key deletion for user {0}: {1}", userName, e.getMessage());
                // Continue with deletion process
            }

            // Step 6: Finally, delete the user
            DeleteUserRequest request = DeleteUserRequest.builder().userName(userName).build();
            logger.ok("Attempting to delete AWS IAM user with UserName: {0}", userName);
            client.deleteUser(request);
            logger.ok("Successfully deleted AWS IAM user with UserName: {0}", userName);

        } catch (NoSuchEntityException e) {
            // User not found - this is not an error for delete
            logger.warn("User not found during delete operation for UserId: {0}", userId);
            // No-op - idempotent delete
        } catch (DeleteConflictException e) {
            logger.error(e, "Delete conflict: The user still has attached resources after cleanup (UserId: {0})", userId);
            throw new ConnectorException("Cannot delete user. User still has attached resources after cleanup: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded during user deletion for UserId: {0}", userId);
            throw new ConnectorException("AWS limit exceeded during user deletion: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception during DeleteUser operation for UserId {0}: {1}", userId, e.getMessage());
            throw new ConnectorException("Error during DeleteUser operation: " + e.getMessage(), e);
        }
    }

    /**
     * Searches for AWS IAM users based on the provided filter.
     * Optimizes the search by using direct API calls when possible.
     *
     * @param handler The results handler.
     * @param query   The filter to apply to the search.
     * @param options Operation options.
     */
    public void searchUsers(ResultsHandler handler, Filter query, OperationOptions options) {
        logger.ok("Searching for users with filter: {0}", query);

        if (query instanceof EqualsFilter) {
            EqualsFilter equalsFilter = (EqualsFilter) query;
            Attribute attribute = equalsFilter.getAttribute();

            // Check if we're filtering by Name (UserName) - we can use GetUser API directly
            if (attribute instanceof Name) {
                String userName = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(userName)) {
                    logger.ok("Searching for user with NAME: {0}", userName);
                    User user = getUserByUserName(userName);
                    ConnectorObject connectorObject = buildConnectorObject(user,
                            getAttachedPolicies(user.userName()),
                            getGroupNamesByUserName(user.userName()));

                    handler.handle(connectorObject);
                    return;
                }
            } else if (attribute instanceof Uid) {
                // Filtering by UID
                String userName = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(userName)) {
                    logger.ok("Searching for user with UID: {0}, using NAME", userName);
                    User user = getUserByUserName(userName);
                    ConnectorObject connectorObject = buildConnectorObject(user,
                            getAttachedPolicies(user.userName()),
                            getGroupNamesByUserName(user.userName()));
                    handler.handle(connectorObject);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_AWS_ID)) {
                // Filtering by UserId
                String userId = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(userId)) {
                    logger.ok("Searching for user with ID: {0}", userId);
                    searchAllUsersWithFilter(handler, role -> userId.equals(role.userId()), options);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_ARN)) {
                // Filtering by ARN
                String arn = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(arn)) {
                    logger.ok("Searching for user with ARN: {0}", arn);
                    // We'll need to list all users and filter by ARN
                    searchAllUsersWithFilter(handler, user -> arn.equals(user.arn()), options);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_PATH)) {
                // Filtering by path
                String path = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(path)) {
                    logger.ok("Searching for users with Path: {0}", path);
                    // We can use PathPrefix in ListUsers API
                    searchUsersWithPathPrefix(handler, path, options);
                    return;
                }
            }
        }

        // For all other filters or complex filters, we need to list all users and filter locally
        logger.ok("Using full user listing with local filtering for query: {0}", query);

        searchAllUsersWithFilter(handler, user -> {
            // For null filter, accept all users. Implement some needed filters
            return true; // Accept all users when no filter is provided
        }, options);
    }

    protected User findUser(String userId, String userName) throws NoSuchEntityException {

        if (StringUtil.isBlank(userName)) {
            // Name not provided in the attributes, need to look it up by UserId
            logger.ok("Name attribute not provided for update, looking up UserName for UserId: {0}", userId);
            return findUserById(userId);
        }

        // Read the user by username, normally this will work!
        try {
            // If we CAN'T find the username, it is because we are updating it !
            return this.getUserByUserName(userName);
        } catch (NoSuchEntityException e) {
            return this.findUserById(userId);
        }

    }

    /**
     * Lists all users with a specific path prefix.
     * AWS API supports filtering by path prefix server-side.
     */
    private void searchUsersWithPathPrefix(ResultsHandler handler, String pathPrefix, OperationOptions options) {
        try {
            String marker = null;
            boolean done = false;
            boolean continueProcessing = true;

            // Handle pagination options if provided
            Integer pageSize = null;
            if (options != null && options.getPageSize() != null) {
                pageSize = options.getPageSize();
                logger.ok("Using page size from options: {0}", pageSize);
            }

            while (!done && continueProcessing) {
                ListUsersRequest.Builder requestBuilder = ListUsersRequest.builder()
                        .pathPrefix(pathPrefix);

                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                // Apply page size if specified
                if (pageSize != null) {
                    requestBuilder.maxItems(pageSize);
                }

                ListUsersResponse response = client.listUsers(requestBuilder.build());

                // Handle null response
                if (response == null) {
                    logger.warn("Received null response from ListUsers API with path prefix: {0}", pathPrefix);
                    break;
                }

                List<User> users = response.users();

                // Handle null users list
                if (users == null) {
                    users = new ArrayList<>();
                }

                logger.ok("Retrieved {0} users with path prefix: {1}", users.size(), pathPrefix);

                for (User user : users) {
                    if (user != null) {
                        ConnectorObject co = buildConnectorObject(user, getAttachedPolicies(user.userName()), getGroupNamesByUserName(user.userName()));
                        if (co != null) {
                            // Only stop processing if the handler explicitly returns false
                            continueProcessing = handler.handle(co);
                            if (!continueProcessing) {
                                logger.info("Handler returned false, stopping processing");
                                return;
                            }
                        }
                    }
                }

                // Check if there are more results
                if (response.isTruncated()) {
                    marker = response.marker();
                    logger.info("Pagination: More results available, marker: {0}", marker);
                } else {
                    done = true;
                    logger.info("Pagination: No more results available");
                }
            }
        } catch (software.amazon.awssdk.services.iam.model.IamException e) {
            logger.error(e, "IAM service exception during ListUsers operation: {0}", e.getMessage());
            throw new ConnectorException("IAM service exception during ListUsers: " + e.getMessage(), e);
        } catch (software.amazon.awssdk.core.exception.SdkClientException e) {
            logger.error(e, "AWS SDK client exception during ListUsers operation: {0}", e.getMessage());
            throw new ConnectorException("AWS SDK client exception during ListUsers: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Unexpected exception during ListUsers operation: {0}", e.getMessage());
            throw ConnectorException.wrap(e);
        }
    }

    /**
     * Lists all users and applies a filter function to each user.
     * Only users that pass the filter are converted to ConnectorObjects and passed to the handler.
     */
    private void searchAllUsersWithFilter(ResultsHandler handler, java.util.function.Predicate<User> filter, OperationOptions options) {
        try {
            String marker = null;
            boolean done = false;
            boolean continueProcessing = true;

            // Handle pagination options if provided
            Integer pageSize = null;
            if (options != null && options.getPageSize() != null) {
                pageSize = options.getPageSize();
                logger.ok("Using page size from options: {0}", pageSize);
            }

            // Get path prefix from options if provided
            String pathPrefix = null;
            if (options != null && options.getOptions() != null) {
                Object pathPrefixObj = options.getOptions().get("pathPrefix");
                if (pathPrefixObj instanceof String) {
                    pathPrefix = (String) pathPrefixObj;
                    logger.ok("Using path prefix from options: {0}", pathPrefix);
                }
            }

            while (!done && continueProcessing) {
                ListUsersRequest.Builder requestBuilder = ListUsersRequest.builder();

                // Apply marker for pagination
                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                // Apply path prefix if specified
                if (StringUtil.isNotBlank(pathPrefix)) {
                    requestBuilder.pathPrefix(pathPrefix);
                }

                // Apply page size if specified
                if (pageSize != null) {
                    requestBuilder.maxItems(pageSize);
                }

                ListUsersResponse response = client.listUsers(requestBuilder.build());

                // Handle null response
                if (response == null) {
                    logger.warn("Received null response from ListUsers API");
                    break;
                }

                List<User> users = response.users();

                // Handle null users list
                if (users == null) {
                    users = new ArrayList<>();
                }

                logger.ok("Retrieved {0} users from AWS IAM", users.size());

                for (User user : users) {
                    // Apply the filter
                    if (user != null && filter.test(user)) {
                        ConnectorObject co = buildConnectorObject(user, getAttachedPolicies(user.userName()), getGroupNamesByUserName(user.userName()));
                        if (co != null) {
                            // Only stop processing if the handler explicitly returns false
                            continueProcessing = handler.handle(co);
                            if (!continueProcessing) {
                                logger.info("Handler returned false, stopping processing");
                                return;
                            }
                        }
                    }
                }

                // Check if there are more results
                if (response.isTruncated()) {
                    marker = response.marker();
                    logger.info("Pagination: More results available, marker: {0}", marker);
                } else {
                    done = true;
                    logger.info("Pagination: No more results available");
                }
            }
        } catch (software.amazon.awssdk.services.iam.model.IamException e) {
            logger.error(e, "IAM service exception during ListUsers operation: {0}", e.getMessage());
            throw new ConnectorException("IAM service exception during ListUsers: " + e.getMessage(), e);
        } catch (software.amazon.awssdk.core.exception.SdkClientException e) {
            logger.error(e, "AWS SDK client exception during ListUsers operation: {0}", e.getMessage());
            throw new ConnectorException("AWS SDK client exception during ListUsers: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Unexpected exception during ListUsers operation: {0}", e.getMessage());
            throw ConnectorException.wrap(e);
        }
    }

    /**
     * Builds a ConnectorObject from an AWS User object.
     */
    protected ConnectorObject buildConnectorObject(User user, List<String> attachedPoliciesArns, List<String> userGroups) {
        if (user == null) {
            return null;
        }

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();

        // Set the object class
        builder.setObjectClass(ObjectClass.ACCOUNT);

        builder.setName(user.userName());
        builder.setUid(user.userName()); // Since AWS does not have a lookup by ID, use the name.
        builder.addAttribute(AWSSchema.ATTRIBUTE_AWS_ID, user.userId());
        builder.addAttribute(AWSSchema.ATTRIBUTE_ARN, user.arn());

        if (user.path() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_PATH, user.path());
        }

        // Handle date attributes - convert to String format to avoid class cast issues
        if (user.createDate() != null) {
            String createDateStr = user.createDate().toString();
            builder.addAttribute(AWSSchema.ATTRIBUTE_CREATE_DATE, createDateStr);
        }

        // Only add optional attributes if they have values
        if (user.passwordLastUsed() != null) {
            String passwordLastUsedStr = user.passwordLastUsed().toString();
            builder.addAttribute(AWSSchema.ATTRIBUTE_PASSWORD_LAST_USED, passwordLastUsedStr);
        }

        // Add group membership association
        if (userGroups != null && !userGroups.isEmpty()) {
            builder.addAttribute(AWSSchema.ASSOCIATION_GROUPS, userGroups);
            logger.ok("Added {0} group memberships to user {1}", userGroups.size(), user.userName());
        }

        if (attachedPoliciesArns != null && !attachedPoliciesArns.isEmpty()) {
            builder.addAttribute(AWSSchema.ASSOCIATION_POLICIES, attachedPoliciesArns);
            logger.ok("Added {0} attached policies to user {1}", attachedPoliciesArns.size(), user.userName());
        }

        return builder.build();
    }

    /**
     * Add a user to a group in AWS IAM.
     *
     * @param groupName The name of the group to which the user will be added
     * @param userName  The name of the user to add to the group
     */
    public void addUserToGroup(String groupName, String userName) {
        logger.ok("Adding user {0} to group {1}", userName, groupName);

        try {
            AddUserToGroupRequest request = AddUserToGroupRequest.builder()
                    .groupName(groupName)
                    .userName(userName)
                    .build();

            client.addUserToGroup(request);
            logger.ok("Successfully added user {0} to group {1}", userName, groupName);
        } catch (NoSuchEntityException e) {
            logger.error(e, "User or group does not exist: {0}", e.getMessage());
            throw new ConnectorException("User or group does not exist: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded when adding user to group: {0}", e.getMessage());
            throw new ConnectorException("AWS limit exceeded when adding user to group: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception adding user to group: {0}", e.getMessage());
            throw new ConnectorException("Error adding user to group: " + e.getMessage(), e);
        }
    }

    /**
     * Remove a user from a group in AWS IAM.
     *
     * @param groupName The name of the group from which the user will be removed
     * @param userName  The name of the user to remove from the group
     */
    public void removeUserFromGroup(String groupName, String userName) {
        logger.ok("Removing user {0} from group {1}", userName, groupName);

        try {
            RemoveUserFromGroupRequest request = RemoveUserFromGroupRequest.builder()
                    .groupName(groupName)
                    .userName(userName)
                    .build();

            client.removeUserFromGroup(request);
            logger.ok("Successfully removed user {0} from group {1}", userName, groupName);
        } catch (NoSuchEntityException e) {
            logger.error(e, "User or group does not exist: {0}", e.getMessage());
            throw new ConnectorException("User or group does not exist: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded when removing user from group: {0}", e.getMessage());
            throw new ConnectorException("AWS limit exceeded when removing user from group: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception removing user from group: {0}", e.getMessage());
            throw new ConnectorException("Error removing user from group: " + e.getMessage(), e);
        }
    }

    /**
     * Attaches a policy to a user.
     *
     * @param userName  The name of the user.
     * @param policyArn The ARN of the policy to attach.
     */
    public void attachUserPolicy(String userName, String policyArn) {
        logger.ok("Attaching policy {0} to user {1}", policyArn, userName);
        try {
            AttachUserPolicyRequest request = AttachUserPolicyRequest.builder()
                    .userName(userName)
                    .policyArn(policyArn)
                    .build();
            client.attachUserPolicy(request);
            logger.ok("Successfully attached policy {0} to user {1}", policyArn, userName);
        } catch (NoSuchEntityException e) {
            logger.error(e, "User or policy does not exist: {0}", e.getMessage());
            throw new ConnectorException("User or policy does not exist: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded when attaching policy to user: {0}", e.getMessage());
            throw new ConnectorException("AWS limit exceeded when attaching policy to user: " + e.getMessage(), e);
        } catch (InvalidInputException e) {
            logger.error(e, "Invalid input when attaching policy to user: {0}", e.getMessage());
            throw new InvalidAttributeValueException("Invalid input for attaching policy: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception attaching policy to user: {0}", e.getMessage());
            throw new ConnectorException("Error attaching policy to user: " + e.getMessage(), e);
        }
    }

    /**
     * Detaches a policy from a user.
     *
     * @param userName  The name of the user.
     * @param policyArn The ARN of the policy to detach.
     */
    public void detachUserPolicy(String userName, String policyArn) {
        logger.ok("Detaching policy {0} from user {1}", policyArn, userName);
        try {
            DetachUserPolicyRequest request = DetachUserPolicyRequest.builder()
                    .userName(userName)
                    .policyArn(policyArn)
                    .build();
            client.detachUserPolicy(request);
            logger.ok("Successfully detached policy {0} from user {1}", policyArn, userName);
        } catch (NoSuchEntityException e) {
            logger.error(e, "User or policy does not exist: {0}", e.getMessage());
            throw new ConnectorException("User or policy does not exist: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded when detaching policy from user: {0}", e.getMessage());
            throw new ConnectorException("AWS limit exceeded when detaching policy from user: " + e.getMessage(), e);
        } catch (InvalidInputException e) {
            logger.error(e, "Invalid input when detaching policy from user: {0}", e.getMessage());
            throw new InvalidAttributeValueException("Invalid input for detaching policy: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception detaching policy from user: {0}", e.getMessage());
            throw new ConnectorException("Error detaching policy from user: " + e.getMessage(), e);
        }
    }

    /**
     * Lists the ARNs of policies attached to a user.
     *
     * @param userName The name of the user.
     * @return A list of policy ARNs.
     */
    public List<String> getAttachedPolicies(String userName) {
        logger.ok("Listing attached policies for user {0}", userName);
        List<String> policyArns = new ArrayList<>();
        if (userName == null) return policyArns;
        String marker = null;
        boolean done = false;

        try {
            while (!done) {
                ListAttachedUserPoliciesRequest.Builder b = ListAttachedUserPoliciesRequest.builder().userName(userName);
                if (marker != null) {
                    b.marker(marker);
                }

                ListAttachedUserPoliciesResponse res = client.listAttachedUserPolicies(b.build());
                if (res == null) {
                    return policyArns;
                }

                if (res.hasAttachedPolicies()) {
                    for (AttachedPolicy policy : res.attachedPolicies()) {
                        policyArns.add(policy.policyArn());
                    }
                }

                if (res.isTruncated()) {
                    marker = res.marker();
                } else {
                    done = true;
                }
            }
            logger.ok("Found {0} attached policies for user {1}", policyArns.size(), userName);
            return policyArns;
        } catch (NoSuchEntityException e) {
            logger.error(e, "User does not exist when listing attached policies: {0}", e.getMessage());
            throw new ConnectorException("User does not exist: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception listing attached policies for user {0}: {1}", userName, e.getMessage());
            throw new ConnectorException("Error listing attached policies for user " + userName + ": " + e.getMessage(), e);
        }
    }

    protected List<AttachedPolicy> getPoliciesByUserName(String userName) {
        boolean done = false;
        String marker = null;
        List<AttachedPolicy> result = new ArrayList<>();
        if (userName == null) return result;
        while (!done) {
            ListAttachedUserPoliciesRequest.Builder b = ListAttachedUserPoliciesRequest.builder().userName(userName);
            if (marker != null) {
                b.marker(marker);
            }

            ListAttachedUserPoliciesResponse res = client.listAttachedUserPolicies(b.build());

            // Handle null response
            if (res == null) {
                logger.warn("Received null response from ListAttachedUserPolicies API for user: {0}", userName);
                break;
            }

            List<AttachedPolicy> policies = res.attachedPolicies();

            // Handle null policies list
            if (policies != null) {
                for (AttachedPolicy policy : policies) {
                    if (policy != null) {
                        result.add(policy);
                    }
                }
            }

            if (res.isTruncated() != null && res.isTruncated()) {
                marker = res.marker();
            } else {
                done = true;
            }
            ;
        }
        return result;
    }

    protected List<AccessKeyMetadata> getAccessKeysByUserName(String userName) {
        boolean done = false;
        String marker = null;
        List<AccessKeyMetadata> result = new ArrayList<>();
        if (userName == null) return result;
        while (!done) {

            ListAccessKeysRequest.Builder b = ListAccessKeysRequest.builder()
                    .userName(userName);
            if (marker != null) {
                b.marker(marker);
            }
            ListAccessKeysResponse res = client.listAccessKeys(b.build());

            // Handle null response
            if (res == null) {
                logger.warn("Received null response from ListAccessKeys API for user: {0}", userName);
                break;
            }

            List<AccessKeyMetadata> accessKeys = res.accessKeyMetadata();

            // Handle null accessKeys list
            if (accessKeys != null) {
                for (AccessKeyMetadata accessKey : accessKeys) {
                    if (accessKey != null) {
                        result.add(accessKey);
                    }
                }
            }

            if (res.isTruncated() != null && res.isTruncated()) {
                marker = res.marker();
            } else {
                done = true;
            }
            ;
        }

        logger.ok("Found {0} access keys to delete for user {1}", result.size(), userName);
        return result;
    }

    /**
     * Process changes to user groups
     *
     * @param username
     * @param delta
     */
    protected void processGroupsDelta(String username, AttributeDelta delta) {
        List<String> groupsToAdd = new ArrayList<>();
        List<String> groupsToRemove = new ArrayList<>();

        if (delta.getValuesToAdd() != null) {
            for (Object groupNameObj : delta.getValuesToAdd()) {
                String groupName = groupNameObj.toString();
                if (StringUtil.isBlank(groupName)) continue;
                try {
                    logger.ok("Delta: Adding user {0} to group (Name: {1})", username, groupName);
                    groupsToAdd.add(groupName);
                } catch (NoSuchEntityException e) {
                    logger.warn("Delta: Group with Name {0} not found. Cannot add user {1} to this group. Skipping.", groupName, username);
                } catch (Exception e) {
                    logger.error(e, "Delta: Error adding user {0} to group (Name: {1})", username, groupName);
                }
            }
        }

        if (delta.getValuesToRemove() != null) {
            for (Object groupValue : delta.getValuesToRemove()) {
                String groupName = groupValue.toString();
                if (StringUtil.isBlank(groupName)) continue;
                try {
                    logger.ok("Delta: Removing user {0} from group (Name: {1})", username, groupName);
                    groupsToRemove.add(groupName);
                } catch (NoSuchEntityException e) {
                    logger.warn("Delta: Group with Name {0} not found. Cannot remove user {1} from this group. Skipping.", groupName, username);
                } catch (Exception e) {
                    logger.error(e, "Delta: Error removing user {0} from group (Name: {1})", username, groupName);
                }
            }
        }

        if (delta.getValuesToReplace() != null) {
            List<Group> currentGroups = getGroupsByUserName(username);
            logger.ok("Delta: User {0} currently belongs to {1} groups", username, currentGroups.size());

            List<String> newGroupNames = new ArrayList<>();
            for (Object groupNameObj : delta.getValuesToReplace()) {
                String groupName = groupNameObj.toString();
                if (StringUtil.isNotBlank(groupName)) {
                    newGroupNames.add(groupName);
                }
            }

            // Determine groups to remove (current - new)
            for (Group currentGroup : currentGroups) {
                if (!newGroupNames.contains(currentGroup.groupName())) {
                    groupsToRemove.add(currentGroup.groupName());
                }
            }

            // Determine groups to add (new - current)
            for (String newGroupName : newGroupNames) {
                boolean found = false;
                for (Group currentGroup : currentGroups) {
                    if (newGroupName.equals(currentGroup.groupName())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    groupsToAdd.add(newGroupName);
                }
            }

        }

        try {
            // Remove user from groups they should no longer be in
            logger.ok("Delta: Will remove user {0} from {1} groups and add to {2} groups",
                    username, groupsToRemove.size(), groupsToAdd.size());

            for (String groupIdToRemove : groupsToRemove) {
                try {
                    Group group = getGroupByName(groupIdToRemove);
                    logger.ok("Delta: Removing user {0} from group {1} (Name: {2})", username, group.groupName(), groupIdToRemove);
                    removeUserFromGroup(group.groupName(), username);
                } catch (Exception e) {
                    logger.error(e, "Delta: Error removing user {0} from group(Name: {1})",
                            username, groupIdToRemove);
                }
            }

            // Add user to new groups
            for (String groupNameToAdd : groupsToAdd) {
                try {
                    Group group = getGroupByName(groupNameToAdd);
                    logger.ok("Delta: Adding user {0} to group {1} (Name: {2})", username, group.groupName(), groupNameToAdd);
                    addUserToGroup(group.groupName(), username);
                } catch (NoSuchEntityException e) {
                    logger.warn("Delta: Group with Name {0} not found. Cannot add user {1} to this group. Skipping.",
                            groupNameToAdd, username);
                } catch (Exception e) {
                    logger.error(e, "Delta: Error adding user {0} to group (Name: {1})",
                            username, groupNameToAdd);
                }
            }

            logger.ok("Delta: Successfully replaced group memberships for user {0}", username);

        } catch (Exception e) {
            logger.error(e, "Delta: Error during group membership replacement for user {0}: {1}",
                    username, e.getMessage());
            throw new ConnectorException("Error during group membership replacement: " + e.getMessage(), e);
        }
    }

    protected void processPoliciesDelta(String userName, AttributeDelta delta) {
        List<String> policiesToAdd = new ArrayList<>();
        List<String> policiesToRemove = new ArrayList<>();

        if (delta.getValuesToAdd() != null) {
            for (Object policyObj : delta.getValuesToAdd()) {
                if (policyObj instanceof String) {
                    String policyArn = (String) policyObj;
                    if (StringUtil.isNotBlank(policyArn)) {
                        logger.ok("Delta: Adding policy {0} to user {1}", policyArn, userName);
                        policiesToAdd.add(policyArn);
                    }
                }
            }
        }

        if (delta.getValuesToRemove() != null) {
            for (Object policyObj : delta.getValuesToRemove()) {
                if (policyObj instanceof String) {
                    String policyArn = (String) policyObj;
                    if (StringUtil.isNotBlank(policyArn)) {
                        logger.ok("Delta: Removing policy {0} from user {1}", policyArn, userName);
                        policiesToRemove.add(policyArn);
                    }
                }
            }
        }

        if (delta.getValuesToReplace() != null) {
            logger.ok("Delta: Replacing all policies for user {0} with {1} new policies", userName, delta.getValuesToReplace().size());

            try {
                // Get current attached policies
                List<String> currentPolicyArns = getAttachedPolicies(userName);
                logger.ok("Delta: User {0} currently has {1} attached policies", userName, currentPolicyArns.size());

                // Convert new policies to String list
                List<String> newPolicyArns = new ArrayList<>();
                for (Object policyObj : delta.getValuesToReplace()) {
                    if (policyObj instanceof String) {
                        String policyArn = (String) policyObj;
                        if (StringUtil.isNotBlank(policyArn)) {
                            newPolicyArns.add(policyArn);
                        }
                    }
                }

                // Determine policies to detach (current - new)
                for (String currentPolicy : currentPolicyArns) {
                    if (!newPolicyArns.contains(currentPolicy)) {
                        policiesToRemove.add(currentPolicy);
                    }
                }

                // Determine policies to attach (new - current)
                for (String newPolicy : newPolicyArns) {
                    if (!currentPolicyArns.contains(newPolicy)) {
                        policiesToAdd.add(newPolicy);
                    }
                }

            } catch (Exception e) {
                logger.error(e, "Delta: Error during policy replacement analysis for user {0}: {1}", userName, e.getMessage());
            }
        }

        try {
            // Detach policies that should be removed
            logger.ok("Delta: Will detach {0} policies and attach {1} policies for user {2}",
                    policiesToRemove.size(), policiesToAdd.size(), userName);

            for (String policyArnToRemove : policiesToRemove) {
                logger.ok("Delta: Detaching policy {0} from user {1}", policyArnToRemove, userName);
                try {
                    detachUserPolicy(userName, policyArnToRemove);
                } catch (Exception e) {
                    logger.error(e, "Delta: Error detaching policy {0} from user {1}", policyArnToRemove, userName);
                }
            }

            // Attach policies that should be added
            for (String policyArnToAdd : policiesToAdd) {
                logger.ok("Delta: Attaching policy {0} to user {1}", policyArnToAdd, userName);
                try {
                    attachUserPolicy(userName, policyArnToAdd);
                } catch (Exception e) {
                    logger.error(e, "Delta: Error attaching policy {0} to user {1}", policyArnToAdd, userName);
                }
            }

            logger.ok("Delta: Successfully processed policy changes for user {0}", userName);

        } catch (Exception e) {
            logger.error(e, "Delta: Error during policy management for user {0}: {1}", userName, e.getMessage());
            throw new ConnectorException("Error during policy management: " + e.getMessage(), e);
        }
    }
}
