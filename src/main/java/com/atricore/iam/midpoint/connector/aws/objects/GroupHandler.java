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

import java.util.*;
import java.util.function.Predicate;

/**
 * Handler for AWS IAM Group operations.
 */
public class GroupHandler extends AbstractHandler {

    private static final Log logger = Log.getLog(GroupHandler.class);

    public GroupHandler(IamClient client, AWSConfiguration config) {
        super(client,config);
    }

    /**
     * Creates a new AWS IAM group based on the provided attributes.
     *
     * @param objectClass      The object class (should be GROUP).
     * @param createAttributes The set of attributes for the new group.
     * @param options          Operation options.
     * @return The Uid of the newly created group.
     */
    public Uid createGroup(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
        logger.ok("createGroup called for ObjectClass: {0}", objectClass);

        if (!ObjectClass.GROUP.equals(objectClass)) {
            throw new IllegalArgumentException("Unsupported object class for create: " + objectClass);
        }

        String groupName = null;
        String path = null; // Optional path

        // Extract attributes
        for (Attribute attr : createAttributes) {
            if (Name.NAME.equals(attr.getName())) {
                groupName = AttributeUtil.getAsStringValue(attr);
            } else if (AWSSchema.ATTRIBUTE_PATH.equals(attr.getName())) {
                path = AttributeUtil.getAsStringValue(attr);
            }
            // Handle other attributes as needed
        }

        // Validate required attributes
        if (StringUtil.isBlank(groupName)) {
            throw new InvalidAttributeValueException("Missing required attribute: " + Name.NAME);
        }

        try {
            logger.ok("Attempting to create AWS IAM group with GroupName: {0}, Path: {1}", groupName, path);

            // Build the request
            CreateGroupRequest.Builder requestBuilder = CreateGroupRequest.builder()
                    .groupName(groupName);

            if (StringUtil.isNotBlank(path)) {
                requestBuilder.path(path);
            }

            // Execute the request
            CreateGroupResponse response = client.createGroup(requestBuilder.build());
            Group newGroup = response.group();

            if (newGroup == null || StringUtil.isBlank(newGroup.groupId())) {
                logger.error("CreateGroup call succeeded but returned null group or group with no GroupId for GroupName: {0}", groupName);
                throw new ConnectorException("Failed to retrieve GroupId for newly created group: " + groupName);
            }

            String groupId = newGroup.groupId();
            logger.ok("Successfully created AWS IAM group. GroupName: {0}, GroupId: {1}", groupName, groupId);

            // Handle initial policy attachments if provided
            Attribute policyAttachmentAttr = AttributeUtil.find(AWSSchema.ASSOCIATION_POLICIES, createAttributes);
            if (policyAttachmentAttr != null && policyAttachmentAttr.getValue() != null && !policyAttachmentAttr.getValue().isEmpty()) {
                try {
                    for (Object policyArnObj : policyAttachmentAttr.getValue()) {
                        String policyName = policyArnObj.toString();
                        if (StringUtil.isNotBlank(policyName)) {
                            attachGroupPolicy(groupName, policyName);
                            logger.ok("Attached policy {0} to newly created group {1}", policyName, groupName);
                        }
                    }
                } catch (Exception e) {
                    logger.error(e, "Error attaching policies to newly created group {0}: {1}", groupName, e.getMessage());
                    // Don't fail the whole creation if policy attachment fails
                }
            }

            return new Uid(groupId); // Return the AWS-generated GroupId as the Uid

        } catch (EntityAlreadyExistsException e) {
            logger.warn("Group with GroupName {0} already exists.", groupName);
            throw new AlreadyExistsException("Group with GroupName '" + groupName + "' already exists", e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded during group creation for GroupName: {0}", groupName);
            throw new ConnectorException("AWS limit exceeded during group creation: " + e.getMessage(), e);
        } catch (InvalidInputException e) {
            logger.error(e, "Invalid input provided for group creation (GroupName: {0}): {1}", groupName, e.getMessage());
            throw new InvalidAttributeValueException("Invalid input for group creation: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception during CreateGroup operation for GroupName {0}: {1}", groupName, e.getMessage());
            throw new ConnectorException("Error during CreateGroup operation: " + e.getMessage(), e);
        }
    }

    /**
     * Updates an AWS IAM group based on attribute deltas.
     *
     * @param uid           The Uid of the group to update.
     * @param modifications A set of attribute deltas specifying the changes.
     * @param options       Operation options.
     * @return An empty set if the update is successful.
     */
    public Set<AttributeDelta> updateDeltaGroup(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        logger.ok("updateDeltaGroup called for Uid: {0}, Modifications: {1}", uid, modifications);

        if (uid == null || StringUtil.isBlank(uid.getUidValue())) {
            throw new InvalidAttributeValueException("Uid cannot be null or empty for updateDelta operation");
        }

        if (modifications == null || modifications.isEmpty()) {
            logger.ok("No modifications provided for Uid: {0}", uid);
            return Collections.emptySet();
        }

        String groupId = uid.getUidValue();

        try {
            Group existingGroup = findGroupById(groupId);
            String currentGroupName = existingGroup.groupName();
            String groupNameForApiCall = currentGroupName; // This will be updated if group name changes

            UpdateGroupRequest.Builder updateGroupRequestBuilder = null;
            String newGroupNameHolder = null;

            // Pass 1: Handle Name and Path updates (attributes requiring UpdateGroup API)
            for (AttributeDelta delta : modifications) {
                if (delta == null) continue;
                String attributeName = delta.getName();

                if (Name.NAME.equals(attributeName)) {
                    List<Object> valuesToReplace = delta.getValuesToReplace();
                    if (valuesToReplace != null && !valuesToReplace.isEmpty()) {
                        String newGroupNameCandidate = valuesToReplace.get(0).toString();
                        if (StringUtil.isNotBlank(newGroupNameCandidate) && !newGroupNameCandidate.equals(currentGroupName)) {
                            if (updateGroupRequestBuilder == null) {
                                updateGroupRequestBuilder = UpdateGroupRequest.builder().groupName(currentGroupName);
                            }
                            updateGroupRequestBuilder.newGroupName(newGroupNameCandidate);
                            newGroupNameHolder = newGroupNameCandidate;
                            logger.ok("Delta: Preparing to update group name from {0} to {1}", currentGroupName, newGroupNameCandidate);
                        }
                    }
                } else if (AWSSchema.ATTRIBUTE_PATH.equals(attributeName)) {
                    List<Object> valuesToReplace = delta.getValuesToReplace();
                    if (valuesToReplace != null && !valuesToReplace.isEmpty()) {
                        String newPath = valuesToReplace.get(0).toString(); // Path can be empty string
                        if (updateGroupRequestBuilder == null) {
                            updateGroupRequestBuilder = UpdateGroupRequest.builder().groupName(currentGroupName);
                        }
                        updateGroupRequestBuilder.newPath(newPath);
                        logger.ok("Delta: Preparing to update path to \"{0}\" for group {1}", newPath, currentGroupName);
                    }
                } else if (AWSSchema.ATTRIBUTE_ARN.equals(attributeName)) {
                    logger.warn("Delta update for ARN is not supported as ARN is an identifier. Attribute: {0}", attributeName);
                }
            }

            // Execute UpdateGroup API call if there are changes to Name or Path
            if (updateGroupRequestBuilder != null) {
                try {
                    logger.info("Executing UpdateGroup API call for current group name: {0}", currentGroupName);
                    client.updateGroup(updateGroupRequestBuilder.build());
                    logger.ok("Successfully updated group attributes (Name/Path) for original group name: {0}", currentGroupName);
                    if (newGroupNameHolder != null) {
                        groupNameForApiCall = newGroupNameHolder; // Update group name for subsequent operations
                        logger.info("Group name was changed from {0} to {1}. Subsequent operations will use new group name.", currentGroupName, groupNameForApiCall);
                    }
                } catch (IamException e) {
                    logger.error(e, "AWS IAM Error during UpdateGroup (Name/Path) for group {0}: {1}", currentGroupName, e.getMessage());
                    throw new ConnectorException("Error updating group core attributes: " + e.getMessage(), e);
                }
            }

            // Pass 2: Handle associations (Policies)
            for (AttributeDelta delta : modifications) {
                if (delta == null) continue;
                String attributeName = delta.getName();

                if (AWSSchema.ASSOCIATION_POLICIES.equals(attributeName)) {

                    List<String> policiesToAdd = new ArrayList<>();
                    List<String> policiesToRemove = new ArrayList<>();

                    if (delta.getValuesToAdd() != null) {
                        for (Object policyObj : delta.getValuesToAdd()) {
                            if (policyObj instanceof String) {
                                String policyArn = (String) policyObj;
                                if (StringUtil.isNotBlank(policyArn)) {
                                    logger.ok("Delta: Adding policy {0} to group {1}", policyArn, groupNameForApiCall);
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
                                    logger.ok("Delta: Removing policy {0} from group {1}", policyArn, groupNameForApiCall);
                                    policiesToRemove.add(policyArn);
                                }
                            }
                        }
                    }

                    if (delta.getValuesToReplace() != null) {
                        logger.ok("Delta: Replacing all policies for group {0} with {1} new policies", groupNameForApiCall, delta.getValuesToReplace().size());

                        try {
                            // Get current attached policies
                            List<String> currentPolicyArns = getAttachedPolicies(groupNameForApiCall);
                            logger.ok("Delta: Group {0} currently has {1} attached policies", groupNameForApiCall, currentPolicyArns.size());

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
                            logger.error(e, "Delta: Error during policy replacement analysis for group {0}: {1}", groupNameForApiCall, e.getMessage());
                        }
                    }

                    try {
                        // Detach policies that should be removed
                        logger.ok("Delta: Will detach {0} policies and attach {1} policies for group {2}",
                                policiesToRemove.size(), policiesToAdd.size(), groupNameForApiCall);

                        for (String policyArnToRemove : policiesToRemove) {
                            logger.ok("Delta: Detaching policy {0} from group {1}", policyArnToRemove, groupNameForApiCall);
                            try {
                                detachGroupPolicy(groupNameForApiCall, policyArnToRemove);
                            } catch (Exception e) {
                                logger.error(e, "Delta: Error detaching policy {0} from group {1}", policyArnToRemove, groupNameForApiCall);
                            }
                        }

                        // Attach policies that should be added
                        for (String policyArnToAdd : policiesToAdd) {
                            logger.ok("Delta: Attaching policy {0} to group {1}", policyArnToAdd, groupNameForApiCall);
                            try {
                                attachGroupPolicy(groupNameForApiCall, policyArnToAdd);
                            } catch (Exception e) {
                                logger.error(e, "Delta: Error attaching policy {0} to group {1}", policyArnToAdd, groupNameForApiCall);
                            }
                        }

                        logger.ok("Delta: Successfully processed policy changes for group {0}", groupNameForApiCall);

                    } catch (Exception e) {
                        logger.error(e, "Delta: Error during policy management for group {0}: {1}", groupNameForApiCall, e.getMessage());
                        throw new ConnectorException("Error during policy management: " + e.getMessage(), e);
                    }

                } else if (!Name.NAME.equals(attributeName) &&
                        !AWSSchema.ATTRIBUTE_PATH.equals(attributeName) &&
                        !AWSSchema.ATTRIBUTE_ARN.equals(attributeName)) {
                    // This attribute was not Name, Path, ARN, or Policies
                    logger.warn("Delta update for attribute {0} is not explicitly handled by updateDeltaGroup.", attributeName);
                }
            }

            logger.ok("Successfully processed delta updates for group originally identified by GroupId: {0} (current/new group name: {1})", groupId, groupNameForApiCall);
            return Collections.emptySet(); // Standard practice to return empty set on success

        } catch (NoSuchEntityException e) {
            logger.error(e, "Group not found during updateDelta operation for GroupId: {0}", groupId);
            throw NoSuchEntityException.builder().cause(e).build();
        } catch (IamException e) {
            logger.error(e, "AWS IAM Exception during updateDeltaGroup for GroupId {0}: {1}", groupId, e.getMessage());
            throw new ConnectorException("AWS IAM Error during updateDeltaGroup: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Unexpected exception during updateDeltaGroup for GroupId {0}: {1}", groupId, e.getMessage());
            throw new ConnectorException("Unexpected error during updateDeltaGroup: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes an AWS IAM group.
     *
     * @param objectClass The object class (should be GROUP).
     * @param uid         The Uid of the group to delete.
     * @param options     Operation options.
     */
    public void deleteGroup(ObjectClass objectClass, Uid uid, OperationOptions options) {
        logger.ok("deleteGroup called for Uid {0}", uid);

        if (!ObjectClass.GROUP.equals(objectClass)) {
            throw new IllegalArgumentException("Unsupported object class for delete: " + objectClass);
        }

        if (uid == null || StringUtil.isBlank(uid.getUidValue())) {
            throw new InvalidAttributeValueException("Uid cannot be null or empty for delete operation");
        }

        String groupId = uid.getUidValue();

        try {
            // First, try to find the group by groupId to get the groupName
            logger.ok("Looking up for GroupId: {0}", groupId);
            Group group = findGroupById(groupId);
            String groupName = group.groupName();

            // TODO-IA : detach group from policies before delete

            // Build the delete request
            DeleteGroupRequest request = DeleteGroupRequest.builder().groupName(groupName).build();

            logger.ok("Attempting to delete AWS IAM group with GroupName: {0}", groupName);
            client.deleteGroup(request);
            logger.ok("Successfully deleted AWS IAM group with GroupName: {0}", groupName);

        } catch (NoSuchEntityException e) {
            // Group not found - this is not an error for delete
            logger.warn("Group not found during delete operation for GroupId: {0}", groupId);
            // No-op - idempotent delete
        } catch (DeleteConflictException e) {
            logger.error(e, "Delete conflict: The group has attached resources (GroupId: {0})", groupId);
            throw new ConnectorException("Cannot delete group. Group has attached resources: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded during group deletion for GroupId: {0}", groupId);
            throw new ConnectorException("AWS limit exceeded during group deletion: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception during DeleteGroup operation for GroupId {0}: {1}", groupId, e.getMessage());
            throw new ConnectorException("Error during DeleteGroup operation: " + e.getMessage(), e);
        }
    }

    /**
     * Searches for AWS IAM groups based on the provided filter.
     * Optimizes the search by using direct API calls when possible.
     *
     * @param handler The result handler.
     * @param query   The filter to apply to the search.
     * @param options Operation options.
     */
    public void searchGroups(ResultsHandler handler, Filter query, OperationOptions options) {
        logger.ok("Searching for groups with filter: {0}", query);

        if (query instanceof EqualsFilter equalsFilter) {
            Attribute attribute = equalsFilter.getAttribute();

            // Check if we're filtering by Name (GroupName) - we can use GetGroup API directly
            if (attribute instanceof Name) {
                Name name = (Name) attribute;
                String groupName = name.getNameValue();
                if (StringUtil.isNotBlank(groupName)) {
                    logger.ok("Searching for group with NAME: {0}", groupName);
                    Group group = getGroupByName(groupName);
                    if (group != null) {
                        handler.handle(buildConnectorObject(group, getAttachedPolicies(groupName)));
                    }
                    return;
                }
            } else if (attribute instanceof Uid) {
                logger.ok("Searching for group with UID, using as NAME: {0}", attribute);
                Uid uid = (Uid) attribute;
                String groupName = uid.getUidValue();
                if (StringUtil.isNotBlank(groupName)) {
                    logger.ok("Searching for group with NAME: {0}", groupName);
                    Group group = getGroupByName(groupName);
                    if (group != null) {
                        handler.handle(buildConnectorObject(group, getAttachedPolicies(groupName)));
                    }
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_AWS_ID)) {
                // Filtering by GroupId
                String groupId = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(groupId)) {
                    logger.ok("Searching for role with ID: {0}", groupId);
                    searchAllGroupsWithFilter(handler, role -> groupId.equals(role.groupId()), options);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_ARN)) {
                // Filtering by ARN
                String arn = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(arn)) {
                    logger.ok("Searching for group with ARN: {0}", arn);
                    searchAllGroupsWithFilter(handler, group -> arn.equals(group.arn()), options);
                    return;
                }
            } else if (attribute.getName().equals(AWSSchema.ATTRIBUTE_PATH)) {
                // Filtering by path
                String path = AttributeUtil.getStringValue(attribute);
                if (StringUtil.isNotBlank(path)) {
                    logger.ok("Searching for groups with Path: {0}", path);
                    searchGroupsWithPathPrefix(handler, path, options);
                    return;
                }
            }
        }

        // For all other filters or complex filters, we need to list all groups and filter locally
        logger.ok("Using full group listing with local filtering for query: {0}", query);
        searchAllGroupsWithFilter(handler, group -> {
            // For null filter, accept all groups. Implement some necessary filters
            return true; // Accept all groups when no filter is provided
        }, options);
    }

    /**
     * Lists all groups with a specific path prefix.
     * AWS API supports filtering by path prefix server-side.
     */
    private void searchGroupsWithPathPrefix(ResultsHandler handler, String pathPrefix, OperationOptions options) {
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
                ListGroupsRequest.Builder requestBuilder = ListGroupsRequest.builder()
                        .pathPrefix(pathPrefix);

                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                // Apply page size if specified
                if (pageSize != null) {
                    requestBuilder.maxItems(pageSize);
                }

                ListGroupsResponse response = client.listGroups(requestBuilder.build());

                // Handle null response
                if (response == null) {
                    logger.warn("Received null response from ListGroups API with path prefix: {0}", pathPrefix);
                    break;
                }

                List<Group> groups = response.groups();

                // Handle null groups list
                if (groups == null) {
                    groups = new ArrayList<>();
                }

                logger.ok("Retrieved {0} groups with path prefix: {1}", groups.size(), pathPrefix);

                for (Group group : groups) {
                    if (group != null) {
                        ConnectorObject co = buildConnectorObject(group, getAttachedPolicies(group.groupName()));
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
        } catch (IamException e) {
            logger.error(e, "IAM service exception during ListGroups operation: {0}", e.getMessage());
            throw new ConnectorException("IAM service exception during ListGroups: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Unexpected exception during ListGroups operation: {0}", e.getMessage());
            throw ConnectorException.wrap(e);
        }
    }

    /**
     * Lists all groups and applies a filter function to each group.
     * Only groups that pass the filter are converted to ConnectorObjects and passed to the handler.
     */
    private void searchAllGroupsWithFilter(ResultsHandler handler, Predicate<Group> filter, OperationOptions options) {
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
                ListGroupsRequest.Builder requestBuilder = ListGroupsRequest.builder();

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

                // Execute the request
                ListGroupsResponse response = client.listGroups(requestBuilder.build());

                // Handle null response
                if (response == null) {
                    logger.warn("Received null response from ListGroups API");
                    break;
                }

                List<Group> groups = response.groups();

                // Handle null groups list
                if (groups == null) {
                    groups = new ArrayList<>();
                }

                logger.ok("Retrieved {0} groups from AWS IAM", groups.size());

                for (Group group : groups) {
                    // Apply the filter
                    if (group != null && filter.test(group)) {
                        ConnectorObject co = buildConnectorObject(group, getAttachedPolicies(group.groupName()));
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
        } catch (IamException e) {
            logger.error(e, "IAM service exception during ListGroups operation: {0}", e.getMessage());
            throw new ConnectorException("IAM service exception during ListGroups: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Unexpected exception during ListGroups operation: {0}", e.getMessage());
            throw ConnectorException.wrap(e);
        }
    }

    /**
     * Builds a ConnectorObject from an AWS Group object.
     */
    protected ConnectorObject buildConnectorObject(Group group, List<String> attachedPoliciesArns) {
        if (group == null) {
            return null;
        }

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.GROUP);

        builder.setName(group.groupName());
        builder.setUid(group.groupName()); // Since AWS does not have a lookup by id
        builder.addAttribute(AWSSchema.ATTRIBUTE_ARN, group.arn());
        builder.addAttribute(AWSSchema.ATTRIBUTE_AWS_ID, group.groupId());

        if (group.path() != null) {
            builder.addAttribute(AWSSchema.ATTRIBUTE_PATH, group.path());
        }

        // Handle date attributes - convert to String format to avoid class cast issues
        if (group.createDate() != null) {
            String createDateStr = group.createDate().toString();
            builder.addAttribute(AWSSchema.ATTRIBUTE_CREATE_DATE, createDateStr);
        }

        // Add attached policy association
        if (attachedPoliciesArns != null && !attachedPoliciesArns.isEmpty()) {
            builder.addAttribute(AWSSchema.ASSOCIATION_POLICIES, attachedPoliciesArns);
            logger.ok("Added {0} attached policies to group {1}", attachedPoliciesArns.size(), group.groupName());
        }

        return builder.build();
    }

    /**
     * Attaches a policy to a group.
     *
     * @param groupName The name of the group.
     * @param policyArn The ARN of the policy to attach.
     */
    public void attachGroupPolicy(String groupName, String policyArn) {

        logger.ok("Attaching policy {0} to group {1}", policyArn, groupName);
        try {
            AttachGroupPolicyRequest request = AttachGroupPolicyRequest.builder()
                    .groupName(groupName)
                    .policyArn(policyArn)
                    .build();
            client.attachGroupPolicy(request);
            logger.ok("Successfully attached policy {0} to group {1}", policyArn, groupName);
        } catch (NoSuchEntityException e) {
            logger.error(e, "Group or policy does not exist: {0}", e.getMessage());
            throw new ConnectorException("Group or policy does not exist: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded when attaching policy to group: {0}", e.getMessage());
            throw new ConnectorException("AWS limit exceeded when attaching policy to group: " + e.getMessage(), e);
        } catch (InvalidInputException e) {
            logger.error(e, "Invalid input when attaching policy to group: {0}", e.getMessage());
            throw new InvalidAttributeValueException("Invalid input for attaching policy: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception attaching policy to group: {0}", e.getMessage());
            throw new ConnectorException("Error attaching policy to group: " + e.getMessage(), e);
        }
    }

    /**
     * Detaches a policy from a group.
     *
     * @param groupName The name of the group.
     * @param policyArn The ARN of the policy to detach.
     */
    public void detachGroupPolicy(String groupName, String policyArn) {
        logger.ok("Detaching policy {0} from group {1}", policyArn, groupName);
        try {
            DetachGroupPolicyRequest request = DetachGroupPolicyRequest.builder()
                    .groupName(groupName)
                    .policyArn(policyArn)
                    .build();
            client.detachGroupPolicy(request);
            logger.ok("Successfully detached policy {0} from group {1}", policyArn, groupName);
        } catch (NoSuchEntityException e) {
            logger.error(e, "Group or policy does not exist: {0}", e.getMessage());
            throw new ConnectorException("Group or policy does not exist: " + e.getMessage(), e);
        } catch (LimitExceededException e) {
            logger.error(e, "AWS limit exceeded when detaching policy from group: {0}", e.getMessage());
            throw new ConnectorException("AWS limit exceeded when detaching policy from group: " + e.getMessage(), e);
        } catch (InvalidInputException e) {
            logger.error(e, "Invalid input when detaching policy from group: {0}", e.getMessage());
            throw new InvalidAttributeValueException("Invalid input for detaching policy: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception detaching policy from group: {0}", e.getMessage());
            throw new ConnectorException("Error detaching policy from group: " + e.getMessage(), e);
        }
    }

    /**
     * Lists the ARNs of policies attached to a group.
     *
     * @param groupName The name of the group.
     * @return A list of policy ARNs.
     */
    public List<String> getAttachedPolicies(String groupName) {
        logger.ok("Listing attached policies for group {0}", groupName);
        List<String> policyArns = new ArrayList<>();
        String marker = null;
        boolean done = false;

        try {
            while (!done) {
                ListAttachedGroupPoliciesRequest.Builder requestBuilder = ListAttachedGroupPoliciesRequest.builder()
                        .groupName(groupName);
                if (marker != null) {
                    requestBuilder.marker(marker);
                }

                ListAttachedGroupPoliciesResponse response = client.listAttachedGroupPolicies(requestBuilder.build());
                if (response == null) {
                    logger.warn("Received null response from ListAttachedGroupPolicies API for group: {0}", groupName);
                    break;
                }
                if (response.hasAttachedPolicies()) {
                    List<AttachedPolicy> policies = response.attachedPolicies();
                    if (policies != null) {
                        for (AttachedPolicy policy : policies) {
                            if (policy != null && policy.policyArn() != null) {
                                policyArns.add(policy.policyArn());
                            }
                        }
                    }
                }

                if (response.isTruncated()) {
                    marker = response.marker();
                } else {
                    done = true;
                }
            }
            logger.ok("Found {0} attached policies for group {1}", policyArns.size(), groupName);
            return policyArns;
        } catch (NoSuchEntityException e) {
            logger.error(e, "Group does not exist when listing attached policies: {0}", e.getMessage());
            throw new ConnectorException("Group does not exist: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception listing attached policies for group {0}: {1}", groupName, e.getMessage());
            throw new ConnectorException("Error listing attached policies for group " + groupName + ": " + e.getMessage(), e);
        }
    }


}
