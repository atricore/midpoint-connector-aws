package com.atricore.iam.midpoint.connector.aws.objects;

import com.atricore.iam.midpoint.connector.aws.AWSConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import java.util.ArrayList;
import java.util.List;

public class AbstractHandler {
    
    private static final Log logger = Log.getLog(AbstractHandler.class);
    
    protected AWSConfiguration config;
    protected IamClient client;

    public AbstractHandler(IamClient client, AWSConfiguration config) {
        this.config = config;
        this.client = client;
    }

    protected User getUserByUserName(String userName) {
        try {
            GetUserResponse res = client.getUser(GetUserRequest.builder().userName(userName).build());
            return res != null ? res.user() : null;
        } catch (NoSuchEntityException e) {
            logger.info("User not found for userName: {0}", userName);
            return null;
        } catch (Exception e) {
            logger.error(e, "Error searching for user by userName {0}: {1}", userName, e.getMessage());
            throw new ConnectorException("Error searching for user by userName " + userName + " : " + e.getMessage(), e);
        }
    }

    protected Group getGroupByName(String name) {
        try {
            GetGroupResponse res = client.getGroup(GetGroupRequest.builder().groupName(name).build());
            return res != null ? res.group() : null;
        } catch (NoSuchEntityException e) {
            logger.info("Group not found for name: {0}", name);
            return null;
        } catch (Exception e) {
            logger.error(e, "Error searching for group by name {0}: {1}", name, e.getMessage());
            throw new ConnectorException("Error searching for group by nameame " + name + " : " + e.getMessage(), e);
        }
    }

    /**
     * Helper method to find a user's UserName by UserId. Very expensive since AWS does not have a lookup by ID.
     *
     * @param userId The UserId to lookup.
     * @return The UserName if found, or null if not found.
     */
    protected User findUserById(String userId) {
        logger.info("Finding user by id: " + userId);

        // In AWS IAM, we need to list users and filter by userId since there's no direct API to get user by ID
        String marker = null;
        boolean done = false;

        while (!done) {

            ListUsersRequest.Builder requestBuilder = ListUsersRequest.builder();
            if (marker != null) {
                requestBuilder.marker(marker);
            }

            try {
                ListUsersResponse response = client.listUsers(requestBuilder.build());

                // Handle null response
                if (response == null) {
                    logger.warn("Received null response from ListUsers API");
                    break;
                }

                List<User> users = response.users();

                // Handle null users list
                if (users != null) {
                    // Search for user with matching userId
                    for (User user : users) {
                        if (user != null && userId.equals(user.userId())) {
                            return user;
                        }
                    }
                }

                // Check if there are more results
                if (response.isTruncated() != null && response.isTruncated()) {
                    marker = response.marker();
                } else {
                    done = true;
                }
            } catch (Exception e) {
                logger.error(e, "Error searching user by id {0}: {1}", userId, e.getMessage());
                throw new ConnectorException("Error searching user by id " + userId + " : " + e.getMessage(), e);
            }
        }

        // User not found
        throw NoSuchEntityException.builder().message("User not found for id " + userId).build();
    }

    /**
     * List users in a specific group.
     *
     * @param groupName The name of the group whose users will be listed
     * @return List of users in the group
     */
    public List<User> getUsersInGroup(String groupName) {
        logger.ok("Listing users in group {0}", groupName);

        try {
            GetGroupRequest request = GetGroupRequest.builder()
                    .groupName(groupName)
                    .build();

            GetGroupResponse response = client.getGroup(request);
            logger.ok("Successfully retrieved {0} users from group {1}",
                    response.users().size(), groupName);

            return response.users();
        } catch (NoSuchEntityException e) {
            logger.error(e, "Group does not exist: {0}", e.getMessage());
            throw new ConnectorException("Group does not exist: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e, "Exception listing users in group: {0}", e.getMessage());
            throw new ConnectorException("Error listing users in group: " + e.getMessage(), e);
        }
    }

    /**
     * Get a list of group names that are assigned to a user
     *
     * @param userName
     * @return list of group names
     */
    protected List<String> getGroupNamesByUserName(String userName) {
        return getGroupsByUserName(userName).stream().map(Group::groupName).toList();
    }

    /**
     * Get a list of groups that are assigned to a user
     *
     * @param username
     * @return list of groups
     */
    protected List<Group> getGroupsByUserName(String username) {
        boolean done = false;
        String marker = null;
        List<Group> result = new ArrayList<>();
        if (username == null) return result;
        while (!done) {
            ListGroupsForUserRequest.Builder b = ListGroupsForUserRequest.builder().userName(username);
            if (marker != null) {
                b.marker(marker);
            }

            ListGroupsForUserResponse res = client.listGroupsForUser(b.build());
            if (res == null) {
                logger.warn("Received null response from ListGroupsForUser API for user: {0}", username);
                break;
            }

            List<Group> groups = res.groups();

            // Handle null groups list
            if (groups != null) {
                for (Group group : groups) {
                    if (group != null) {
                        result.add(group);
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


    /**
     * Helper method to find a group's GroupName by GroupId.
     *
     * @param groupId The GroupId to lookup.
     * @return The GroupName if found, or null if not found.
     */
    protected Group findGroupById(String groupId) {
        logger.info("Finding group by id: " + groupId);

        // In AWS IAM, we need to list groups and filter by groupId since there's no direct API to get group by ID
        String marker = null;
        boolean done = false;

        while (!done) {
            ListGroupsRequest.Builder requestBuilder = ListGroupsRequest.builder();
            if (marker != null) {
                requestBuilder.marker(marker);
            }

            try {
                ListGroupsResponse response = client.listGroups(requestBuilder.build());

                // Handle null response
                if (response == null) {
                    logger.warn("Received null response from ListGroups API");
                    break;
                }

                List<Group> groups = response.groups();

                // Handle null groups list
                if (groups != null) {
                    // Search for group with matching groupId
                    for (Group group : groups) {
                        if (group != null && groupId.equals(group.groupId())) {
                            return group;
                        }
                    }
                }

                // Check if there are more results
                if (response.isTruncated() != null && response.isTruncated()) {
                    marker = response.marker();
                } else {
                    done = true;
                }
            } catch (Exception e) {
                logger.error(e, "Exception during group lookup by id {0}: {1}", groupId, e.getMessage());
                throw new ConnectorException("Error during group lookup for id " + groupId + " : " + e.getMessage(), e);
            }
        }

        // Group not found
        throw NoSuchEntityException.builder().message("Group not found for id " + groupId).build();
    }
}
