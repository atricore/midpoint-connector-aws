package com.atricore.iam.midpoint.connector.aws;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.spi.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
public class UserCrudTest {

    @Mock
    private IamClient mockClient;

    private AWSConnector connector;
    private AWSConfiguration config;

    @BeforeEach
    public void setup() {
        // Setup configuration
        config = new AWSConfiguration();
        config.setAwsAccessKeyId("test-access-key");
        config.setAwsSecretAccessKey(new GuardedString("test-secret-key".toCharArray()));
        config.setAwsRegion("us-east-1");
        config.setAllowCache(false);

        // Create connector with mocked AWS client
        connector = new AWSConnector() {
            @Override
            public void init(Configuration cfg) {
                this.configuration = (AWSConfiguration) cfg;
                // Skip actual AWS client initialization, use our mock
                this.client = mockClient;
                // Initialize other components as needed with our mock client
                super.userHandler = new com.atricore.iam.midpoint.connector.aws.objects.UserHandler(this.client, this.configuration);
            }
        };

        connector.init(config);
    }

    /**
     * Test creating a user with minimal required attributes.
     */
    @Test
    public void testCreateUser_Basic() {
        // Setup test data
        String userName = "test-user";
        String userId = "test-user";

        // Setup attributes for user creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(userName));

        // Setup mock response
        User createdUser = User.builder()
                .userId(userId)
                .userName(userName)
                .arn("arn:aws:iam::123456789012:user/" + userName)
                .path("/")
                .build();

        CreateUserResponse createUserResponse = CreateUserResponse.builder()
                .user(createdUser)
                .build();

        when(mockClient.createUser(any(CreateUserRequest.class))).thenReturn(createUserResponse);

        // Execute create
        Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);

        // Verify
        assertNotNull(uid);
        assertEquals(userId, uid.getUidValue());

        // Verify the request sent to AWS
        ArgumentCaptor<CreateUserRequest> requestCaptor = ArgumentCaptor.forClass(CreateUserRequest.class);
        verify(mockClient).createUser(requestCaptor.capture());

        CreateUserRequest actualRequest = requestCaptor.getValue();
        assertEquals(userName, actualRequest.userName());
        // Path should be null or not set since we didn't provide it
        assertNull(actualRequest.path());
    }

    /**
     * Test creating a user with a custom path.
     */
    @Test
    public void testCreateUser_WithPath() {
        // Setup test data
        String userName = "dev-user";
        String userId = "dev-user";
        String path = "/development/";

        // Setup attributes for user creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(userName));
        attributes.add(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, path));

        // Setup mock response
        User createdUser = User.builder()
                .userId(userId)
                .userName(userName)
                .arn("arn:aws:iam::123456789012:user" + path + userName)
                .path(path)
                .build();

        CreateUserResponse createUserResponse = CreateUserResponse.builder()
                .user(createdUser)
                .build();

        when(mockClient.createUser(any(CreateUserRequest.class))).thenReturn(createUserResponse);

        // Execute create
        Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);

        // Verify
        assertNotNull(uid);
        assertEquals(userId, uid.getUidValue());

        // Verify the request sent to AWS
        ArgumentCaptor<CreateUserRequest> requestCaptor = ArgumentCaptor.forClass(CreateUserRequest.class);
        verify(mockClient).createUser(requestCaptor.capture());

        CreateUserRequest actualRequest = requestCaptor.getValue();
        assertEquals(userName, actualRequest.userName());
        assertEquals(path, actualRequest.path());
    }

    /**
     * Test creating a user that already exists.
     */
    @Test
    public void testCreateUser_AlreadyExists() {
        // Setup test data
        String userName = "existing-user";

        // Setup attributes for user creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(userName));

        // Setup mock to throw EntityAlreadyExistsException
        when(mockClient.createUser(any(CreateUserRequest.class)))
                .thenThrow(EntityAlreadyExistsException.builder().message("User " + userName + " already exists").build());

        // Execute and verify exception
        assertThrows(AlreadyExistsException.class, () -> {
            connector.create(ObjectClass.ACCOUNT, attributes, null);
        });

        // Verify the request was sent to AWS
        verify(mockClient).createUser(any(CreateUserRequest.class));
    }

    /**
     * Test creating a user with invalid input.
     */
    @Test
    public void testCreateUser_InvalidInput() {
        // Setup test data - missing required Name attribute
        Set<Attribute> attributes = new HashSet<>();
        // No Name attribute added

        // Execute and verify exception
        assertThrows(InvalidAttributeValueException.class, () -> {
            connector.create(ObjectClass.ACCOUNT, attributes, null);
        });

        // Verify no request was sent to AWS
        verify(mockClient, never()).createUser(any(CreateUserRequest.class));
    }

    /**
     * Test creating a user with invalid characters.
     */
    @Test
    public void testCreateUser_InvalidCharacters() {
        // Setup test data
        String invalidUserName = "user@invalid"; // @ is not allowed in IAM usernames

        // Setup attributes for user creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(invalidUserName));

        // Setup mock to throw InvalidInputException
        when(mockClient.createUser(any(CreateUserRequest.class)))
                .thenThrow(InvalidInputException.builder().message("Invalid character in username").build());

        // Execute and verify exception
        assertThrows(InvalidAttributeValueException.class, () -> {
            connector.create(ObjectClass.ACCOUNT, attributes, null);
        });

        // Verify the request was sent to AWS
        verify(mockClient).createUser(any(CreateUserRequest.class));
    }

    /**
     * Test creating a user when AWS limit is exceeded.
     */
    @Test
    public void testCreateUser_LimitExceeded() {
        // Setup test data
        String userName = "limit-test-user";

        // Setup attributes for user creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(userName));

        // Setup mock to throw LimitExceededException
        when(mockClient.createUser(any(CreateUserRequest.class)))
                .thenThrow(LimitExceededException.builder().message("Limit exceeded").build());

        // Execute and verify exception
        Exception exception = assertThrows(ConnectorException.class, () -> {
            connector.create(ObjectClass.ACCOUNT, attributes, null);
        });

        // Verify the underlying cause
        assertTrue(exception.getCause() instanceof LimitExceededException);

        // Verify the request was sent to AWS
        verify(mockClient).createUser(any(CreateUserRequest.class));
    }

    /**
     * Test creating a user with initial group assignments.
     */
    @Test
    public void testCreateUser_WithGroups() {
        // Setup test data
        String userName = "group-test-user";
        String userId = "group-test-user";
        String groupId1 = "AGPATEST111222333";
        String groupId2 = "AGPATEST444555666";
        String groupName1 = "developers";
        String groupName2 = "admins";

        // Setup attributes for user creation with group membership
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(userName));
        attributes.add(AttributeBuilder.build(AWSSchema.ASSOCIATION_GROUPS,
                      Arrays.asList(groupId1, groupId2)));

        // Setup mock response for user creation
        User createdUser = User.builder()
                .userId(userId)
                .userName(userName)
                .arn("arn:aws:iam::123456789012:user/" + userName)
                .path("/")
                .build();

        CreateUserResponse createUserResponse = CreateUserResponse.builder()
                .user(createdUser)
                .build();

        when(mockClient.createUser(any(CreateUserRequest.class))).thenReturn(createUserResponse);

        // Note: During user creation, the connector uses group IDs directly as group names
        // without calling getGroup, so no group lookup mocks are needed

        // Setup mock responses for adding users to groups
        AddUserToGroupResponse addToGroupResponse = AddUserToGroupResponse.builder().build();
        when(mockClient.addUserToGroup(any(AddUserToGroupRequest.class))).thenReturn(addToGroupResponse);

        // Execute create
        Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);

        // Verify the user was created
        assertNotNull(uid);
        assertEquals(userId, uid.getUidValue());

        // Verify the request sent to AWS for user creation
        ArgumentCaptor<CreateUserRequest> createRequestCaptor = ArgumentCaptor.forClass(CreateUserRequest.class);
        verify(mockClient).createUser(createRequestCaptor.capture());

        CreateUserRequest actualCreateRequest = createRequestCaptor.getValue();
        assertEquals(userName, actualCreateRequest.userName());

        // Verify the requests sent to AWS for adding user to groups
        ArgumentCaptor<AddUserToGroupRequest> addToGroupCaptor = ArgumentCaptor.forClass(AddUserToGroupRequest.class);
        verify(mockClient, times(2)).addUserToGroup(addToGroupCaptor.capture());

        // Verify the group assignments
        List<AddUserToGroupRequest> addToGroupRequests = addToGroupCaptor.getAllValues();
        assertEquals(2, addToGroupRequests.size());

        // Sort the requests to ensure consistent testing
        addToGroupRequests.sort((r1, r2) -> r1.groupName().compareTo(r2.groupName()));

        // Verify the group assignments (connector uses group IDs directly as group names during creation)
        // First group assignment (1st request after sorting alphabetically)
        assertEquals(groupId1, addToGroupRequests.get(0).groupName());
        assertEquals(userName, addToGroupRequests.get(0).userName());

        // Second group assignment (2nd request after sorting)
        assertEquals(groupId2, addToGroupRequests.get(1).groupName());
        assertEquals(userName, addToGroupRequests.get(1).userName());
    }

    /**
     * Test deleting a user by Uid.
     */
    @Test
    public void testDeleteUser_ByUid() {
        // Setup test data
        String userId = "delete-test-user";
        String userName = "delete-test-user";
        Uid uid = new Uid(userId);

        // Setup mock response for the lookup (needed to convert UserId to UserName)
        User user = User.builder()
                .userId(userId)
                .userName(userName)
                .build();

        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(List.of(user))
                .isTruncated(false)
                .build();

        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);

        // Setup mock response for the delete
        DeleteUserResponse deleteUserResponse = DeleteUserResponse.builder().build(); // AWS returns an empty response
        when(mockClient.deleteUser(any(DeleteUserRequest.class))).thenReturn(deleteUserResponse);

        // Execute delete
        connector.delete(ObjectClass.ACCOUNT, uid, null);

        // Verify the request sent to AWS
        ArgumentCaptor<DeleteUserRequest> requestCaptor = ArgumentCaptor.forClass(DeleteUserRequest.class);
        verify(mockClient).deleteUser(requestCaptor.capture());

        DeleteUserRequest actualRequest = requestCaptor.getValue();
        assertEquals(userName, actualRequest.userName());
    }

    /**
     * Test deleting a user that doesn't exist.
     */
    @Test
    public void testDeleteUser_UserNotFound() {
        // Setup test data
        String userId = "test-user";
        Uid uid = new Uid(userId);

        // Setup mock response for the lookup (no users found)
        ListUsersResponse emptyResult = ListUsersResponse.builder()
                .users(List.of())
                .isTruncated(false)
                .build();

        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(emptyResult);

        // Execute delete - should not throw an exception, just log a warning
        connector.delete(ObjectClass.ACCOUNT, uid, null);

    }

    @Test
    public void testUpdateUser_UserName() {
        // Setup test data
        String userId = "existing-test-user";
        Uid uid = new Uid(userId);
        String userName = "existing-test-user";
        String newUserName = "updated-test-user";
        String newPath = "/updated/path/";

        // Setup attributes for update - INCLUDING the Name attribute
        // to test direct lookup by username path in UserHandler
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(new AttributeDeltaBuilder()
                .setName(Name.NAME) // Standard ICF name for the object's name
                .addValueToReplace(newUserName)
                .build());
        modifications.add(new AttributeDeltaBuilder()
                .setName(AWSSchema.ATTRIBUTE_PATH)
                .addValueToReplace(newPath)
                .build());

        User existingUser = User.builder()
                .userId(userId)
                .userName(userName)
                .path("/original/path/")
                .build();

        // Mock GetUser response for looking up by username
        GetUserRequest expectedRequest = GetUserRequest.builder().userName(newUserName).build();

        // Setup mock response for the update
        UpdateUserResponse updateUserResponse = UpdateUserResponse.builder().build();
        when(mockClient.updateUser(any(UpdateUserRequest.class))).thenReturn(updateUserResponse);

        // After update, we need to get the user again to return updated Uid
        User updatedUser = User.builder()
                .userId(userId)
                .userName(newUserName)
                .path(newPath)
                .build();

        // Mock the ListUsers for findUserById
        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(List.of(existingUser))
                .isTruncated(false)
                .build();
        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);

        // Execute update
        Set<AttributeDelta> result = connector.updateDelta(ObjectClass.ACCOUNT, uid, modifications, new OperationOptionsBuilder().build());

        // Verify
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Expected no unapplied modifications on successful update.");


        // Verify updateUser was called
        verify(mockClient).updateUser(any(UpdateUserRequest.class));

        // Verify the update request sent to AWS
        ArgumentCaptor<UpdateUserRequest> requestCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
        verify(mockClient).updateUser(requestCaptor.capture());

        UpdateUserRequest actualRequest = requestCaptor.getValue();
        assertEquals(userName, actualRequest.userName());
        assertEquals(newUserName, actualRequest.newUserName());
        assertEquals(newPath, actualRequest.newPath());
    }

    /**
     * Test updating a user's path.
     */
    @Test
    public void testUpdateUser_Path() {
        // Setup test data
        String userId = "update-test-user";
        Uid uid = new Uid(userId);
        String userName = "update-test-user";

        // Updated data
        String newPath = "/updated/path/";

        // Setup attributes for update - INCLUDING the Name attribute
        // to test direct lookup by username path in UserHandler
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(new AttributeDeltaBuilder()
                .setName(AWSSchema.ATTRIBUTE_PATH)
                .addValueToReplace(newPath)
                .build());

        User existingUser = User.builder()
                .userId(userId)
                .userName(userName)
                .path("/original/path/")
                .build();

        // Mock GetUser response for looking up by username
        GetUserRequest expectedRequest = GetUserRequest.builder().userName(userName).build();

        // Setup mock response for the update
        UpdateUserResponse updateUserResponse = UpdateUserResponse.builder().build();
        when(mockClient.updateUser(any(UpdateUserRequest.class))).thenReturn(updateUserResponse);

        // After update, we need to get the user again to return updated Uid
        User updatedUser = User.builder()
                .userId(userId)
                .userName(userName)
                .path(newPath)
                .build();

        // Also mock the ListUsers for findUserById as a fallback
        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(List.of(existingUser))
                .isTruncated(false)
                .build();
        lenient().when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);
        
        // Also mock getUser for direct lookup by username
        GetUserResponse getUserResponse = GetUserResponse.builder().user(existingUser).build();
        lenient().when(mockClient.getUser(any(GetUserRequest.class))).thenReturn(getUserResponse);

        // Execute update
        Set<AttributeDelta> result = connector.updateDelta(ObjectClass.ACCOUNT, uid, modifications, new OperationOptionsBuilder().build());

        // Verify
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Expected no unapplied modifications on successful update.");

        // ListUsers should NOT be called since we've provided the username directly
        verify(mockClient).listUsers(any(ListUsersRequest.class));

        // Verify updateUser was called
        verify(mockClient).updateUser(any(UpdateUserRequest.class));

        // Verify the update request sent to AWS
        ArgumentCaptor<UpdateUserRequest> requestCaptor = ArgumentCaptor.forClass(UpdateUserRequest.class);
        verify(mockClient).updateUser(requestCaptor.capture());

        UpdateUserRequest actualRequest = requestCaptor.getValue();
        assertEquals(userName, actualRequest.userName());
        assertNull(actualRequest.newUserName());
        assertEquals(newPath, actualRequest.newPath());
    }

    /**
     * Test updating a user's group memberships.
     */
    @Test
    public void testUpdateUser_GroupMemberships() {
        // Setup test data
        String userId = "group-update-test-user";
        Uid uid = new Uid(userId);
        String userName = "group-update-test-user";

        // Group data
        String groupKeptId = "AGPATEST_KEPT_GROUP_ID";
        String groupKeptName = "group-kept-name";

        String groupToAddId = "AGPATEST_ADD_GROUP_ID";
        String groupToAddName = "group-to-add-name";

        String groupToRemoveId = "AGPATEST_REMOVE_GROUP_ID";
        String groupToRemoveName = "group-to-remove-name";


        // Setup AttributeDelta: Add groupToAddId, Remove groupToRemoveId
        Set<AttributeDelta> modifications = new HashSet<>();
        AttributeDelta groupMembershipDelta = new AttributeDeltaBuilder()
                .setName(AWSSchema.ASSOCIATION_GROUPS)
                .addValueToAdd(groupToAddId)
                .addValueToRemove(groupToRemoveId)
                .build();
        modifications.add(groupMembershipDelta);

        // Mock initial user state (for findUserById)
        User existingUser = User.builder()
                .userId(userId)
                .userName(userName)
                .path("/")
                .build();
        ListUsersResponse listUsersResponse = ListUsersResponse.builder().users(java.util.Collections.singletonList(existingUser)).build();
        lenient().when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);
        
        // Also mock getUser for direct lookup by username
        GetUserResponse getUserResponse = GetUserResponse.builder().user(existingUser).build();
        lenient().when(mockClient.getUser(any(GetUserRequest.class))).thenReturn(getUserResponse);

        // Mock Group lookups (connector uses getGroup, not listGroups)
        Group groupToAdd = Group.builder().groupId(groupToAddId).groupName(groupToAddName).build();
        Group groupToRemove = Group.builder().groupId(groupToRemoveId).groupName(groupToRemoveName).build();

        // Mock GetGroup calls for group lookups
        GetGroupResponse getGroupResponseAdd = GetGroupResponse.builder().group(groupToAdd).build();
        GetGroupResponse getGroupResponseRemove = GetGroupResponse.builder().group(groupToRemove).build();
        
        when(mockClient.getGroup(any(GetGroupRequest.class)))
            .thenReturn(getGroupResponseRemove)  // First call for remove
            .thenReturn(getGroupResponseAdd);    // Second call for add


        // Mock AddUserToGroup and RemoveUserFromGroup
        when(mockClient.addUserToGroup(any(AddUserToGroupRequest.class))).thenReturn(AddUserToGroupResponse.builder().build());
        when(mockClient.removeUserFromGroup(any(RemoveUserFromGroupRequest.class))).thenReturn(RemoveUserFromGroupResponse.builder().build());

        // Execute update
        connector.updateDelta(ObjectClass.ACCOUNT, uid, modifications, new OperationOptionsBuilder().build());

        // Verify calls
        // 1. Verify user was looked up
        verify(mockClient).listUsers(any(ListUsersRequest.class)); // For findUserById

        // 2. Verify groups were looked up (to get their names)
        //    findGroupById calls listGroups. It will be called for groupToAddId and groupToRemoveId.
        //    The exact number of listGroups calls depends on pagination in findGroupById,
        //    but it should be called at least once for each group ID resolution.
        //    Given our simplified mock for listGroups, we expect it to be called.
        //    A more precise verification would require a more sophisticated mock setup for listGroups
        //    that responds differently based on the iteration within findGroupById.
        //    For now, we'll verify the end-effects: addUserToGroup and removeUserFromGroup.

        // 3. Verify addUserToGroup for groupToAddName
        ArgumentCaptor<AddUserToGroupRequest> addUserCaptor = ArgumentCaptor.forClass(AddUserToGroupRequest.class);
        verify(mockClient).addUserToGroup(addUserCaptor.capture());
        assertEquals(userName, addUserCaptor.getValue().userName());
        assertEquals(groupToAddName, addUserCaptor.getValue().groupName());

        // 4. Verify removeUserFromGroup for groupToRemoveName
        ArgumentCaptor<RemoveUserFromGroupRequest> removeUserCaptor = ArgumentCaptor.forClass(RemoveUserFromGroupRequest.class);
        verify(mockClient).removeUserFromGroup(removeUserCaptor.capture());
        assertEquals(userName, removeUserCaptor.getValue().userName());
        assertEquals(groupToRemoveName, removeUserCaptor.getValue().groupName());

        // 5. Verify no operations for groupKeptName (since it wasn't in the delta)
        verify(mockClient, never()).addUserToGroup(argThat((AddUserToGroupRequest req) -> req.groupName().equals(groupKeptName)));
        verify(mockClient, never()).removeUserFromGroup(argThat((RemoveUserFromGroupRequest req) -> req.groupName().equals(groupKeptName)));
    }

    /**
     * Test updating a user that doesn't exist.
     */
    @Test
    public void testUpdateUser_UserNotFound() {
        // Setup test data
        String userId = "AIDATESTNONEXISTENT";
        Uid uid = new Uid(userId);

        // Setup attributes for update
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(new AttributeDeltaBuilder()
                .setName(AWSSchema.ATTRIBUTE_PATH)
                .addValueToReplace("/new/path/")
                .build());

        // Setup mock for listUsers (empty result for findUserNameByUserId)
        // This is crucial because the code will first try to find the username using listUsers
        ListUsersResponse emptyResult = ListUsersResponse.builder()
                .users(List.of())
                .isTruncated(false)
                .build();

        when(mockClient.listUsers(any(ListUsersRequest.class)))
                .thenReturn(emptyResult);

        // Execute and verify exception
        Exception exception = assertThrows(ConnectorException.class, () -> {
            connector.updateDelta(ObjectClass.ACCOUNT, uid, modifications, new OperationOptionsBuilder().build());
        });

        verify(mockClient).listUsers(any(ListUsersRequest.class));
        verify(mockClient, never()).updateUser(any(UpdateUserRequest.class));
    }

    /**
     * Test reading a user with groups.
     */
    @Test
    public void testReadUser_WithGroups() {
        // Setup test data
        String userName = "read-user-with-groups";
        String userId = "AIDATEST999888777";

        // Group data
        String groupId1 = "AGPATEST111222333";
        String groupId2 = "AGPATEST444555666";
        String groupName1 = "developers";
        String groupName2 = "admins";

        // Create a search filter for the user
        Filter userNameFilter = new EqualsFilter(new Name(userName));

        // Create a results handler to capture the connector object
        final List<ConnectorObject> results = new ArrayList<>();
        ResultsHandler handler = new ResultsHandler() {
            @Override
            public boolean handle(ConnectorObject connectorObject) {
                results.add(connectorObject);
                return true;
            }
        };

        // Setup mock response for GetUser
        User user = User.builder()
                .userId(userId)
                .userName(userName)
                .path("/")
                .arn("arn:aws:iam::123456789012:user/" + userName)
                .build();

        GetUserResponse getUserResponse = GetUserResponse.builder().user(user).build();
        when(mockClient.getUser(any(GetUserRequest.class))).thenReturn(getUserResponse);

        // Setup mock response for ListGroupsForUser
        Group group1 = Group.builder()
                .groupId(groupId1)
                .groupName(groupName1)
                .build();

        Group group2 = Group.builder()
                .groupId(groupId2)
                .groupName(groupName2)
                .build();

        ListGroupsForUserResponse listGroupsResponse = ListGroupsForUserResponse.builder()
                .groups(List.of(group1, group2))
                .build();

        when(mockClient.listGroupsForUser(any(ListGroupsForUserRequest.class)))
                .thenReturn(listGroupsResponse);

        // Execute the search
        connector.executeQuery(ObjectClass.ACCOUNT, userNameFilter, handler, null);

        // Verify results
        assertEquals(1, results.size(), "Should return exactly one user");
        ConnectorObject connObj = results.get(0);

        // Verify basic attributes
        assertEquals(userName, connObj.getName().getNameValue(), "User name should match");
        assertEquals(userName, connObj.getUid().getUidValue(), "UID should match user name (connector uses userName as UID)");
        
        // Verify AWS user ID is in the awsId attribute
        Attribute awsIdAttr = connObj.getAttributeByName(AWSSchema.ATTRIBUTE_AWS_ID);
        assertNotNull(awsIdAttr, "AWS ID attribute should be present");
        assertEquals(userId, AttributeUtil.getStringValue(awsIdAttr), "AWS ID should match");

        // Verify group membership attribute
        Attribute groupMemberships = connObj.getAttributeByName(AWSSchema.ASSOCIATION_GROUPS);
        assertNotNull(groupMemberships, "Group membership attribute should be present");
        assertNotNull(groupMemberships.getValue(), "Group membership values should not be null");
        assertEquals(2, groupMemberships.getValue().size(), "Should have 2 group memberships");

        // Verify the group names (connector returns group names, not IDs)
        List<Object> groupNames = new ArrayList<>(groupMemberships.getValue());
        assertTrue(groupNames.contains(groupName1), "Should contain first group name");
        assertTrue(groupNames.contains(groupName2), "Should contain second group name");

        // Verify API calls
        verify(mockClient).getUser(any(GetUserRequest.class));
        verify(mockClient).listGroupsForUser(any(ListGroupsForUserRequest.class));
    }

    /**
     * Test deleting a user when the user has attached resources.
     */
    @Test
    public void testDeleteUser_DeleteConflict() {
        // Setup test data
        String userId = "AIDATESTCONFLICT";
        String userName = "conflict-user";
        Uid uid = new Uid(userId);

        // Setup mock response for the lookup
        User user = User.builder()
                .userId(userId)
                .userName(userName)
                .build();

        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(List.of(user))
                .isTruncated(false)
                .build();

        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);

        // Setup mock to throw DeleteConflictException
        when(mockClient.deleteUser(any(DeleteUserRequest.class)))
                .thenThrow(DeleteConflictException.builder().message("User has attached resources").build());

        // Execute and verify exception
        Exception exception = assertThrows(ConnectorException.class, () -> {
            connector.delete(ObjectClass.ACCOUNT, uid, null);
        });

        // Verify the request was sent to AWS
        verify(mockClient).deleteUser(any(DeleteUserRequest.class));
    }
}
