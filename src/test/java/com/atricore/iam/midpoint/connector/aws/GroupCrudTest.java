package com.atricore.iam.midpoint.connector.aws;

import com.atricore.iam.midpoint.connector.aws.objects.GroupHandler;
import com.atricore.iam.midpoint.connector.aws.objects.UserHandler;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.spi.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
public class GroupCrudTest {

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
                // Initialize handlers with our mock client
                this.userHandler = new UserHandler(this.client, this.configuration);
                this.groupHandler = new GroupHandler(this.client, this.configuration);
            }
        };

        connector.init(config);
    }

    /**
     * Test creating a group with minimal required attributes.
     */
    @Test
    public void testCreateGroup_Basic() {
        // Setup test data
        String groupName = "test-group";
        String groupId = "AGPATEST123456789";

        // Setup attributes for group creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(groupName));

        // Setup mock response
        Group createdGroup = Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .arn("arn:aws:iam::123456789012:group/" + groupName)
                .path("/")
                .build();

        CreateGroupResponse createGroupResponse = CreateGroupResponse.builder()
                .group(createdGroup)
                .build();

        when(mockClient.createGroup(any(CreateGroupRequest.class))).thenReturn(createGroupResponse);

        // Execute create
        Uid uid = connector.create(ObjectClass.GROUP, attributes, null);

        // Verify
        assertNotNull(uid);
        assertEquals(groupId, uid.getUidValue());

        // Verify the request sent to AWS
        ArgumentCaptor<CreateGroupRequest> requestCaptor = ArgumentCaptor.forClass(CreateGroupRequest.class);
        verify(mockClient).createGroup(requestCaptor.capture());

        CreateGroupRequest actualRequest = requestCaptor.getValue();
        assertEquals(groupName, actualRequest.groupName());
        // Path should be null or not set since we didn't provide it
        assertNull(actualRequest.path());
    }

    /**
     * Test creating a group with a custom path.
     */
    @Test
    public void testCreateGroup_WithPath() {
        // Setup test data
        String groupName = "dev-group";
        String groupId = "AGPATEST987654321";
        String path = "/development/";

        // Setup attributes for group creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(groupName));
        attributes.add(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, path));

        // Setup mock response
        Group createdGroup = Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .arn("arn:aws:iam::123456789012:group" + path + groupName)
                .path(path)
                .build();

        CreateGroupResponse createGroupResponse = CreateGroupResponse.builder()
                .group(createdGroup)
                .build();

        when(mockClient.createGroup(any(CreateGroupRequest.class))).thenReturn(createGroupResponse);

        // Execute create
        Uid uid = connector.create(ObjectClass.GROUP, attributes, null);

        // Verify
        assertNotNull(uid);
        assertEquals(groupId, uid.getUidValue());

        // Verify the request sent to AWS
        ArgumentCaptor<CreateGroupRequest> requestCaptor = ArgumentCaptor.forClass(CreateGroupRequest.class);
        verify(mockClient).createGroup(requestCaptor.capture());

        CreateGroupRequest actualRequest = requestCaptor.getValue();
        assertEquals(groupName, actualRequest.groupName());
        assertEquals(path, actualRequest.path());
    }

    /**
     * Test creating a group that already exists.
     */
    @Test
    public void testCreateGroup_AlreadyExists() {
        // Setup test data
        String groupName = "existing-group";

        // Setup attributes for group creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(groupName));

        // Setup mock to throw EntityAlreadyExistsException
        when(mockClient.createGroup(any(CreateGroupRequest.class)))
                .thenThrow(EntityAlreadyExistsException.builder().message("Group " + groupName + " already exists").build());

        // Execute and verify exception
        assertThrows(AlreadyExistsException.class, () -> {
            connector.create(ObjectClass.GROUP, attributes, null);
        });

        // Verify the request was sent to AWS
        verify(mockClient).createGroup(any(CreateGroupRequest.class));
    }

    /**
     * Test creating a group with invalid input.
     */
    @Test
    public void testCreateGroup_InvalidInput() {
        // Setup test data - missing required Name attribute
        Set<Attribute> attributes = new HashSet<>();
        // No Name attribute added

        // Execute and verify exception
        assertThrows(InvalidAttributeValueException.class, () -> {
            connector.create(ObjectClass.GROUP, attributes, null);
        });

        // Verify no request was sent to AWS
        verify(mockClient, never()).createGroup(any(CreateGroupRequest.class));
    }

    /**
     * Test creating a group with invalid characters.
     */
    @Test
    public void testCreateGroup_InvalidCharacters() {
        // Setup test data
        String invalidGroupName = "group@invalid"; // @ is not allowed in IAM group names

        // Setup attributes for group creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(invalidGroupName));

        // Setup mock to throw InvalidInputException
        when(mockClient.createGroup(any(CreateGroupRequest.class)))
                .thenThrow(InvalidInputException.builder().message("Invalid character in group name").build());

        // Execute and verify exception
        assertThrows(InvalidAttributeValueException.class, () -> {
            connector.create(ObjectClass.GROUP, attributes, null);
        });

        // Verify the request was sent to AWS
        verify(mockClient).createGroup(any(CreateGroupRequest.class));
    }

    /**
     * Test creating a group when AWS limit is exceeded.
     */
    @Test
    public void testCreateGroup_LimitExceeded() {
        // Setup test data
        String groupName = "limit-test-group";

        // Setup attributes for group creation
        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(groupName));

        // Setup mock to throw LimitExceededException
        when(mockClient.createGroup(any(CreateGroupRequest.class)))
                .thenThrow(LimitExceededException.builder().message("Limit exceeded").build());

        // Execute and verify exception
        Exception exception = assertThrows(ConnectorException.class, () -> {
            connector.create(ObjectClass.GROUP, attributes, null);
        });

        // Verify the underlying cause
        assertTrue(exception.getCause() instanceof LimitExceededException);

        // Verify the request was sent to AWS
        verify(mockClient).createGroup(any(CreateGroupRequest.class));
    }

    /**
     * Test deleting a group by Uid.
     */
    @Test
    public void testDeleteGroup_ByUid() {
        // Setup test data
        String groupId = "AGPATEST123456789";
        String groupName = "delete-test-group";
        Uid uid = new Uid(groupId);

        // Setup mock response for the lookup (needed to convert GroupId to GroupName)
        Group group = Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .build();

        ListGroupsResponse listGroupsResponse = ListGroupsResponse.builder()
                .groups(List.of(group))
                .isTruncated(false)
                .build();

        when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(listGroupsResponse);

        // Setup mock response for the delete
        DeleteGroupResponse deleteGroupResponse = DeleteGroupResponse.builder().build(); // AWS returns an empty response
        when(mockClient.deleteGroup(any(DeleteGroupRequest.class))).thenReturn(deleteGroupResponse);

        // Execute delete
        connector.delete(ObjectClass.GROUP, uid, null);

        // Verify the request sent to AWS
        ArgumentCaptor<DeleteGroupRequest> requestCaptor = ArgumentCaptor.forClass(DeleteGroupRequest.class);
        verify(mockClient).deleteGroup(requestCaptor.capture());

        DeleteGroupRequest actualRequest = requestCaptor.getValue();
        assertEquals(groupName, actualRequest.groupName());
    }

    /**
     * Test deleting a group that doesn't exist.
     */
    @Test
    public void testDeleteGroup_GroupNotFound() {
        // Setup test data
        String groupId = "AGPATESTNONEXISTENT";
        Uid uid = new Uid(groupId);

        // Setup mock response for the lookup (no groups found)
        ListGroupsResponse emptyResult = ListGroupsResponse.builder()
                .groups(List.of())
                .isTruncated(false)
                .build();

        when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(emptyResult);

        // Execute delete - should not throw an exception, just log a warning
        connector.delete(ObjectClass.GROUP, uid, null);

    }

    /**
     * Test updating a group's name.
     */
    @Test
    public void testUpdateGroup_GroupName() {
        // Setup test data
        String groupId = "AGPATEST123456789";
        Uid uid = new Uid(groupId);
        String groupName = "existing-test-group";
        String newGroupName = "updated-test-group";
        String newPath = "/updated/path/";

        // Setup attributes for update
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(new AttributeDeltaBuilder()
                .setName(Name.NAME) // Standard ICF name for the object's name
                .addValueToReplace(newGroupName)
                .build());
        modifications.add(new AttributeDeltaBuilder()
                .setName(AWSSchema.ATTRIBUTE_PATH)
                .addValueToReplace(newPath)
                .build());
        
        // Create group object for the mock responses
        Group existingGroup = Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .path("/original/path/")
                .build();

        // Mock ListGroups for the handler to find the current group name by ID
        ListGroupsResponse listGroupsResponse = ListGroupsResponse.builder().groups(List.of(existingGroup)).isTruncated(false).build();
        lenient().when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(listGroupsResponse);


        // Setup mock response for the update
        UpdateGroupResponse updateGroupResponse = UpdateGroupResponse.builder().build();
        when(mockClient.updateGroup(any(UpdateGroupRequest.class))).thenReturn(updateGroupResponse);

        // After update, we need to get the group again to return updated Uid
        Group updatedGroup = Group.builder()
                .groupId(groupId)
                .groupName(newGroupName)
                .path(newPath)
                .build();

        // Execute update
        Set<AttributeDelta> result = connector.updateDelta(ObjectClass.GROUP, uid, modifications, new OperationOptionsBuilder().build());

        // Verify
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Expected no unapplied modifications on successful update.");

        verify(mockClient).listGroups(any(ListGroupsRequest.class)); // For findGroupNameByGroupId

        // Verify updateGroup was called
        verify(mockClient).updateGroup(any(UpdateGroupRequest.class));

        // Verify the update request sent to AWS
        ArgumentCaptor<UpdateGroupRequest> requestCaptor = ArgumentCaptor.forClass(UpdateGroupRequest.class);
        verify(mockClient).updateGroup(requestCaptor.capture());

        UpdateGroupRequest actualRequest = requestCaptor.getValue();
        assertEquals(groupName, actualRequest.groupName());
        assertEquals(newGroupName, actualRequest.newGroupName());
        assertEquals(newPath, actualRequest.newPath());
    }

    /**
     * Test updating a group's path.
     */
    @Test
    public void testUpdateGroup_Path() {
        // Setup test data
        String groupId = "AGPATEST123456789";
        Uid uid = new Uid(groupId);
        String groupName = "update-test-group";

        // Updated data
        String newPath = "/updated/path/";

        // Setup attributes for update
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(new AttributeDeltaBuilder()
                .setName(AWSSchema.ATTRIBUTE_PATH)
                .addValueToReplace(newPath)
                .build());
        
        // Create group object for the mock responses
        Group existingGroup = Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .path("/original/path/")
                .build();

        // Mock ListGroups for the handler to find the current group name by ID
        ListGroupsResponse listGroupsResponse = ListGroupsResponse.builder().groups(List.of(existingGroup)).isTruncated(false).build();
        lenient().when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(listGroupsResponse);

        // Setup mock response for the update
        UpdateGroupResponse updateGroupResponse = UpdateGroupResponse.builder().build();
        when(mockClient.updateGroup(any(UpdateGroupRequest.class))).thenReturn(updateGroupResponse);

        // After update, we need to get the group again to return updated Uid
        Group updatedGroup = Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .path(newPath)
                .build();

        // Execute update
        Set<AttributeDelta> result = connector.updateDelta(ObjectClass.GROUP, uid, modifications, new OperationOptionsBuilder().build());

        // Verify
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Expected no unapplied modifications on successful update.");

        verify(mockClient).listGroups(any(ListGroupsRequest.class)); // For findGroupNameByGroupId

        // Verify updateGroup was called
        verify(mockClient).updateGroup(any(UpdateGroupRequest.class));

        // Verify the update request sent to AWS
        ArgumentCaptor<UpdateGroupRequest> requestCaptor = ArgumentCaptor.forClass(UpdateGroupRequest.class);
        verify(mockClient).updateGroup(requestCaptor.capture());

        UpdateGroupRequest actualRequest = requestCaptor.getValue();
        assertEquals(groupName, actualRequest.groupName());
        assertNull(actualRequest.newGroupName()); // No group name change
        assertEquals(newPath, actualRequest.newPath()); // Path was changed
    }
    
    /**
     * Test updating a group that doesn't exist.
     */
    @Test
    public void testUpdateGroup_GroupNotFound() {
        // Setup test data
        String groupId = "AGPATESTNONEXISTENT";
        Uid uid = new Uid(groupId);

        // Setup attributes for update
        Set<AttributeDelta> modifications = new HashSet<>();
        modifications.add(new AttributeDeltaBuilder()
                .setName(AWSSchema.ATTRIBUTE_PATH)
                .addValueToReplace("/new/path/")
                .build());


        // Setup mock for findGroupById to throw NoSuchEntityException
        NoSuchEntityException noSuchEntityException = NoSuchEntityException.builder()
                .message("Group not found for " + groupId)
                .build();
        
        // Setup mock for listGroups (empty result for findGroupNameByGroupId)
        ListGroupsResponse emptyResult = ListGroupsResponse.builder()
                .groups(List.of())
                .isTruncated(false)
                .build();

        when(mockClient.listGroups(any(ListGroupsRequest.class)))
                .thenReturn(emptyResult); // This will cause findGroupById to throw the exception
                
        // Execute and verify exception
        Exception exception = assertThrows(NoSuchEntityException.class, () -> {
            connector.updateDelta(ObjectClass.GROUP, uid, modifications, new OperationOptionsBuilder().build());
        });

        verify(mockClient).listGroups(any(ListGroupsRequest.class));
        verify(mockClient, never()).updateGroup(any(UpdateGroupRequest.class));
    }

    /**
     * Test deleting a group when the group has attached resources.
     */
    @Test
    public void testDeleteGroup_DeleteConflict() {
        // Setup test data
        String groupId = "AGPATESTCONFLICT";
        String groupName = "conflict-group";
        Uid uid = new Uid(groupId);

        // Setup mock response for the lookup
        Group group = Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .build();

        ListGroupsResponse listGroupsResponse = ListGroupsResponse.builder()
                .groups(List.of(group))
                .isTruncated(false)
                .build();

        when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(listGroupsResponse);

        // Setup mock to throw DeleteConflictException
        when(mockClient.deleteGroup(any(DeleteGroupRequest.class)))
                .thenThrow(DeleteConflictException.builder().message("Group has attached resources").build());

        // Execute and verify exception
        Exception exception = assertThrows(ConnectorException.class, () -> {
            connector.delete(ObjectClass.GROUP, uid, null);
        });

        // Verify the request was sent to AWS
        verify(mockClient).deleteGroup(any(DeleteGroupRequest.class));
    }
}