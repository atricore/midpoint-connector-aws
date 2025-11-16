package com.atricore.iam.midpoint.connector.aws;

import com.atricore.iam.midpoint.connector.aws.objects.GroupHandler;
import com.atricore.iam.midpoint.connector.aws.objects.UserHandler;
import org.identityconnectors.common.security.GuardedString;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class GroupSearchTest {

    @Mock
    private IamClient mockClient;

    @Mock
    private ResultsHandler mockHandler;

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
                // Initialize handlers
                this.userHandler = new UserHandler(this.client, this.configuration);
                this.groupHandler = new GroupHandler(this.client, this.configuration);
            }
        };

        connector.init(config);

    }

    @Test
    public void testSearchByGroupName_DirectApiCall() {
        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data
        String testGroupName = "test-group";
        Group testGroup = Group.builder()
                .groupId("AGPATEST123456789")
                .groupName(testGroupName)
                .arn("arn:aws:iam::123456789012:group/test-group")
                .path("/")
                .createDate(Instant.now())
                .build();

        // Mock list of users in the group
        List<User> usersInGroup = new ArrayList<>();

        // Setup mock responses
        GetGroupResponse getGroupResponse = GetGroupResponse.builder()
                .group(testGroup)
                .users(usersInGroup)
                .build();

        when(mockClient.getGroup(any(GetGroupRequest.class))).thenReturn(getGroupResponse);

        // Create a filter for groupName
        Filter nameFilter = new EqualsFilter(new Name(testGroupName));

        // Execute search
        connector.executeQuery(ObjectClass.GROUP, nameFilter, mockHandler, null);

        // Verify GetGroup API was called with correct groupName
        ArgumentCaptor<GetGroupRequest> requestCaptor = ArgumentCaptor.forClass(GetGroupRequest.class);
        verify(mockClient).getGroup(requestCaptor.capture());
        assertEquals(testGroupName, requestCaptor.getValue().groupName());

        // Verify handler was called once with a connector object
        verify(mockHandler, times(1)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByGroupName_GroupNotFound() {
        // Setup test data
        String testGroupName = "non-existent-group";

        // Setup mock to throw NoSuchEntityException
        when(mockClient.getGroup(any(GetGroupRequest.class)))
                .thenThrow(NoSuchEntityException.builder().message("Group not found").build());

        // Create a filter for groupName
        Filter nameFilter = new EqualsFilter(new Name(testGroupName));

        // Execute search
        connector.executeQuery(ObjectClass.GROUP, nameFilter, mockHandler, null);

        // Verify GetGroup API was called
        verify(mockClient).getGroup(any(GetGroupRequest.class));

        // Verify handler was never called (no results)
        verify(mockHandler, never()).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchAllGroups_NoFilter() {
        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data
        List<Group> testGroups = new ArrayList<>();
        testGroups.add(Group.builder()
                .groupId("AGPATEST123456789")
                .groupName("group1")
                .arn("arn:aws:iam::123456789012:group/group1")
                .path("/")
                .createDate(Instant.now())
                .build());

        testGroups.add(Group.builder()
                .groupId("AGPATEST987654321")
                .groupName("group2")
                .arn("arn:aws:iam::123456789012:group/group2")
                .path("/")
                .createDate(Instant.now())
                .build());

        // Setup mock responses
        ListGroupsResponse listGroupsResponse = ListGroupsResponse.builder()
                .groups(testGroups)
                .isTruncated(false)
                .build();

        when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(listGroupsResponse);

        ListAttachedGroupPoliciesResponse emptyPoliciesResponse = ListAttachedGroupPoliciesResponse.builder()
                .attachedPolicies(new ArrayList<>())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedGroupPolicies(any(ListAttachedGroupPoliciesRequest.class)))
                .thenReturn(emptyPoliciesResponse);

        // Execute search with null filter (list all)
        connector.executeQuery(ObjectClass.GROUP, null, mockHandler, null);

        // Verify ListGroups API was called
        verify(mockClient).listGroups(any(ListGroupsRequest.class));

        // Verify handler was called twice (once for each group)
        verify(mockHandler, times(2)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchAllGroups_WithPagination() {
        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data for first page
        List<Group> firstPageGroups = new ArrayList<>();
        firstPageGroups.add(Group.builder()
                .groupName("group1")
                .groupId("AGPATEST111111111")
                .build());

        // Setup test data for second page
        List<Group> secondPageGroups = new ArrayList<>();
        secondPageGroups.add(Group.builder()
                .groupName("group2")
                .groupId("AGPATEST222222222")
                .build());

        // Setup mock responses
        ListGroupsResponse firstPageResponse = ListGroupsResponse.builder()
                .groups(firstPageGroups)
                .isTruncated(true)
                .marker("marker-token")
                .build();

        ListGroupsResponse secondPageResponse = ListGroupsResponse.builder()
                .groups(secondPageGroups)
                .isTruncated(false)
                .build();

        // First call returns first page, second call returns second page
        when(mockClient.listGroups(any(ListGroupsRequest.class)))
                .thenReturn(firstPageResponse)
                .thenReturn(secondPageResponse);

        // Default stubbing for listAttachedGroupPolicies to avoid NPE in buildConnectorObject
        ListAttachedGroupPoliciesResponse emptyPoliciesResponse = ListAttachedGroupPoliciesResponse.builder()
                .attachedPolicies(new ArrayList<>())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedGroupPolicies(any(ListAttachedGroupPoliciesRequest.class)))
                .thenReturn(emptyPoliciesResponse);

        // Execute search
        connector.executeQuery(ObjectClass.GROUP, null, mockHandler, null);

        // Verify ListGroups API was called twice (once for each page)
        verify(mockClient, times(2)).listGroups(any(ListGroupsRequest.class));

        // Verify second call included the marker token
        ArgumentCaptor<ListGroupsRequest> requestCaptor = ArgumentCaptor.forClass(ListGroupsRequest.class);
        verify(mockClient, times(2)).listGroups(requestCaptor.capture());
        assertEquals("marker-token", requestCaptor.getAllValues().get(1).marker());

        // Verify handler was called twice (once for each group)
        verify(mockHandler, times(2)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchWithNonNameFilter_FallsBackToListAll() {
        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data
        Group testGroup = Group.builder()
                .groupName("group1")
                .groupId("AGPATEST123456789") // Setting GroupId to match our filter
                .arn("arn:aws:iam::123456789012:group/group1")
                .path("/")
                .build();

        // Mock GetGroup response (connector uses getGroup when searching by UID)
        GetGroupResponse getGroupResponse = GetGroupResponse.builder()
                .group(testGroup)
                .build();
        when(mockClient.getGroup(any(GetGroupRequest.class))).thenReturn(getGroupResponse);

        // Default stubbing for listAttachedGroupPolicies to avoid NPE in buildConnectorObject
        ListAttachedGroupPoliciesResponse emptyPoliciesResponse = ListAttachedGroupPoliciesResponse.builder()
                .attachedPolicies(new ArrayList<>())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedGroupPolicies(any(ListAttachedGroupPoliciesRequest.class)))
                .thenReturn(emptyPoliciesResponse);

        // Create a filter for a non-Name attribute (UID)
        Filter uidFilter = new EqualsFilter(new Uid("AGPATEST123456789"));

        // Execute search
        connector.executeQuery(ObjectClass.GROUP, uidFilter, mockHandler, null);

        // Verify GetGroup API was called (connector uses getGroup for UID search)
        verify(mockClient).getGroup(any(GetGroupRequest.class));

        // Verify handler was called once
        verify(mockHandler, times(1)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByPath() {
        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data
        String testPath = "/test-path/";
        List<Group> testGroups = new ArrayList<>();
        testGroups.add(Group.builder()
                .groupId("AGPATEST123456789")
                .groupName("group1")
                .arn("arn:aws:iam::123456789012:group/test-path/group1")
                .path(testPath)
                .createDate(Instant.now())
                .build());

        // Setup mock responses
        ListGroupsResponse listGroupsResponse = ListGroupsResponse.builder()
                .groups(testGroups)
                .isTruncated(false)
                .build();

        when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(listGroupsResponse);

        // Create a filter for path
        Filter pathFilter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, testPath));

        // Execute search
        connector.executeQuery(ObjectClass.GROUP, pathFilter, mockHandler, null);

        // Verify ListGroups API was called with pathPrefix
        ArgumentCaptor<ListGroupsRequest> requestCaptor = ArgumentCaptor.forClass(ListGroupsRequest.class);
        verify(mockClient).listGroups(requestCaptor.capture());
        assertEquals(testPath, requestCaptor.getValue().pathPrefix());

        // Verify handler was called once
        verify(mockHandler, times(1)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchInterruption() {
        // Setup handler to return false after first item (to stop processing)
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(false);

        // Setup test data
        List<Group> testGroups = new ArrayList<>();
        testGroups.add(Group.builder()
                .groupId("AGPATEST123456789")
                .groupName("group1")
                .build());
        testGroups.add(Group.builder()
                .groupId("AGPATEST987654321")
                .groupName("group2")
                .build());

        // Setup mock responses
        ListGroupsResponse listGroupsResponse = ListGroupsResponse.builder()
                .groups(testGroups)
                .isTruncated(false)
                .build();

        when(mockClient.listGroups(any(ListGroupsRequest.class))).thenReturn(listGroupsResponse);

        // Execute search with null filter (list all)
        connector.executeQuery(ObjectClass.GROUP, null, mockHandler, null);

        // Verify handler was called only once despite having 2 groups
        // (processing stopped after handler returned false)
        verify(mockHandler, times(1)).handle(any(ConnectorObject.class));
    }
}
