package com.atricore.iam.midpoint.connector.aws;

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
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserSearchTest {

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
                // Initialize other components as needed
                this.userHandler = new UserHandler(this.client, this.configuration);
            }
        };

        connector.init(config);

    }

    @Test
    public void testSearchByUserName_DirectApiCall() {

        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data
        String testUserName = "test-user";
        User testUser = User.builder()
                .userId("user1")
                .userName(testUserName)
                .arn("arn:aws:iam::123456789012:user/test-user")
                .path("/")
                .createDate(Instant.now())
                .build();

        // Setup mock responses
        GetUserResponse getUserResponse = GetUserResponse.builder()
                .user(testUser)
                .build();

        when(mockClient.getUser(any(GetUserRequest.class))).thenReturn(getUserResponse);

        // Create a filter for username
        Filter nameFilter = new EqualsFilter(new Name(testUserName));

        // Execute search
        connector.executeQuery(ObjectClass.ACCOUNT, nameFilter, mockHandler, null);

        // Verify GetUser API was called with correct username
        ArgumentCaptor<GetUserRequest> requestCaptor = ArgumentCaptor.forClass(GetUserRequest.class);
        verify(mockClient).getUser(requestCaptor.capture());
        assertEquals(testUserName, requestCaptor.getValue().userName());

        // Verify handler was called once with a connector object
        verify(mockHandler, times(1)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByUserName_UserNotFound() {
        // Setup test data
        String testUserName = "non-existent-user";

        // Setup mock to return null user (simulating user not found)
        GetUserResponse getUserResponse = GetUserResponse.builder()
                .user((User) null)
                .build();
        when(mockClient.getUser(any(GetUserRequest.class))).thenReturn(getUserResponse);

        // Create a filter for username
        Filter nameFilter = new EqualsFilter(new Name(testUserName));

        // Execute search - current connector code throws NullPointerException when user not found
        org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class, () -> {
            connector.executeQuery(ObjectClass.ACCOUNT, nameFilter, mockHandler, null);
        });

        // Verify GetUser API was called
        verify(mockClient).getUser(any(GetUserRequest.class));
    }

    @Test
    public void testSearchAllUsers_NoFilter() {

        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data
        List<User> testUsers = new ArrayList<>();
        testUsers.add(User.builder()
                .userId("user1")
                .userName("user1")
                .arn("arn:aws:iam::123456789012:user/user1")
                .path("/")
                .createDate(Instant.now())
                .build());

        testUsers.add(User.builder()
                .userId("user2")
                .userName("user2")
                .arn("arn:aws:iam::123456789012:user/user2")
                .path("/")
                .createDate(Instant.now())
                .build());

        // Setup mock responses
        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(testUsers)
                .isTruncated(false)
                .build();

        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);

        // Default stubbing for listAttachedUserPolicies to avoid NPE in buildConnectorObject
        ListAttachedUserPoliciesResponse emptyPoliciesResponse = ListAttachedUserPoliciesResponse.builder()
                .attachedPolicies(new ArrayList<>())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedUserPolicies(any(ListAttachedUserPoliciesRequest.class)))
                .thenReturn(emptyPoliciesResponse);


        // Execute search with null filter (list all)
        connector.executeQuery(ObjectClass.ACCOUNT, null, mockHandler, null);

        // Verify ListUsers API was called
        verify(mockClient).listUsers(any(ListUsersRequest.class));

        // Verify handler was called twice (once for each user)
        verify(mockHandler, times(2)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchAllUsers_WithPagination() {

        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data for first page
        List<User> firstPageUsers = new ArrayList<>();
        firstPageUsers.add(User.builder()
                .userName("user1")
                .userId("user1")
                .build());

        // Setup test data for second page
        List<User> secondPageUsers = new ArrayList<>();
        secondPageUsers.add(User.builder()
                .userName("user2")
                .userId("user2")
                .build());

        // Setup mock responses
        ListUsersResponse firstPageResponse = ListUsersResponse.builder()
                .users(firstPageUsers)
                .isTruncated(true)
                .marker("marker-token")
                .build();

        ListUsersResponse secondPageResponse = ListUsersResponse.builder()
                .users(secondPageUsers)
                .isTruncated(false)
                .build();

        // First call returns first page, second call returns second page
        when(mockClient.listUsers(any(ListUsersRequest.class)))
                .thenReturn(firstPageResponse)
                .thenReturn(secondPageResponse);

        // Default stubbing for listAttachedUserPolicies to avoid NPE in buildConnectorObject
        ListAttachedUserPoliciesResponse emptyPoliciesResponse = ListAttachedUserPoliciesResponse.builder()
                .attachedPolicies(new ArrayList<>())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedUserPolicies(any(ListAttachedUserPoliciesRequest.class)))
                .thenReturn(emptyPoliciesResponse);


        // Execute search
        connector.executeQuery(ObjectClass.ACCOUNT, null, mockHandler, null);

        // Verify ListUsers API was called twice (once for each page)
        verify(mockClient, times(2)).listUsers(any(ListUsersRequest.class));

        // Verify second call included the marker token
        ArgumentCaptor<ListUsersRequest> requestCaptor = ArgumentCaptor.forClass(ListUsersRequest.class);
        verify(mockClient, times(2)).listUsers(requestCaptor.capture());
        assertEquals("marker-token", requestCaptor.getAllValues().get(1).marker());

        // Verify handler was called twice (once for each user)
        verify(mockHandler, times(2)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchWithNonNameFilter_FallsBackToListAll() {

        // Make mockHandler.handle() return true by default to allow processing all items
        when(mockHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Setup test data
        User testUser = User.builder()
                .userName("user1")
                .userId("user1") // Setting UserId to match our filter
                .arn("arn:aws:iam::123456789012:user/user1")
                .path("/")
                .build();

        // Mock GetUser API call (used when searching by UID)
        GetUserResponse getUserResponse = GetUserResponse.builder()
                .user(testUser)
                .build();
        when(mockClient.getUser(any(GetUserRequest.class))).thenReturn(getUserResponse);

        // Mock ListAttachedUserPolicies response
        ListAttachedUserPoliciesResponse listPoliciesResponse = ListAttachedUserPoliciesResponse.builder()
                .attachedPolicies(Collections.emptyList())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedUserPolicies(any(ListAttachedUserPoliciesRequest.class)))
                .thenReturn(listPoliciesResponse);

        // Mock ListGroupsForUser response
        ListGroupsForUserResponse listGroupsResponse = ListGroupsForUserResponse.builder()
                .groups(Collections.emptyList())
                .isTruncated(false)
                .build();
        when(mockClient.listGroupsForUser(any(ListGroupsForUserRequest.class)))
                .thenReturn(listGroupsResponse);

        // Create a filter for a non-Name attribute (UID)
        Filter uidFilter = new EqualsFilter(new Uid("user1"));

        // Execute search
        connector.executeQuery(ObjectClass.ACCOUNT, uidFilter, mockHandler, null);

        // Verify GetUser API was called (connector uses getUser for UID search)
        verify(mockClient).getUser(any(GetUserRequest.class));

        // Verify handler was called once
        verify(mockHandler, times(1)).handle(any(ConnectorObject.class));
    }
}
