package com.atricore.iam.midpoint.connector.aws;

import com.atricore.iam.midpoint.connector.aws.objects.UserHandler;
import com.atricore.iam.midpoint.connector.aws.objects.PolicyHandler;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.framework.spi.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for associating policies with users.
 */
@ExtendWith(MockitoExtension.class)
public class UserPolicyAssociationTest {

    @Mock
    private IamClient mockClient;

    private AWSConnector connector;
    private AWSConfiguration config;

    @BeforeEach
    public void setup() {
        config = new AWSConfiguration();
        config.setAwsAccessKeyId("test-access-key");
        config.setAwsSecretAccessKey(new GuardedString("test-secret-key".toCharArray()));
        config.setAwsRegion("us-east-1");
        config.setAllowCache(false);

        connector = new AWSConnector() {
            @Override
            public void init(Configuration cfg) {
                this.configuration = (AWSConfiguration) cfg;
                this.client = mockClient;
                super.userHandler = new UserHandler(this.client, this.configuration);
                super.policyHandler = new PolicyHandler(this.client, this.configuration);
            }
        };
        connector.init(config);
    }

    @Test
    public void testCreateUserWithPolicies() {
        String userName = "test-user-with-policies";
        String policyArn1 = "arn:aws:iam::aws:policy/ReadOnlyAccess";
        String policyArn2 = "arn:aws:iam::123456789012:policy/CustomUserPolicy";

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(userName));
        attributes.add(AttributeBuilder.build(AWSSchema.ASSOCIATION_POLICIES, policyArn1, policyArn2));

        CreateUserResponse createUserResponse = CreateUserResponse.builder()
                .user(User.builder().userName(userName).userId("test-user-id").build())
                .build();
        when(mockClient.createUser(any(CreateUserRequest.class))).thenReturn(createUserResponse);
        when(mockClient.attachUserPolicy(any(AttachUserPolicyRequest.class)))
                .thenReturn(AttachUserPolicyResponse.builder().build());

        Uid userUid = connector.create(ObjectClass.ACCOUNT, attributes, new OperationOptionsBuilder().build());
        assertNotNull(userUid);

        verify(mockClient).createUser(any(CreateUserRequest.class));
        verify(mockClient, times(2)).attachUserPolicy(any(AttachUserPolicyRequest.class));
    }

    @Test
    public void testUpdateUser_AddPolicy() {
        Uid userUid = new Uid("existing-user-id"); // AWS IAM User Uid is userId not userName
        String userName = "existing-user-name";
        String newPolicyArn = "arn:aws:iam::aws:policy/PowerUserAccess";

        Set<AttributeDelta> modifications = new HashSet<>();
        AttributeDelta addPolicyDelta = new AttributeDeltaBuilder()
                .setName(AWSSchema.ASSOCIATION_POLICIES)
                .addValueToAdd(newPolicyArn)
                .build();
        modifications.add(addPolicyDelta);

        // Mock user lookup
        User existingUser = User.builder()
                .userId(userUid.getUidValue())
                .userName(userName)
                .build();

        // Mock ListUsers response for findUserById
        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(Collections.singletonList(existingUser))
                .isTruncated(false)
                .build();
        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);

        // Mock policy attachment
        when(mockClient.attachUserPolicy(any(AttachUserPolicyRequest.class)))
                .thenReturn(AttachUserPolicyResponse.builder().build());

        // Call updateDelta
        connector.updateDelta(ObjectClass.ACCOUNT, userUid, modifications, new OperationOptionsBuilder().build());

        // Verify the policy was attached
        verify(mockClient).attachUserPolicy(ArgumentMatchers.<AttachUserPolicyRequest>argThat(req ->
                req.policyArn().equals(newPolicyArn) &&
                req.userName().equals(userName)));
    }

    @Test
    public void testUpdateUser_RemovePolicy() {
        Uid userUid = new Uid("user-id-to-remove-policy");
        String userName = "user-to-remove-policy-from";
        String policyArnToRemove = "arn:aws:iam::aws:policy/ReadOnlyAccess";

        Set<AttributeDelta> modifications = new HashSet<>();
        // To remove a specific policy
        AttributeDelta removePolicyDelta = new AttributeDeltaBuilder()
                .setName(AWSSchema.ASSOCIATION_POLICIES)
                .addValueToRemove(policyArnToRemove)
                .build();
        modifications.add(removePolicyDelta);

        // Mock user lookup
        User existingUser = User.builder()
                .userId(userUid.getUidValue())
                .userName(userName)
                .build();

        // Mock ListUsers response for findUserById
        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(Collections.singletonList(existingUser))
                .isTruncated(false)
                .build();
        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);

        // Mock policy detachment
        when(mockClient.detachUserPolicy(any(DetachUserPolicyRequest.class)))
                .thenReturn(DetachUserPolicyResponse.builder().build());

        // Call updateDelta
        connector.updateDelta(ObjectClass.ACCOUNT, userUid, modifications, new OperationOptionsBuilder().build());

        // Verify policy was detached
        verify(mockClient).detachUserPolicy(ArgumentMatchers.<DetachUserPolicyRequest>argThat(req ->
                req.policyArn().equals(policyArnToRemove) &&
                req.userName().equals(userName)));
    }

    @Test
    public void testUpdateUser_ReplacePolicies() {
        Uid userUid = new Uid("user-id-to-replace-policies");
        String userName = "user-to-replace-policies-from";
        String oldPolicyArn = "arn:aws:iam::aws:policy/OldUserPolicy";
        String newPolicyArn = "arn:aws:iam::aws:policy/NewUserPolicy";

        Set<AttributeDelta> modifications = new HashSet<>();
        AttributeDelta replacePolicyDelta = new AttributeDeltaBuilder()
                .setName(AWSSchema.ASSOCIATION_POLICIES)
                .addValueToReplace(newPolicyArn)
                .build();
        modifications.add(replacePolicyDelta);

        // Mock user lookup
        User existingUser = User.builder()
                .userId(userUid.getUidValue())
                .userName(userName)
                .build();
        ListUsersResponse listUsersResponse = ListUsersResponse.builder()
                .users(Collections.singletonList(existingUser))
                .isTruncated(false)
                .build();
        when(mockClient.listUsers(any(ListUsersRequest.class))).thenReturn(listUsersResponse);

        // Mock current attached policies (the old one)
        ListAttachedUserPoliciesResponse listAttachedPoliciesResponse = ListAttachedUserPoliciesResponse.builder()
                .attachedPolicies(AttachedPolicy.builder().policyArn(oldPolicyArn).policyName("OldUserPolicy").build())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedUserPolicies(any(ListAttachedUserPoliciesRequest.class)))
                .thenReturn(listAttachedPoliciesResponse);

        // Mock policy detachment and attachment
        when(mockClient.detachUserPolicy(any(DetachUserPolicyRequest.class)))
                .thenReturn(DetachUserPolicyResponse.builder().build());
        when(mockClient.attachUserPolicy(any(AttachUserPolicyRequest.class)))
                .thenReturn(AttachUserPolicyResponse.builder().build());

        // Call updateDelta
        connector.updateDelta(ObjectClass.ACCOUNT, userUid, modifications, new OperationOptionsBuilder().build());

        // Verify old policy was detached
        verify(mockClient).detachUserPolicy(ArgumentMatchers.<DetachUserPolicyRequest>argThat(req ->
                req.policyArn().equals(oldPolicyArn) &&
                req.userName().equals(userName)));

        // Verify new policy was attached
        verify(mockClient).attachUserPolicy(ArgumentMatchers.<AttachUserPolicyRequest>argThat(req ->
                req.policyArn().equals(newPolicyArn) &&
                req.userName().equals(userName)));
    }

    @Test
    public void testReadUser_VerifyAttachedPolicies() {
        // Setup test data (userId and userName must match)
        String userId = "test-user-name";
        String userName = "test-user-name";
        String policyArn1 = "arn:aws:iam::aws:policy/ReadOnlyAccess";
        String policyArn2 = "arn:aws:iam::123456789012:policy/CustomUserPolicy";

        // Create a filter to search for the user by Uid
        Filter uidFilter = FilterBuilder.equalTo(new Uid(userId));

        // Mock GetUser response
        User user = User.builder()
                .userId(userId)
                .userName(userName)
                .arn("arn:aws:iam::123456789012:user/" + userName)
                .path("/")
                .build();

        // Mock GetUser API call (used when searching by UID/userName)
        GetUserResponse getUserResponse = GetUserResponse.builder()
                .user(user)
                .build();
        when(mockClient.getUser(any(GetUserRequest.class))).thenReturn(getUserResponse);

        // Mock ListAttachedUserPolicies response
        ListAttachedUserPoliciesResponse listPoliciesResponse = ListAttachedUserPoliciesResponse.builder()
                .attachedPolicies(
                        AttachedPolicy.builder().policyArn(policyArn1).policyName("ReadOnlyAccess").build(),
                        AttachedPolicy.builder().policyArn(policyArn2).policyName("CustomUserPolicy").build()
                )
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

        // Create a results handler to capture the returned ConnectorObject
        final Set<ConnectorObject> capturedObjects = new HashSet<>();
        ResultsHandler resultsHandler = connectorObject -> {
            capturedObjects.add(connectorObject);
            return true;
        };

        // Execute the query
        connector.executeQuery(ObjectClass.ACCOUNT, uidFilter, resultsHandler, new OperationOptionsBuilder().build());

        // Verify that we got exactly one result
        assertNotNull(capturedObjects);
        org.junit.jupiter.api.Assertions.assertEquals(1, capturedObjects.size());

        // Get the ConnectorObject and verify it has the expected policy ARNs
        ConnectorObject resultObject = capturedObjects.iterator().next();
        Attribute policiesAttr = resultObject.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);

        assertNotNull(policiesAttr);
        org.junit.jupiter.api.Assertions.assertEquals(2, policiesAttr.getValue().size());
        org.junit.jupiter.api.Assertions.assertTrue(policiesAttr.getValue().contains(policyArn1));
        org.junit.jupiter.api.Assertions.assertTrue(policiesAttr.getValue().contains(policyArn2));

        // Verify the user ID and name are correct
        org.junit.jupiter.api.Assertions.assertEquals(userId, resultObject.getUid().getUidValue());
        org.junit.jupiter.api.Assertions.assertEquals(userName, resultObject.getName().getNameValue());
    }
}
