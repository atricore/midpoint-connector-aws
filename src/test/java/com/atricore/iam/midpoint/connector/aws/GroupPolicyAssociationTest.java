package com.atricore.iam.midpoint.connector.aws;

import com.atricore.iam.midpoint.connector.aws.objects.GroupHandler;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.iam.IamClient;

import java.util.HashSet;
import java.util.Set;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import org.mockito.ArgumentCaptor;

/**
 * Tests for associating policies with groups.
 */
@ExtendWith(MockitoExtension.class)
public class GroupPolicyAssociationTest {

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
                super.groupHandler = new GroupHandler(this.client, this.configuration);
                // Initialize other handlers if they are interacted with
                super.policyHandler = new com.atricore.iam.midpoint.connector.aws.objects.PolicyHandler(this.client, this.configuration);
            }
        };
        connector.init(config);
    }

    @Test
    public void testCreateGroupWithPolicies() {
        // Setup: Group name, policy ARNs
        String groupName = "test-group-with-policies";
        String policyArn1 = "arn:aws:iam::aws:policy/ReadOnlyAccess";
        String policyArn2 = "arn:aws:iam::123456789012:policy/CustomPolicy";

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(groupName));
        attributes.add(AttributeBuilder.build(AWSSchema.ASSOCIATION_POLICIES, policyArn1, policyArn2));

        // Mock AWS SDK calls for group creation and policy attachment
        software.amazon.awssdk.services.iam.model.Group mockGroup = software.amazon.awssdk.services.iam.model.Group.builder()
                .groupName(groupName)
                .groupId("AGROUPID123456789")
                .arn("arn:aws:iam::123456789012:group/" + groupName)
                .path("/")
                .createDate(java.time.Instant.now())
                .build();

        software.amazon.awssdk.services.iam.model.CreateGroupResponse mockCreateResponse = 
                software.amazon.awssdk.services.iam.model.CreateGroupResponse.builder()
                .group(mockGroup)
                .build();

        software.amazon.awssdk.services.iam.model.AttachGroupPolicyResponse mockAttachResponse = 
                software.amazon.awssdk.services.iam.model.AttachGroupPolicyResponse.builder().build();

        when(mockClient.createGroup(any(software.amazon.awssdk.services.iam.model.CreateGroupRequest.class)))
                .thenReturn(mockCreateResponse);
        when(mockClient.attachGroupPolicy(any(software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest.class)))
                .thenReturn(mockAttachResponse);

        // Execute: Create the group with policies
        Uid groupUid = connector.create(ObjectClass.GROUP, attributes, null);
        
        // Verify: Group was created successfully
        assertNotNull(groupUid);
        assertEquals("AGROUPID123456789", groupUid.getUidValue());

        // Verify: AWS SDK calls were made correctly
        verify(mockClient).createGroup(any(software.amazon.awssdk.services.iam.model.CreateGroupRequest.class));
        verify(mockClient, times(2)).attachGroupPolicy(any(software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest.class));

        // Verify: Policy attachment calls were made with correct parameters
        ArgumentCaptor<software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest> policyCaptor = 
                ArgumentCaptor.forClass(software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest.class);
        verify(mockClient, times(2)).attachGroupPolicy(policyCaptor.capture());
        
        java.util.List<software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest> capturedRequests = policyCaptor.getAllValues();
        assertEquals(2, capturedRequests.size());
        
        // Verify both policies were attached to the correct group
        boolean foundPolicy1 = false;
        boolean foundPolicy2 = false;
        for (software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest request : capturedRequests) {
            assertEquals(groupName, request.groupName());
            if (policyArn1.equals(request.policyArn())) {
                foundPolicy1 = true;
            } else if (policyArn2.equals(request.policyArn())) {
                foundPolicy2 = true;
            }
        }
        assertTrue(foundPolicy1, "Policy 1 should have been attached");
        assertTrue(foundPolicy2, "Policy 2 should have been attached");
    }

    @Test
    public void testUpdateGroup_AddPolicy() {
        // Setup: Existing group Uid, new policy ARN to add
        String groupId = "AGROUPID123456789";
        String groupName = "existing-test-group";
        String newPolicyArn = "arn:aws:iam::aws:policy/PowerUserAccess";
        Uid groupUid = new Uid(groupId);

        Set<AttributeDelta> modifications = new HashSet<>();
        AttributeDelta addPolicyDelta = new AttributeDeltaBuilder()
                .setName(AWSSchema.ASSOCIATION_POLICIES)
                .addValueToAdd(newPolicyArn)
                .build();
        modifications.add(addPolicyDelta);

        // Mock existing group lookup
        software.amazon.awssdk.services.iam.model.Group existingGroup = software.amazon.awssdk.services.iam.model.Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .arn("arn:aws:iam::123456789012:group/" + groupName)
                .path("/")
                .createDate(java.time.Instant.now())
                .build();

        // Mock ListGroups response for findGroupById
        software.amazon.awssdk.services.iam.model.ListGroupsResponse listGroupsResponse = 
                software.amazon.awssdk.services.iam.model.ListGroupsResponse.builder()
                .groups(java.util.Collections.singletonList(existingGroup))
                .isTruncated(false)
                .build();
        when(mockClient.listGroups(any(software.amazon.awssdk.services.iam.model.ListGroupsRequest.class)))
                .thenReturn(listGroupsResponse);

        // Mock policy attachment
        software.amazon.awssdk.services.iam.model.AttachGroupPolicyResponse mockAttachResponse = 
                software.amazon.awssdk.services.iam.model.AttachGroupPolicyResponse.builder().build();
        when(mockClient.attachGroupPolicy(any(software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest.class)))
                .thenReturn(mockAttachResponse);

        // Execute: connector.updateDelta for group with new policy in ASSOCIATION_POLICIES
        Set<AttributeDelta> result = connector.updateDelta(ObjectClass.GROUP, groupUid, modifications, null);

        // Verify: Policy attachment call
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Update should return empty set on success");
        
        ArgumentCaptor<software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest> attachCaptor = 
                ArgumentCaptor.forClass(software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest.class);
        verify(mockClient).attachGroupPolicy(attachCaptor.capture());
        
        software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest capturedRequest = attachCaptor.getValue();
        assertEquals(groupName, capturedRequest.groupName());
        assertEquals(newPolicyArn, capturedRequest.policyArn());
    }

    @Test
    public void testUpdateGroup_RemovePolicy() {
        // Setup: Existing group Uid, policy ARN to remove
        String groupId = "AGROUPID123456789";
        String groupName = "existing-test-group";
        String policyArnToRemove = "arn:aws:iam::aws:policy/ReadOnlyAccess";
        Uid groupUid = new Uid(groupId);

        Set<AttributeDelta> modifications = new HashSet<>();
        AttributeDelta removePolicyDelta = new AttributeDeltaBuilder()
                .setName(AWSSchema.ASSOCIATION_POLICIES)
                .addValueToRemove(policyArnToRemove)
                .build();
        modifications.add(removePolicyDelta);

        // Mock existing group lookup
        software.amazon.awssdk.services.iam.model.Group existingGroup = software.amazon.awssdk.services.iam.model.Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .arn("arn:aws:iam::123456789012:group/" + groupName)
                .path("/")
                .createDate(java.time.Instant.now())
                .build();

        // Mock ListGroups response for findGroupById
        software.amazon.awssdk.services.iam.model.ListGroupsResponse listGroupsResponse = 
                software.amazon.awssdk.services.iam.model.ListGroupsResponse.builder()
                .groups(java.util.Collections.singletonList(existingGroup))
                .isTruncated(false)
                .build();
        when(mockClient.listGroups(any(software.amazon.awssdk.services.iam.model.ListGroupsRequest.class)))
                .thenReturn(listGroupsResponse);

        // Mock policy detachment
        software.amazon.awssdk.services.iam.model.DetachGroupPolicyResponse mockDetachResponse = 
                software.amazon.awssdk.services.iam.model.DetachGroupPolicyResponse.builder().build();
        when(mockClient.detachGroupPolicy(any(software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest.class)))
                .thenReturn(mockDetachResponse);

        // Execute: connector.updateDelta for group with policy removed from ASSOCIATION_POLICIES
        Set<AttributeDelta> result = connector.updateDelta(ObjectClass.GROUP, groupUid, modifications, null);

        // Verify: Policy detachment call
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Update should return empty set on success");
        
        ArgumentCaptor<software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest> detachCaptor = 
                ArgumentCaptor.forClass(software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest.class);
        verify(mockClient).detachGroupPolicy(detachCaptor.capture());
        
        software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest capturedRequest = detachCaptor.getValue();
        assertEquals(groupName, capturedRequest.groupName());
        assertEquals(policyArnToRemove, capturedRequest.policyArn());
    }

    @Test
    public void testUpdateGroup_ReplacePolicies() {
        // Setup: Existing group Uid, old policy ARNs, new policy ARNs
        String groupId = "AGROUPID123456789";
        String groupName = "existing-test-group";
        String oldPolicyArn = "arn:aws:iam::aws:policy/ReadOnlyAccess";
        String newPolicyArn1 = "arn:aws:iam::aws:policy/PowerUserAccess";
        String newPolicyArn2 = "arn:aws:iam::123456789012:policy/CustomGroupPolicy";
        Uid groupUid = new Uid(groupId);

        Set<AttributeDelta> modifications = new HashSet<>();
        AttributeDelta replacePolicyDelta = new AttributeDeltaBuilder()
                .setName(AWSSchema.ASSOCIATION_POLICIES)
                .addValueToReplace(newPolicyArn1)
                .addValueToReplace(newPolicyArn2)
                .build();
        modifications.add(replacePolicyDelta);

        // Mock existing group lookup
        software.amazon.awssdk.services.iam.model.Group existingGroup = software.amazon.awssdk.services.iam.model.Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .arn("arn:aws:iam::123456789012:group/" + groupName)
                .path("/")
                .createDate(java.time.Instant.now())
                .build();

        // Mock ListGroups response for findGroupById
        software.amazon.awssdk.services.iam.model.ListGroupsResponse listGroupsResponse = 
                software.amazon.awssdk.services.iam.model.ListGroupsResponse.builder()
                .groups(java.util.Collections.singletonList(existingGroup))
                .isTruncated(false)
                .build();
        when(mockClient.listGroups(any(software.amazon.awssdk.services.iam.model.ListGroupsRequest.class)))
                .thenReturn(listGroupsResponse);

        // Mock current attached policies (the old one)
        software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesResponse listAttachedPoliciesResponse = 
                software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesResponse.builder()
                .attachedPolicies(software.amazon.awssdk.services.iam.model.AttachedPolicy.builder()
                        .policyArn(oldPolicyArn)
                        .policyName("ReadOnlyAccess")
                        .build())
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedGroupPolicies(any(software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesRequest.class)))
                .thenReturn(listAttachedPoliciesResponse);

        // Mock policy detachment and attachment
        software.amazon.awssdk.services.iam.model.DetachGroupPolicyResponse mockDetachResponse = 
                software.amazon.awssdk.services.iam.model.DetachGroupPolicyResponse.builder().build();
        when(mockClient.detachGroupPolicy(any(software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest.class)))
                .thenReturn(mockDetachResponse);
        
        software.amazon.awssdk.services.iam.model.AttachGroupPolicyResponse mockAttachResponse = 
                software.amazon.awssdk.services.iam.model.AttachGroupPolicyResponse.builder().build();
        when(mockClient.attachGroupPolicy(any(software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest.class)))
                .thenReturn(mockAttachResponse);

        // Execute: connector.updateDelta for group with new set of policies in ASSOCIATION_POLICIES
        Set<AttributeDelta> result = connector.updateDelta(ObjectClass.GROUP, groupUid, modifications, null);

        // Verify: Correct detach and attach calls
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Update should return empty set on success");
        
        // Verify old policy was detached
        ArgumentCaptor<software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest> detachCaptor = 
                ArgumentCaptor.forClass(software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest.class);
        verify(mockClient).detachGroupPolicy(detachCaptor.capture());
        
        software.amazon.awssdk.services.iam.model.DetachGroupPolicyRequest detachRequest = detachCaptor.getValue();
        assertEquals(groupName, detachRequest.groupName());
        assertEquals(oldPolicyArn, detachRequest.policyArn());
        
        // Verify new policies were attached
        ArgumentCaptor<software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest> attachCaptor = 
                ArgumentCaptor.forClass(software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest.class);
        verify(mockClient, times(2)).attachGroupPolicy(attachCaptor.capture());
        
        java.util.List<software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest> attachRequests = attachCaptor.getAllValues();
        assertEquals(2, attachRequests.size());
        
        // Verify both new policies were attached to the correct group
        boolean foundNewPolicy1 = false;
        boolean foundNewPolicy2 = false;
        for (software.amazon.awssdk.services.iam.model.AttachGroupPolicyRequest request : attachRequests) {
            assertEquals(groupName, request.groupName());
            if (newPolicyArn1.equals(request.policyArn())) {
                foundNewPolicy1 = true;
            } else if (newPolicyArn2.equals(request.policyArn())) {
                foundNewPolicy2 = true;
            }
        }
        assertTrue(foundNewPolicy1, "New policy 1 should have been attached");
        assertTrue(foundNewPolicy2, "New policy 2 should have been attached");
    }

    @Test
    public void testReadGroup_VerifyAttachedPolicies() {
        // Setup: Group Uid, policy ARNs associated with the group
        String groupId = "AGROUPID123456789";
        String groupName = "test-group-with-policies";
        String policyArn1 = "arn:aws:iam::aws:policy/ReadOnlyAccess";
        String policyArn2 = "arn:aws:iam::123456789012:policy/CustomGroupPolicy";
        Uid groupUid = new Uid(groupId);

        // Create a filter to search for the group by Uid
        org.identityconnectors.framework.common.objects.filter.Filter uidFilter = 
                org.identityconnectors.framework.common.objects.filter.FilterBuilder.equalTo(groupUid);

        // Mock group data
        software.amazon.awssdk.services.iam.model.Group mockGroup = software.amazon.awssdk.services.iam.model.Group.builder()
                .groupId(groupId)
                .groupName(groupName)
                .arn("arn:aws:iam::123456789012:group/" + groupName)
                .path("/")
                .createDate(java.time.Instant.now())
                .build();

        // Mock GetGroup response (connector uses getGroup when searching by UID)
        software.amazon.awssdk.services.iam.model.GetGroupResponse getGroupResponse = 
                software.amazon.awssdk.services.iam.model.GetGroupResponse.builder()
                .group(mockGroup)
                .build();
        when(mockClient.getGroup(any(software.amazon.awssdk.services.iam.model.GetGroupRequest.class)))
                .thenReturn(getGroupResponse);

        // Mock ListAttachedGroupPolicies response
        software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesResponse listPoliciesResponse = 
                software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesResponse.builder()
                .attachedPolicies(
                        software.amazon.awssdk.services.iam.model.AttachedPolicy.builder()
                                .policyArn(policyArn1)
                                .policyName("ReadOnlyAccess")
                                .build(),
                        software.amazon.awssdk.services.iam.model.AttachedPolicy.builder()
                                .policyArn(policyArn2)
                                .policyName("CustomGroupPolicy")
                                .build()
                )
                .isTruncated(false)
                .build();
        when(mockClient.listAttachedGroupPolicies(any(software.amazon.awssdk.services.iam.model.ListAttachedGroupPoliciesRequest.class)))
                .thenReturn(listPoliciesResponse);

        // Create a results handler to capture the returned ConnectorObject
        final Set<ConnectorObject> capturedObjects = new HashSet<>();
        ResultsHandler resultsHandler = connectorObject -> {
            capturedObjects.add(connectorObject);
            return true;
        };

        // Execute: connector.executeQuery to read the group
        connector.executeQuery(ObjectClass.GROUP, uidFilter, resultsHandler, null);

        // Verify: ConnectorObject contains the correct policy ARNs in ASSOCIATION_POLICIES
        assertNotNull(capturedObjects);
        assertEquals(1, capturedObjects.size());

        // Get the ConnectorObject and verify it has the expected policy ARNs
        ConnectorObject resultObject = capturedObjects.iterator().next();
        Attribute policiesAttr = resultObject.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);

        assertNotNull(policiesAttr, "Group should have attached policies attribute");
        assertEquals(2, policiesAttr.getValue().size());
        assertTrue(policiesAttr.getValue().contains(policyArn1), "Should contain policy 1");
        assertTrue(policiesAttr.getValue().contains(policyArn2), "Should contain policy 2");

        // Verify the group UID and name are correct (connector uses groupName as UID)
        assertEquals(groupName, resultObject.getUid().getUidValue());
        assertEquals(groupName, resultObject.getName().getNameValue());
        
        // Verify AWS group ID is in the awsId attribute
        Attribute awsIdAttr = resultObject.getAttributeByName(AWSSchema.ATTRIBUTE_AWS_ID);
        assertNotNull(awsIdAttr, "AWS Group ID attribute should be present");
        assertEquals(groupId, org.identityconnectors.framework.common.objects.AttributeUtil.getStringValue(awsIdAttr), "AWS Group ID should match");
    }
}
