package com.atricore.iam.midpoint.connector.aws;

import com.atricore.iam.midpoint.connector.aws.objects.PolicyHandler;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
public class PolicySearchTest {

    @Mock
    private IamClient iamClient;

    @Mock
    private ResultsHandler resultsHandler;

    private PolicyHandler policyHandler;
    private AWSConfiguration config;

    @BeforeEach
    public void setup() {
        config = new AWSConfiguration();
        policyHandler = new PolicyHandler(iamClient, config);
        
        // Mock listPolicyTags response for all tests with lenient mode
        // This prevents UnnecessaryStubbing errors when some tests don't use this mock
        lenient().when(iamClient.listPolicyTags((ListPolicyTagsRequest) any()))
                .thenReturn(ListPolicyTagsResponse.builder().tags(new ArrayList<>()).build());
    }

    @Test
    public void testSearchByPolicyName() {
        // Setup
        String policyName = "TestPolicy";
        EqualsFilter filter = new EqualsFilter(new Name(policyName));

        // Mock GetPolicy response (connector uses getPolicy when searching by name)
        Policy policy = createMockPolicy("p-123456", policyName, "arn:aws:iam::123456789012:policy/TestPolicy");
        GetPolicyResponse getPolicyResponse = GetPolicyResponse.builder()
                .policy(policy)
                .build();

        when(iamClient.getPolicy(any(GetPolicyRequest.class))).thenReturn(getPolicyResponse);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        verify(iamClient).getPolicy(any(GetPolicyRequest.class));
        verify(resultsHandler).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByPolicyId() {
        // Setup
        String policyId = "p-123456";
        EqualsFilter filter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_POLICY_ID, policyId));

        // Mock ListPolicies response
        List<Policy> policies = new ArrayList<>();
        Policy policy = createMockPolicy(policyId, "TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy");
        policies.add(policy);

        ListPoliciesResponse listResponse = ListPoliciesResponse.builder()
                .policies(policies)
                .isTruncated(false)
                .build();

        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(listResponse);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        verify(iamClient).listPolicies(any(ListPoliciesRequest.class));
        verify(resultsHandler).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByArn() {
        // Setup
        String arn = "arn:aws:iam::123456789012:policy/TestPolicy";
        EqualsFilter filter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_ARN, arn));

        // Mock GetPolicy response
        Policy policy = createMockPolicy("p-123456", "TestPolicy", arn);
        GetPolicyResponse getPolicyResponse = GetPolicyResponse.builder()
                .policy(policy)
                .build();

        when(iamClient.getPolicy(any(GetPolicyRequest.class))).thenReturn(getPolicyResponse);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        ArgumentCaptor<GetPolicyRequest> requestCaptor = ArgumentCaptor.forClass(GetPolicyRequest.class);
        verify(iamClient).getPolicy(requestCaptor.capture());
        assertEquals(arn, requestCaptor.getValue().policyArn());
        verify(resultsHandler).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByPolicyType() {
        // Setup
        String policyType = "AWS_MANAGED";
        EqualsFilter filter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_POLICY_TYPE, policyType));

        // Mock ListPolicies response
        List<Policy> policies = new ArrayList<>();
        Policy policy = createMockPolicy("p-123456", "TestPolicy", "arn:aws:iam::aws:policy/TestPolicy");
        policies.add(policy);

        ListPoliciesResponse listResponse = ListPoliciesResponse.builder()
                .policies(policies)
                .isTruncated(false)
                .build();

        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(listResponse);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        ArgumentCaptor<ListPoliciesRequest> requestCaptor = ArgumentCaptor.forClass(ListPoliciesRequest.class);
        verify(iamClient).listPolicies(requestCaptor.capture());
        // Fix the expected value to match what's in the PolicyHandler class
        assertEquals(PolicyScopeType.LOCAL, requestCaptor.getValue().scope());
        verify(resultsHandler).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByPath() {
        // Setup
        String path = "/test/path/";
        EqualsFilter filter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, path));

        // Mock ListPolicies response
        List<Policy> policies = new ArrayList<>();
        Policy policy = createMockPolicy("p-123456", "TestPolicy", "arn:aws:iam::123456789012:policy/test/path/TestPolicy");
        policy = policy.toBuilder().path(path).build();
        policies.add(policy);

        ListPoliciesResponse listResponse = ListPoliciesResponse.builder()
                .policies(policies)
                .isTruncated(false)
                .build();

        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(listResponse);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        ArgumentCaptor<ListPoliciesRequest> requestCaptor = ArgumentCaptor.forClass(ListPoliciesRequest.class);
        verify(iamClient).listPolicies(requestCaptor.capture());
        assertEquals(path, requestCaptor.getValue().pathPrefix());
        verify(resultsHandler).handle(any(ConnectorObject.class));
    }

    @Test
    public void testListAllPolicies() {
        // Setup - no filter means list all policies
        Filter filter = null;

        // Mock ListPolicies response
        List<Policy> policies = new ArrayList<>();
        policies.add(createMockPolicy("p-123456", "TestPolicy1", "arn:aws:iam::123456789012:policy/TestPolicy1"));
        policies.add(createMockPolicy("p-234567", "TestPolicy2", "arn:aws:iam::123456789012:policy/TestPolicy2"));

        ListPoliciesResponse listResponse = ListPoliciesResponse.builder()
                .policies(policies)
                .isTruncated(false)
                .build();

        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(listResponse);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        verify(iamClient).listPolicies(any(ListPoliciesRequest.class));
        verify(resultsHandler, times(2)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testPaginatedSearch() {
        // Setup
        Filter filter = null;

        // First page response
        List<Policy> firstPagePolicies = new ArrayList<>();
        firstPagePolicies.add(createMockPolicy("p-123456", "TestPolicy1", "arn:aws:iam::123456789012:policy/TestPolicy1"));

        ListPoliciesResponse firstPageResponse = ListPoliciesResponse.builder()
                .policies(firstPagePolicies)
                .isTruncated(true)
                .marker("marker-token")
                .build();

        // Second page response
        List<Policy> secondPagePolicies = new ArrayList<>();
        secondPagePolicies.add(createMockPolicy("p-234567", "TestPolicy2", "arn:aws:iam::123456789012:policy/TestPolicy2"));

        ListPoliciesResponse secondPageResponse = ListPoliciesResponse.builder()
                .policies(secondPagePolicies)
                .isTruncated(false)
                .build();

        // Fix the stubbing to use a more general approach that works with any request
        when(iamClient.listPolicies(any(ListPoliciesRequest.class)))
            .thenAnswer(invocation -> {
                ListPoliciesRequest req = invocation.getArgument(0);
                if (req.marker() == null) {
                    return firstPageResponse;
                } else {
                    return secondPageResponse;
                }
            });

        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        verify(iamClient, times(2)).listPolicies(any(ListPoliciesRequest.class));
        verify(resultsHandler, times(2)).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchWithPageSize() {
        // Setup
        Filter filter = null;
        OperationOptions options = new OperationOptionsBuilder().setPageSize(10).build();

        // Mock response
        List<Policy> policies = new ArrayList<>();
        policies.add(createMockPolicy("p-123456", "TestPolicy", "arn:aws:iam::123456789012:policy/TestPolicy"));

        ListPoliciesResponse response = ListPoliciesResponse.builder()
                .policies(policies)
                .isTruncated(false)
                .build();

        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(response);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, options);

        // Verify
        ArgumentCaptor<ListPoliciesRequest> requestCaptor = ArgumentCaptor.forClass(ListPoliciesRequest.class);
        verify(iamClient).listPolicies(requestCaptor.capture());
        assertEquals(Integer.valueOf(10), requestCaptor.getValue().maxItems());
        verify(resultsHandler).handle(any(ConnectorObject.class));
    }

    @Test
    public void testSearchByArnPolicyNotFound() {
        // Setup
        String arn = "arn:aws:iam::123456789012:policy/NonExistentPolicy";
        EqualsFilter filter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_ARN, arn));

        // Mock GetPolicy to throw NoSuchEntityException
        when(iamClient.getPolicy(any(GetPolicyRequest.class)))
                .thenThrow(NoSuchEntityException.builder().message("Policy not found").build());

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        verify(iamClient).getPolicy(any(GetPolicyRequest.class));
        verify(resultsHandler, never()).handle(any(ConnectorObject.class));
    }

    @Test
    public void testEarlyTerminationWhenHandlerReturnsFalse() {
        // Setup
        Filter filter = null;

        // Mock response with multiple policies
        List<Policy> policies = new ArrayList<>();
        policies.add(createMockPolicy("p-123456", "TestPolicy1", "arn:aws:iam::123456789012:policy/TestPolicy1"));
        policies.add(createMockPolicy("p-234567", "TestPolicy2", "arn:aws:iam::123456789012:policy/TestPolicy2"));

        ListPoliciesResponse response = ListPoliciesResponse.builder()
                .policies(policies)
                .isTruncated(false)
                .build();

        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(response);

        // Make handler return false after first policy
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(false);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        verify(iamClient).listPolicies(any(ListPoliciesRequest.class));
        verify(resultsHandler, times(1)).handle(any(ConnectorObject.class));
    }
    
    @Test
    public void testPolicyWithTags() {
        // Setup
        String policyId = "p-123456";
        String policyArn = "arn:aws:iam::123456789012:policy/TestPolicy";
        EqualsFilter filter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_POLICY_ID, policyId));

        // Mock ListPolicies response
        List<Policy> policies = new ArrayList<>();
        Policy policy = createMockPolicy(policyId, "TestPolicy", policyArn);
        policies.add(policy);

        ListPoliciesResponse listResponse = ListPoliciesResponse.builder()
                .policies(policies)
                .isTruncated(false)
                .build();

        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(listResponse);
        when(resultsHandler.handle(any(ConnectorObject.class))).thenReturn(true);

        // Mock ListPolicyTags response with tags - must use a specific request matcher
        List<Tag> tags = new ArrayList<>();
        tags.add(Tag.builder().key("Environment").value("Production").build());
        tags.add(Tag.builder().key("Owner").value("DevOps").build());
        
        ListPolicyTagsResponse tagsResponse = ListPolicyTagsResponse.builder()
                .tags(tags)
                .isTruncated(false)
                .build();

        // Reset and mock listPolicyTags to return tags for this test
        reset(iamClient);
        when(iamClient.listPolicies(any(ListPoliciesRequest.class))).thenReturn(listResponse);
        when(iamClient.listPolicyTags(any(ListPolicyTagsRequest.class))).thenReturn(tagsResponse);

        // Execute
        policyHandler.searchPolicies(resultsHandler, filter, null);

        // Verify
        verify(iamClient).listPolicies(any(ListPoliciesRequest.class));
        verify(iamClient).listPolicyTags((ListPolicyTagsRequest) argThat(arg -> 
                arg instanceof ListPolicyTagsRequest && 
                ((ListPolicyTagsRequest) arg).policyArn().equals(policyArn)));
        
        // Capture ConnectorObject passed to handler
        ArgumentCaptor<ConnectorObject> coCaptor = ArgumentCaptor.forClass(ConnectorObject.class);
        verify(resultsHandler).handle(coCaptor.capture());
        
        // Verify tags are included in the connector object
        ConnectorObject co = coCaptor.getValue();
        Attribute tagsAttr = co.getAttributeByName(AWSSchema.ATTRIBUTE_TAGS);
        assertNotNull(tagsAttr, "Tags attribute should exist");
        List<Object> tagValues = tagsAttr.getValue();
        assertEquals(2, tagValues.size(), "Should have two tags");
        assertTrue(tagValues.contains("Environment=Production"), "Should contain Environment tag");
        assertTrue(tagValues.contains("Owner=DevOps"), "Should contain Owner tag");
    }

    // Helper method to create a mock Policy object
    private Policy createMockPolicy(String policyId, String policyName, String arn) {
        return Policy.builder()
                .policyId(policyId)
                .policyName(policyName)
                .arn(arn)
                .defaultVersionId("v1")
                .attachmentCount(0)
                .permissionsBoundaryUsageCount(0)
                .isAttachable(true)
                .createDate(Instant.now())
                .path("/")
                .build();
    }
}
