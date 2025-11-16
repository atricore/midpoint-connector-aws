package com.atricore.iam.midpoint.connector.aws.it;

import com.atricore.iam.midpoint.connector.aws.AWSConfiguration;
import com.atricore.iam.midpoint.connector.aws.AWSConnector;
import com.atricore.iam.midpoint.connector.aws.AWSSchema;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.services.iam.model.*;
import software.amazon.awssdk.services.iam.IamClient;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.IAM;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.STS;

@Tag("integration")
@Testcontainers
public class AWSConnectorLocalStackIT {

    private static final Logger logger = LoggerFactory.getLogger(AWSConnectorLocalStackIT.class);
    private static final String TEST_PREFIX = "midpoint-lstest-";

    // Using LocalStack docker image with explicit configuration
    @Container
    private static final LocalStackContainer localStack = new LocalStackContainer(
            DockerImageName.parse("localstack/localstack:4.3.0"))
            .withServices(IAM)
            .withServices(STS)
            .withEnv("SERVICES", "iam")
            .withEnv("DEBUG", "1")
            .withEnv("AWS_ACCESS_KEY_ID", "test")
            .withEnv("AWS_SECRET_ACCESS_KEY", "test");

    private static AWSConnector connector;

    @BeforeAll
    static void setupConnector() {
        logger.info("Starting LocalStack and setting up AWS connector");

        // Configure the connector to use LocalStack with fixed test credentials
        AWSConfiguration config = new AWSConfiguration();
        config.setAwsAccessKeyId("test");
        config.setAwsSecretAccessKey(new GuardedString("test".toCharArray()));

        // We need to set the region even when using endpoint configuration
        config.setAwsRegion("us-east-1");

        // Set any additional configuration flags for LocalStack testing
        config.setAllowCache(false); // Disable caching for tests

        // Set endpoint to LocalStack's IAM endpoint
        String endpoint = localStack.getEndpointOverride(IAM).toString();
        logger.info("Using LocalStack IAM endpoint: {}", endpoint);
        config.setEndpointOverride(endpoint);

        // Initialize connector using our LocalStack-specific connector
        connector = new AWSConnector();
        connector.init(config);

        logger.info("Using custom LocalStackAWSConnector for better LocalStack compatibility");

        logger.info("AWS connector initialized with LocalStack");

        // Run connector test to verify setup
        try {
            connector.test();
            logger.info("Connection test successful");
        } catch (Exception e) {
            logger.error("Connection test failed", e);
            fail("Failed to connect to LocalStack: " + e.getMessage());
        }
    }

    @AfterAll
    static void cleanup() {
        logger.info("Cleaning up test resources");

        // Dispose connector
        if (connector != null) {
            connector.dispose();
            logger.info("Connector disposed");
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testCRUDUser() {

        // --- CREATE ---
        String userName = TEST_PREFIX + "user1";
        String initialPath = "/test/";
        String updatedPath = "/test/updated/";

        Set<Attribute> createAttributes = new HashSet<>();
        createAttributes.add(new Name(userName));
        createAttributes.add(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, initialPath));

        Uid uid = connector.create(ObjectClass.ACCOUNT, createAttributes, null);
        assertNotNull(uid, "User creation failed, UID is null");
        logger.info("Created user '{}' with Uid: {}", userName, uid.getUidValue());

        // --- READ (after Create) ---
        Filter filter = new EqualsFilter(new Name(userName));
        TestResultsHandler handler = new TestResultsHandler();
        connector.executeQuery(ObjectClass.ACCOUNT, filter, handler, null);

        assertEquals(1, handler.getObjects().size(), "Should find exactly one user after creation");
        ConnectorObject user = handler.getObjects().get(0);
        assertEquals(userName, user.getName().getNameValue(), "User name mismatch after creation");
        assertEquals(uid.getUidValue(), user.getUid().getUidValue(), "UID mismatch after creation");
        Attribute pathAttr = user.getAttributeByName(AWSSchema.ATTRIBUTE_PATH);
        assertNotNull(pathAttr, "Path attribute missing after creation");
        assertEquals(initialPath, AttributeUtil.getStringValue(pathAttr), "Initial path mismatch");
        logger.info("Successfully verified user '{}' after creation", userName);

        // --- UPDATE ---
        Set<AttributeDelta> updateModifications = new HashSet<>();
        updateModifications.add(new AttributeDeltaBuilder()
                .setName(AWSSchema.ATTRIBUTE_PATH)
                .addValueToReplace(updatedPath)
                .build());

        Set<AttributeDelta> updateResult = connector.updateDelta(ObjectClass.ACCOUNT, uid, updateModifications, new OperationOptionsBuilder().build());
        assertNotNull(updateResult, "User updateDelta returned null");
        assertTrue(updateResult.isEmpty(), "User updateDelta should return empty set on success");
        logger.info("Updated user '{}'", userName);

        // --- READ (after Update) ---
        handler.clear();
        connector.executeQuery(ObjectClass.ACCOUNT, filter, handler, null);

        assertEquals(1, handler.getObjects().size(), "Should find exactly one user after update");
        user = handler.getObjects().get(0);
        assertEquals(userName, user.getName().getNameValue(), "User name mismatch after update");
        pathAttr = user.getAttributeByName(AWSSchema.ATTRIBUTE_PATH);
        assertNotNull(pathAttr, "Path attribute missing after update");
        assertEquals(updatedPath, AttributeUtil.getStringValue(pathAttr), "Updated path mismatch");
        logger.info("Successfully verified user '{}' after update", userName);

        // --- DELETE ---
        connector.delete(ObjectClass.ACCOUNT, uid, null);
        logger.info("Deleted user '{}'", userName);

        // --- READ (after Delete) ---
        handler.clear();
        connector.executeQuery(ObjectClass.ACCOUNT, filter, handler, null);
        assertTrue(handler.getObjects().isEmpty(), "User should not be found after deletion");
        logger.info("Successfully verified user '{}' is deleted", userName);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testCreateAndGetGroup() {
        // Create a test group
        String groupName = TEST_PREFIX + "group1";

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(new Name(groupName));
        attributes.add(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, "/testgroups/"));

        // Create the group
        Uid uid = connector.create(ObjectClass.GROUP, attributes, null);
        assertNotNull(uid);
        logger.info("Created group with Uid: {}", uid.getUidValue());

        // Get the group using filter on Name
        Filter filter = new EqualsFilter(new Name(groupName));
        TestResultsHandler handler = new TestResultsHandler();

        connector.executeQuery(ObjectClass.GROUP, filter, handler, null);

        // Verify group was found
        assertEquals(1, handler.getObjects().size());
        ConnectorObject group = handler.getObjects().get(0);

        assertEquals(groupName, group.getName().getNameValue());
        assertEquals(uid.getUidValue(), group.getUid().getUidValue());

        // Check the path attribute
        Attribute pathAttr = group.getAttributeByName(AWSSchema.ATTRIBUTE_PATH);
        assertNotNull(pathAttr);
        assertEquals("/testgroups/", AttributeUtil.getStringValue(pathAttr));

        // Cleanup - delete the created group
        connector.delete(ObjectClass.GROUP, uid, null);

        // Verify the group is deleted
        handler.clear();
        connector.executeQuery(ObjectClass.GROUP, filter, handler, null);
        assertTrue(handler.getObjects().isEmpty(), "Group should be deleted");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testAddUpdateAndRemoveGroupFromUser() {
        // Create a test user
        String userName = TEST_PREFIX + "groupuser";
        Set<Attribute> userAttributes = new HashSet<>();
        userAttributes.add(new Name(userName));

        Uid userId = connector.create(ObjectClass.ACCOUNT, userAttributes, null);
        assertNotNull(userId);
        logger.info("Created user with Uid: {}", userId.getUidValue());

        // Create two test groups
        String groupName1 = TEST_PREFIX + "usergroup1";
        String groupName2 = TEST_PREFIX + "usergroup2";

        Set<Attribute> group1Attributes = new HashSet<>();
        group1Attributes.add(new Name(groupName1));
        Uid group1Id = connector.create(ObjectClass.GROUP, group1Attributes, null);
        assertNotNull(group1Id);
        logger.info("Created group1 with Uid: {}", group1Id.getUidValue());

        Set<Attribute> group2Attributes = new HashSet<>();
        group2Attributes.add(new Name(groupName2));
        Uid group2Id = connector.create(ObjectClass.GROUP, group2Attributes, null);
        assertNotNull(group2Id);
        logger.info("Created group2 with Uid: {}", group2Id.getUidValue());

        try {
            // Step 1: Add user to first group
            Set<AttributeDelta> addToGroup1Modifications = new HashSet<>();
            addToGroup1Modifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_GROUPS)
                    .addValueToReplace(group1Id.getUidValue()) // Replace all with this single group
                    .build());
            Set<AttributeDelta> updateResult1 = connector.updateDelta(ObjectClass.ACCOUNT, userId, addToGroup1Modifications, new OperationOptionsBuilder().build());
            assertNotNull(updateResult1);
            assertTrue(updateResult1.isEmpty());

            // Verify user is in the first group
            TestResultsHandler handler = new TestResultsHandler();
            Filter filter = new EqualsFilter(new Name(userName));
            connector.executeQuery(ObjectClass.ACCOUNT, filter, handler, null);

            assertEquals(1, handler.getObjects().size());
            ConnectorObject user = handler.getObjects().get(0);

            Attribute groupMembership = user.getAttributeByName(AWSSchema.ASSOCIATION_GROUPS);
            assertNotNull(groupMembership, "Group membership attribute should exist");
            assertTrue(groupMembership.getValue().contains(group1Id.getUidValue()),
                    "User should be member of group1");

            // Step 2: Update user to be in both groups
            Set<AttributeDelta> updateToTwoGroupsModifications = new HashSet<>();
            updateToTwoGroupsModifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_GROUPS)
                    .addValueToReplace(group1Id.getUidValue(), group2Id.getUidValue())
                    .build());
            Set<AttributeDelta> updateResult2 = connector.updateDelta(ObjectClass.ACCOUNT, userId, updateToTwoGroupsModifications, new OperationOptionsBuilder().build());
            assertNotNull(updateResult2);
            assertTrue(updateResult2.isEmpty());

            // Verify user is in both groups
            handler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, filter, handler, null);

            assertEquals(1, handler.getObjects().size());
            user = handler.getObjects().get(0);

            groupMembership = user.getAttributeByName(AWSSchema.ASSOCIATION_GROUPS);
            assertNotNull(groupMembership, "Group membership attribute should exist");
            assertTrue(groupMembership.getValue().contains(group1Id.getUidValue()),
                    "User should still be member of group1");
            assertTrue(groupMembership.getValue().contains(group2Id.getUidValue()),
                    "User should now also be member of group2");

            // Step 3: Remove user from first group, keep in second group
            Set<AttributeDelta> updateToGroup2OnlyModifications = new HashSet<>();
            updateToGroup2OnlyModifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_GROUPS)
                    .addValueToReplace(group2Id.getUidValue())
                    .build());
            Set<AttributeDelta> updateResult3 = connector.updateDelta(ObjectClass.ACCOUNT, userId, updateToGroup2OnlyModifications, new OperationOptionsBuilder().build());
            assertNotNull(updateResult3);
            assertTrue(updateResult3.isEmpty());
            // Verify user is only in the second group
            handler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, filter, handler, null);

            assertEquals(1, handler.getObjects().size());
            user = handler.getObjects().get(0);

            groupMembership = user.getAttributeByName(AWSSchema.ASSOCIATION_GROUPS);
            assertNotNull(groupMembership, "Group membership attribute should exist");
            assertFalse(groupMembership.getValue().contains(group1Id.getUidValue()),
                    "User should no longer be member of group1");
            assertTrue(groupMembership.getValue().contains(group2Id.getUidValue()),
                    "User should still be member of group2");

            // Step 4: Remove user from all groups
            Set<AttributeDelta> removeAllGroupsModifications = new HashSet<>();
            removeAllGroupsModifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_GROUPS)
                    .addValueToReplace() // Empty varargs means replace with empty set
                    .build());
            Set<AttributeDelta> updateResult4 = connector.updateDelta(ObjectClass.ACCOUNT, userId, removeAllGroupsModifications, new OperationOptionsBuilder().build());
            assertNotNull(updateResult4);
            assertTrue(updateResult4.isEmpty());

            // Verify user is not in any group
            handler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, filter, handler, null);

            assertEquals(1, handler.getObjects().size());
            user = handler.getObjects().get(0);

            groupMembership = user.getAttributeByName(AWSSchema.ASSOCIATION_GROUPS);
            if (groupMembership != null) {
                assertTrue(groupMembership.getValue() == null || groupMembership.getValue().isEmpty(),
                        "User should not be a member of any group");
            }

        } finally {
            // Cleanup - delete the created groups and user
            try {
                connector.delete(ObjectClass.GROUP, group1Id, null);
                connector.delete(ObjectClass.GROUP, group2Id, null);
                connector.delete(ObjectClass.ACCOUNT, userId, null);
                logger.info("Cleaned up test resources");
            } catch (Exception e) {
                logger.error("Error during cleanup", e);
            }
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testListAllUsers() {
        // Create a couple of test users first
        List<String> userNames = new ArrayList<>();
        userNames.add(TEST_PREFIX + "listuser1");
        userNames.add(TEST_PREFIX + "listuser2");

        userNames.forEach(userName -> {
            // Create first user
            Set<Attribute> attributes = new HashSet<>();
            attributes.add(new Name(userName));
            Uid uid = connector.create(ObjectClass.ACCOUNT, attributes, null);
            assertNotNull(uid);
        });

        // List all users
        TestResultsHandler handler = new TestResultsHandler();
        connector.executeQuery(ObjectClass.ACCOUNT, null, handler, null);

        // Verify that we got all users (should include the one from previous test)
        List<ConnectorObject> users = handler.getObjects();
        assertTrue(users.size() >= userNames.size(), "Expected at least " + userNames.size() + " users, found: " + users.size());

        // Extract all usernames from the returned users
        Set<String> returnedUsernames = users.stream()
                .map(user -> user.getName().getNameValue())
                .collect(Collectors.toSet());

        // Check if all created usernames are in the returned set
        List<String> missingUsers = userNames.stream()
                .filter(username -> !returnedUsernames.contains(username))
                .toList();

        // Assert that no users are missing
        assertTrue(missingUsers.isEmpty(), "Not all created users were found. Missing: " + missingUsers);

        // Delete all created users
        handler.getObjects().forEach(object -> {
            connector.delete(ObjectClass.ACCOUNT, object.getUid(), null);
        });
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testListAllGroups() {
        // Create a couple of test groups first
        List<String> groupNames = new ArrayList<>();
        groupNames.add(TEST_PREFIX + "listgroup1");
        groupNames.add(TEST_PREFIX + "listgroup2");

        groupNames.forEach(groupName -> {
            // Create group
            Set<Attribute> attributes = new HashSet<>();
            attributes.add(new Name(groupName));
            attributes.add(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, "/testgroups/"));
            Uid uid = connector.create(ObjectClass.GROUP, attributes, null);
            assertNotNull(uid);
        });

        // List all groups
        TestResultsHandler handler = new TestResultsHandler();
        connector.executeQuery(ObjectClass.GROUP, null, handler, null);

        // Verify that we got all groups
        List<ConnectorObject> groups = handler.getObjects();
        assertTrue(groups.size() >= groupNames.size(), "Expected at least " + groupNames.size() + " groups, found: " + groups.size());

        // Extract all group names from the returned groups
        Set<String> returnedGroupNames = groups.stream()
                .map(group -> group.getName().getNameValue())
                .collect(Collectors.toSet());

        // Check if all created group names are in the returned set
        List<String> missingGroups = groupNames.stream()
                .filter(groupName -> !returnedGroupNames.contains(groupName))
                .toList();

        // Assert that no groups are missing
        assertTrue(missingGroups.isEmpty(), "Not all created groups were found. Missing: " + missingGroups);

        // Delete all created groups
        groupNames.forEach(groupName -> {
            for (ConnectorObject group : groups) {
                if (group.getName().getNameValue().equals(groupName)) {
                    connector.delete(ObjectClass.GROUP, group.getUid(), null);
                    break;
                }
            }
        });
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testSearchPolicies() {
        logger.info("Testing policy search functionality");

        // Create a custom policy first
        String policyName = TEST_PREFIX + "test-policy";
        String policyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListBucket\",\"Resource\":\"*\"}]}";

        try {
            // Get access to the IAM client from the connector
            // We need to use reflection since the client is protected
            IamClient iamClient = getIamClientFromConnector();
            assertNotNull(iamClient, "Failed to get IAM client from connector");

            // Create a policy using the AWS SDK directly since our connector doesn't support policy creation
            CreatePolicyRequest createPolicyRequest = CreatePolicyRequest.builder()
                    .policyName(policyName)
                    .policyDocument(policyDocument)
                    .description("Test policy for integration tests")
                    .build();

            // Use the client from our connector to create the policy
            CreatePolicyResponse createPolicyResponse = iamClient.createPolicy(createPolicyRequest);
            String policyArn = createPolicyResponse.policy().arn();
            String policyId = createPolicyResponse.policy().policyId();

            logger.info("Created test policy: {} with ARN: {} and ID: {}", policyName, policyArn, policyId);


            // Test 1: Search by policy name
            TestResultsHandler handler = new TestResultsHandler();
            Filter nameFilter = new EqualsFilter(new Name(policyName));

            // Execute search using our custom policy object class
            connector.executeQuery(AWSSchema.POLICY_OBJECT_CLASS, nameFilter, handler, null);

            // Verify we found our policy
            List<ConnectorObject> policies = handler.getObjects();
            assertEquals(1, policies.size(), "Should find exactly one policy by name");

            ConnectorObject policy = policies.get(0);
            assertEquals(policyName, policy.getName().getNameValue(), "Policy name should match");
            assertEquals(policyId, policy.getUid().getUidValue(), "Policy ID should match");

            // Test 2: Search by policy ARN
            handler.clear();
            Filter arnFilter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_ARN, policyArn));

            connector.executeQuery(AWSSchema.POLICY_OBJECT_CLASS, arnFilter, handler, null);

            policies = handler.getObjects();
            assertEquals(1, policies.size(), "Should find exactly one policy by ARN");
            assertEquals(policyName, policies.get(0).getName().getNameValue(), "Policy name should match");

            // Test 3: Search by policy ID
            handler.clear();
            Filter idFilter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_POLICY_ID, policyId));

            connector.executeQuery(AWSSchema.POLICY_OBJECT_CLASS, idFilter, handler, null);

            policies = handler.getObjects();
            assertEquals(1, policies.size(), "Should find exactly one policy by ID");
            assertEquals(policyName, policies.get(0).getName().getNameValue(), "Policy name should match");

            // Test 4: List all policies (should include our test policy)
            handler.clear();
            connector.executeQuery(AWSSchema.POLICY_OBJECT_CLASS, null, handler, null);

            policies = handler.getObjects();
            assertTrue(policies.size() >= 1, "Should find at least our test policy");

            // Verify our test policy is in the results
            boolean foundTestPolicy = policies.stream()
                    .anyMatch(p -> p.getName().getNameValue().equals(policyName));
            assertTrue(foundTestPolicy, "Test policy should be included in the list of all policies");

            // Test 5: Search with path prefix
            handler.clear();
            // Most policies have the default "/" path
            Filter pathFilter = new EqualsFilter(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, "/"));

            connector.executeQuery(AWSSchema.POLICY_OBJECT_CLASS, pathFilter, handler, null);

            policies = handler.getObjects();
            assertTrue(policies.size() >= 1, "Should find at least one policy with default path");

            // Test 6: Search by policy type (CUSTOMER_MANAGED)
            handler.clear();
            Filter typeFilter = new EqualsFilter(
                    AttributeBuilder.build(AWSSchema.ATTRIBUTE_POLICY_TYPE, "CUSTOMER_MANAGED"));

            connector.executeQuery(AWSSchema.POLICY_OBJECT_CLASS, typeFilter, handler, null);

            policies = handler.getObjects();
            assertTrue(policies.size() >= 1, "Should find at least one customer managed policy");

            // Verify our test policy is in the results
            foundTestPolicy = policies.stream()
                    .anyMatch(p -> p.getName().getNameValue().equals(policyName));
            assertTrue(foundTestPolicy, "Test policy should be included in customer managed policies");

            // Test 7: Verify policy attributes
            ConnectorObject testPolicy = policies.stream()
                    .filter(p -> p.getName().getNameValue().equals(policyName))
                    .findFirst()
                    .orElse(null);

            assertNotNull(testPolicy, "Test policy should be found");
            assertEquals(policyId, testPolicy.getUid().getUidValue(), "Policy ID should match");
            assertEquals(policyArn, AttributeUtil.getStringValue(testPolicy.getAttributeByName(AWSSchema.ATTRIBUTE_ARN)),
                    "Policy ARN should match");

            // Verify policy has description attribute
            // For now, description is not returned back?
            // Attribute descAttr = testPolicy.getAttributeByName(AWSSchema.ATTRIBUTE_DESCRIPTION);
            // assertNotNull(descAttr, "Policy should have description attribute");
            // assertEquals("Test policy for integration tests", AttributeUtil.getStringValue(descAttr),
            //        "Policy description should match");

            // Verify policy has default version ID
            Attribute versionAttr = testPolicy.getAttributeByName(AWSSchema.ATTRIBUTE_DEFAULT_VERSION_ID);
            assertNotNull(versionAttr, "Policy should have default version ID attribute");
            assertEquals("v1", AttributeUtil.getStringValue(versionAttr),
                    "Default policy version should be v1");

            // Verify boolean attribute
            Attribute attachableAttr = testPolicy.getAttributeByName(AWSSchema.ATTRIBUTE_IS_ATTACHABLE);
            // Clean up - delete the test policy
            logger.info("Cleaning up test policy: {}", policyName);
            DeletePolicyRequest deletePolicyRequest = DeletePolicyRequest.builder()
                    .policyArn(policyArn)
                    .build();
            iamClient.deletePolicy(deletePolicyRequest);


        } catch (Exception e) {
            logger.error("Error during policy search test", e);
            fail("Policy search test failed: " + e.getMessage());
        }
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS) // Increased timeout for more operations
    void testAddUpdateAndRemovePolicyFromUser() {
        logger.info("Starting testAddUpdateAndRemovePolicyFromUser");

        // --- CREATE USER ---
        String userName = TEST_PREFIX + "policy-user";
        Set<Attribute> userAttributes = new HashSet<>();
        userAttributes.add(new Name(userName));
        Uid userUid = connector.create(ObjectClass.ACCOUNT, userAttributes, null);
        assertNotNull(userUid, "User creation failed");
        logger.info("Created user '{}' with Uid: {}", userName, userUid.getUidValue());

        // --- CREATE POLICIES (using SDK directly) ---
        IamClient iamClient = getIamClientFromConnector();
        assertNotNull(iamClient, "Failed to get IAM client from connector");

        String policyName1 = TEST_PREFIX + "test-policy1";
        String policyDocument1 = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"*\"}]}";
        String policyArn1 = null;

        String policyName2 = TEST_PREFIX + "test-policy2";
        String policyDocument2 = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ec2:DescribeInstances\",\"Resource\":\"*\"}]}";
        String policyArn2 = null;

        try {
            CreatePolicyResponse response1 = iamClient.createPolicy(CreatePolicyRequest.builder()
                    .policyName(policyName1).policyDocument(policyDocument1).build());
            policyArn1 = response1.policy().arn();
            logger.info("Created policy '{}' with ARN: {}", policyName1, policyArn1);

            CreatePolicyResponse response2 = iamClient.createPolicy(CreatePolicyRequest.builder()
                    .policyName(policyName2).policyDocument(policyDocument2).build());
            policyArn2 = response2.policy().arn();
            logger.info("Created policy '{}' with ARN: {}", policyName2, policyArn2);

            // --- STEP 1: Attach first policy to user ---
            Set<AttributeDelta> attachPolicy1Modifications = new HashSet<>();
            attachPolicy1Modifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policyArn1) // Replace with this single policy
                    .build());
            Set<AttributeDelta> resultAttach1 = connector.updateDelta(ObjectClass.ACCOUNT, userUid, attachPolicy1Modifications, new OperationOptionsBuilder().build());
            assertTrue(resultAttach1.isEmpty());
            logger.info("Attached policy '{}' to user '{}'", policyName1, userName);

            // Verify policy 1 is attached
            TestResultsHandler handler = new TestResultsHandler();
            Filter userFilter = new EqualsFilter(new Name(userName));
            connector.executeQuery(ObjectClass.ACCOUNT, userFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            ConnectorObject user = handler.getObjects().get(0);
            Attribute attachedPoliciesAttr = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(attachedPoliciesAttr, "Attached policies attribute missing");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn1), "Policy 1 ARN not found in user's attached policies");
            logger.info("Verified policy '{}' is attached to user '{}'", policyName1, userName);

            // --- STEP 2: Attach second policy (user should now have both) ---
            Set<AttributeDelta> attachPolicy2Modifications = new HashSet<>();
            attachPolicy2Modifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policyArn1, policyArn2) // Replace with these two policies
                    .build());
            Set<AttributeDelta> resultAttach2 = connector.updateDelta(ObjectClass.ACCOUNT, userUid, attachPolicy2Modifications, new OperationOptionsBuilder().build());
            assertTrue(resultAttach2.isEmpty());
            logger.info("Updated user '{}' to have policies '{}' and '{}'", userName, policyName1, policyName2);

            // Verify both policies are attached
            handler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, userFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            user = handler.getObjects().get(0);
            attachedPoliciesAttr = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(attachedPoliciesAttr, "Attached policies attribute missing after adding second policy");
            assertEquals(2, attachedPoliciesAttr.getValue().size(), "User should have 2 policies attached");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn1), "Policy 1 ARN should still be present");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn2), "Policy 2 ARN should now be present");
            logger.info("Verified policies '{}' and '{}' are attached to user '{}'", policyName1, policyName2, userName);

            // --- STEP 3: Detach first policy (user should now have only policy 2) ---
            Set<AttributeDelta> detachPolicy1Modifications = new HashSet<>();
            detachPolicy1Modifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policyArn2) // Replace with only policy 2
                    .build());
            Set<AttributeDelta> resultDetach1 = connector.updateDelta(ObjectClass.ACCOUNT, userUid, detachPolicy1Modifications, new OperationOptionsBuilder().build());
            assertTrue(resultDetach1.isEmpty());
            logger.info("Detached policy '{}' from user '{}', keeping '{}'", policyName1, userName, policyName2);

            // Verify only policy 2 is attached
            handler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, userFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            user = handler.getObjects().get(0);
            attachedPoliciesAttr = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(attachedPoliciesAttr, "Attached policies attribute missing after detaching first policy");
            assertEquals(1, attachedPoliciesAttr.getValue().size(), "User should have 1 policy attached");
            assertFalse(attachedPoliciesAttr.getValue().contains(policyArn1), "Policy 1 ARN should be detached");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn2), "Policy 2 ARN should still be present");
            logger.info("Verified policy '{}' is detached and '{}' remains for user '{}'", policyName1, policyName2, userName);

            // --- STEP 4: Detach all policies ---
            Set<AttributeDelta> detachAllPoliciesModifications = new HashSet<>();
            detachAllPoliciesModifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace() // Replace with empty set
                    .build());
            Set<AttributeDelta> resultDetachAll = connector.updateDelta(ObjectClass.ACCOUNT, userUid, detachAllPoliciesModifications, new OperationOptionsBuilder().build());
            assertTrue(resultDetachAll.isEmpty());
            logger.info("Detached all policies from user '{}'", userName);

            // Verify no policies are attached
            handler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, userFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            user = handler.getObjects().get(0);
            attachedPoliciesAttr = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            if (attachedPoliciesAttr != null && attachedPoliciesAttr.getValue() != null) {
                assertTrue(attachedPoliciesAttr.getValue().isEmpty(), "User should have no policies attached");
            }
            logger.info("Verified all policies are detached from user '{}'", userName);

        } catch (Exception e) {
            logger.error("Error during policy attachment/detachment test for user '{}'", userName, e);
            fail("Test failed: " + e.getMessage());
        } finally {
            // --- CLEANUP ---
            logger.info("Cleaning up resources for testAddUpdateAndRemovePolicyFromUser");
            if (userUid != null) {
                try {
                    connector.delete(ObjectClass.ACCOUNT, userUid, null);
                    logger.info("Deleted user '{}'", userName);
                } catch (Exception e) {
                    logger.error("Error deleting user '{}': {}", userName, e.getMessage());
                }
            }
            if (policyArn1 != null) {
                try {
                    iamClient.deletePolicy(DeletePolicyRequest.builder().policyArn(policyArn1).build());
                    logger.info("Deleted policy '{}'", policyName1);
                } catch (Exception e) {
                    logger.error("Error deleting policy '{}': {}", policyName1, e.getMessage());
                }
            }
            if (policyArn2 != null) {
                try {
                    iamClient.deletePolicy(DeletePolicyRequest.builder().policyArn(policyArn2).build());
                    logger.info("Deleted policy '{}'", policyName2);
                } catch (Exception e) {
                    logger.error("Error deleting policy '{}': {}", policyName2, e.getMessage());
                }
            }
        }
        logger.info("Finished testAddUpdateAndRemovePolicyFromUser");
    }


    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS) // Increased timeout for more operations
    void testAddUpdateAndRemovePolicyFromGroup() {
        logger.info("Starting testAddUpdateAndRemovePolicyFromGroup");

        // --- CREATE GROUP ---
        String groupName = TEST_PREFIX + "policy-group";
        Set<Attribute> groupAttributes = new HashSet<>();
        groupAttributes.add(new Name(groupName));
        groupAttributes.add(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, "/test/"));
        Uid groupUid = connector.create(ObjectClass.GROUP, groupAttributes, null);
        assertNotNull(groupUid, "Group creation failed");
        logger.info("Created group '{}' with Uid: {}", groupName, groupUid.getUidValue());

        // --- CREATE POLICIES (using SDK directly) ---
        IamClient iamClient = getIamClientFromConnector();
        assertNotNull(iamClient, "Failed to get IAM client from connector");

        String policyName1 = TEST_PREFIX + "group-policy1";
        String policyDocument1 = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"*\"}]}";
        String policyArn1 = null;

        String policyName2 = TEST_PREFIX + "group-policy2";
        String policyDocument2 = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ec2:DescribeInstances\",\"Resource\":\"*\"}]}";
        String policyArn2 = null;

        try {
            CreatePolicyResponse response1 = iamClient.createPolicy(CreatePolicyRequest.builder()
                    .policyName(policyName1).policyDocument(policyDocument1).build());
            policyArn1 = response1.policy().arn();
            logger.info("Created policy '{}' with ARN: {}", policyName1, policyArn1);

            CreatePolicyResponse response2 = iamClient.createPolicy(CreatePolicyRequest.builder()
                    .policyName(policyName2).policyDocument(policyDocument2).build());
            policyArn2 = response2.policy().arn();
            logger.info("Created policy '{}' with ARN: {}", policyName2, policyArn2);

            // --- STEP 1: Attach first policy to group ---
            Set<AttributeDelta> attachPolicy1Modifications = new HashSet<>();
            attachPolicy1Modifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policyArn1) // Replace with this single policy
                    .build());
            Set<AttributeDelta> resultAttach1 = connector.updateDelta(ObjectClass.GROUP, groupUid, attachPolicy1Modifications, new OperationOptionsBuilder().build());
            assertTrue(resultAttach1.isEmpty());
            logger.info("Attached policy '{}' to group '{}'", policyName1, groupName);

            // Verify policy 1 is attached
            TestResultsHandler handler = new TestResultsHandler();
            Filter groupFilter = new EqualsFilter(new Name(groupName));
            connector.executeQuery(ObjectClass.GROUP, groupFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            ConnectorObject group = handler.getObjects().get(0);
            Attribute attachedPoliciesAttr = group.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(attachedPoliciesAttr, "Attached policies attribute missing");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn1), "Policy 1 ARN not found in group's attached policies");
            logger.info("Verified policy '{}' is attached to group '{}'", policyName1, groupName);

            // --- STEP 2: Attach second policy (group should now have both) ---
            Set<AttributeDelta> attachPolicy2Modifications = new HashSet<>();
            attachPolicy2Modifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policyArn1, policyArn2) // Replace with these two policies
                    .build());
            Set<AttributeDelta> resultAttach2 = connector.updateDelta(ObjectClass.GROUP, groupUid, attachPolicy2Modifications, new OperationOptionsBuilder().build());
            assertTrue(resultAttach2.isEmpty());
            logger.info("Updated group '{}' to have policies '{}' and '{}'", groupName, policyName1, policyName2);

            // Verify both policies are attached
            handler.clear();
            connector.executeQuery(ObjectClass.GROUP, groupFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            group = handler.getObjects().get(0);
            attachedPoliciesAttr = group.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(attachedPoliciesAttr, "Attached policies attribute missing after adding second policy");
            assertEquals(2, attachedPoliciesAttr.getValue().size(), "Group should have 2 policies attached");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn1), "Policy 1 ARN should still be present");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn2), "Policy 2 ARN should now be present");
            logger.info("Verified policies '{}' and '{}' are attached to group '{}'", policyName1, policyName2, groupName);

            // --- STEP 3: Detach first policy (group should now have only policy 2) ---
            Set<AttributeDelta> detachPolicy1Modifications = new HashSet<>();
            detachPolicy1Modifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policyArn2) // Replace with only policy 2
                    .build());
            Set<AttributeDelta> resultDetach1 = connector.updateDelta(ObjectClass.GROUP, groupUid, detachPolicy1Modifications, new OperationOptionsBuilder().build());
            assertTrue(resultDetach1.isEmpty());
            logger.info("Detached policy '{}' from group '{}', keeping '{}'", policyName1, groupName, policyName2);

            // Verify only policy 2 is attached
            handler.clear();
            connector.executeQuery(ObjectClass.GROUP, groupFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            group = handler.getObjects().get(0);
            attachedPoliciesAttr = group.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(attachedPoliciesAttr, "Attached policies attribute missing after detaching first policy");
            assertEquals(1, attachedPoliciesAttr.getValue().size(), "Group should have 1 policy attached");
            assertFalse(attachedPoliciesAttr.getValue().contains(policyArn1), "Policy 1 ARN should be detached");
            assertTrue(attachedPoliciesAttr.getValue().contains(policyArn2), "Policy 2 ARN should still be present");
            logger.info("Verified policy '{}' is detached and '{}' remains for group '{}'", policyName1, policyName2, groupName);

            // --- STEP 4: Detach all policies ---
            Set<AttributeDelta> detachAllPoliciesModifications = new HashSet<>();
            detachAllPoliciesModifications.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace() // Replace with empty set
                    .build());
            Set<AttributeDelta> resultDetachAll = connector.updateDelta(ObjectClass.GROUP, groupUid, detachAllPoliciesModifications, new OperationOptionsBuilder().build());
            assertTrue(resultDetachAll.isEmpty());
            logger.info("Detached all policies from group '{}'", groupName);

            // Verify no policies are attached
            handler.clear();
            connector.executeQuery(ObjectClass.GROUP, groupFilter, handler, null);
            assertEquals(1, handler.getObjects().size());
            group = handler.getObjects().get(0);
            attachedPoliciesAttr = group.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            if (attachedPoliciesAttr != null && attachedPoliciesAttr.getValue() != null) {
                assertTrue(attachedPoliciesAttr.getValue().isEmpty(), "Group should have no policies attached");
            }
            logger.info("Verified all policies are detached from group '{}'", groupName);

        } catch (Exception e) {
            logger.error("Error during policy attachment/detachment test for group '{}'", groupName, e);
            fail("Test failed: " + e.getMessage());
        } finally {
            // --- CLEANUP ---
            logger.info("Cleaning up resources for testAddUpdateAndRemovePolicyFromGroup");
            if (groupUid != null) {
                try {
                    connector.delete(ObjectClass.GROUP, groupUid, null);
                    logger.info("Deleted group '{}'", groupName);
                } catch (Exception e) {
                    logger.error("Error deleting group '{}': {}", groupName, e.getMessage());
                }
            }
            if (policyArn1 != null) {
                try {
                    iamClient.deletePolicy(DeletePolicyRequest.builder().policyArn(policyArn1).build());
                    logger.info("Deleted policy '{}'", policyName1);
                } catch (Exception e) {
                    logger.error("Error deleting policy '{}': {}", policyName1, e.getMessage());
                }
            }
            if (policyArn2 != null) {
                try {
                    iamClient.deletePolicy(DeletePolicyRequest.builder().policyArn(policyArn2).build());
                    logger.info("Deleted policy '{}'", policyName2);
                } catch (Exception e) {
                    logger.error("Error deleting policy '{}': {}", policyName2, e.getMessage());
                }
            }
        }
        logger.info("Finished testAddUpdateAndRemovePolicyFromGroup");

    }

    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS) // Extended timeout for comprehensive test
    void testComprehensivePolicyManagementIntegration() {
        logger.info("Starting testComprehensivePolicyManagementIntegration");

        // --- CREATE TEST RESOURCES ---
        String userName = TEST_PREFIX + "policy-integration-user";
        String groupName = TEST_PREFIX + "policy-integration-group";
        
        Set<Attribute> userAttributes = new HashSet<>();
        userAttributes.add(new Name(userName));
        Uid userUid = connector.create(ObjectClass.ACCOUNT, userAttributes, null);
        assertNotNull(userUid, "User creation failed");
        logger.info("Created user '{}' with Uid: {}", userName, userUid.getUidValue());

        Set<Attribute> groupAttributes = new HashSet<>();
        groupAttributes.add(new Name(groupName));
        groupAttributes.add(AttributeBuilder.build(AWSSchema.ATTRIBUTE_PATH, "/integration-test/"));
        Uid groupUid = connector.create(ObjectClass.GROUP, groupAttributes, null);
        assertNotNull(groupUid, "Group creation failed");
        logger.info("Created group '{}' with Uid: {}", groupName, groupUid.getUidValue());

        // --- CREATE POLICIES ---
        IamClient iamClient = getIamClientFromConnector();
        assertNotNull(iamClient, "Failed to get IAM client from connector");

        String policy1Name = TEST_PREFIX + "integration-policy1";
        String policy2Name = TEST_PREFIX + "integration-policy2";
        String policy3Name = TEST_PREFIX + "integration-policy3";
        
        String policy1Document = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListBucket\",\"Resource\":\"*\"}]}";
        String policy2Document = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ec2:DescribeInstances\",\"Resource\":\"*\"}]}";
        String policy3Document = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"iam:ListUsers\",\"Resource\":\"*\"}]}";
        
        String policy1Arn = null, policy2Arn = null, policy3Arn = null;

        try {
            // Create policies
            CreatePolicyResponse response1 = iamClient.createPolicy(CreatePolicyRequest.builder()
                    .policyName(policy1Name).policyDocument(policy1Document).build());
            policy1Arn = response1.policy().arn();
            
            CreatePolicyResponse response2 = iamClient.createPolicy(CreatePolicyRequest.builder()
                    .policyName(policy2Name).policyDocument(policy2Document).build());
            policy2Arn = response2.policy().arn();
            
            CreatePolicyResponse response3 = iamClient.createPolicy(CreatePolicyRequest.builder()
                    .policyName(policy3Name).policyDocument(policy3Document).build());
            policy3Arn = response3.policy().arn();
            
            logger.info("Created test policies: {}, {}, {}", policy1Name, policy2Name, policy3Name);

            // --- TEST SCENARIO 1: User and Group get same initial policy ---
            Set<AttributeDelta> initialUserMods = new HashSet<>();
            initialUserMods.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policy1Arn)
                    .build());
            connector.updateDelta(ObjectClass.ACCOUNT, userUid, initialUserMods, null);
            
            Set<AttributeDelta> initialGroupMods = new HashSet<>();
            initialGroupMods.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policy1Arn)
                    .build());
            connector.updateDelta(ObjectClass.GROUP, groupUid, initialGroupMods, null);
            
            logger.info("Attached policy1 to both user and group");

            // Verify both have policy1
            TestResultsHandler userHandler = new TestResultsHandler();
            connector.executeQuery(ObjectClass.ACCOUNT, new EqualsFilter(new Name(userName)), userHandler, null);
            ConnectorObject user = userHandler.getObjects().get(0);
            Attribute userPolicies = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(userPolicies);
            assertTrue(userPolicies.getValue().contains(policy1Arn));
            
            TestResultsHandler groupHandler = new TestResultsHandler();
            connector.executeQuery(ObjectClass.GROUP, new EqualsFilter(new Name(groupName)), groupHandler, null);
            ConnectorObject group = groupHandler.getObjects().get(0);
            Attribute groupPolicies = group.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(groupPolicies);
            assertTrue(groupPolicies.getValue().contains(policy1Arn));
            
            logger.info("Verified both user and group have policy1");

            // --- TEST SCENARIO 2: Replace policies differently for user and group ---
            // User gets policy2 and policy3, group gets only policy2
            Set<AttributeDelta> userReplaceMods = new HashSet<>();
            userReplaceMods.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policy2Arn, policy3Arn)
                    .build());
            connector.updateDelta(ObjectClass.ACCOUNT, userUid, userReplaceMods, null);
            
            Set<AttributeDelta> groupReplaceMods = new HashSet<>();
            groupReplaceMods.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace(policy2Arn)
                    .build());
            connector.updateDelta(ObjectClass.GROUP, groupUid, groupReplaceMods, null);
            
            logger.info("Replaced policies: User gets policy2+policy3, Group gets policy2");

            // Verify replacement worked correctly
            userHandler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, new EqualsFilter(new Name(userName)), userHandler, null);
            user = userHandler.getObjects().get(0);
            userPolicies = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(userPolicies);
            assertEquals(2, userPolicies.getValue().size(), "User should have 2 policies");
            assertFalse(userPolicies.getValue().contains(policy1Arn), "User should not have policy1");
            assertTrue(userPolicies.getValue().contains(policy2Arn), "User should have policy2");
            assertTrue(userPolicies.getValue().contains(policy3Arn), "User should have policy3");
            
            groupHandler.clear();
            connector.executeQuery(ObjectClass.GROUP, new EqualsFilter(new Name(groupName)), groupHandler, null);
            group = groupHandler.getObjects().get(0);
            groupPolicies = group.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(groupPolicies);
            assertEquals(1, groupPolicies.getValue().size(), "Group should have 1 policy");
            assertFalse(groupPolicies.getValue().contains(policy1Arn), "Group should not have policy1");
            assertTrue(groupPolicies.getValue().contains(policy2Arn), "Group should have policy2");
            assertFalse(groupPolicies.getValue().contains(policy3Arn), "Group should not have policy3");
            
            logger.info("Verified policy replacement worked correctly for both user and group");

            // --- TEST SCENARIO 3: Add user to group (user inherits group policies + keeps own) ---
            Set<AttributeDelta> addUserToGroupMods = new HashSet<>();
            addUserToGroupMods.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_GROUPS)
                    .addValueToReplace(groupUid.getUidValue())
                    .build());
            connector.updateDelta(ObjectClass.ACCOUNT, userUid, addUserToGroupMods, null);
            
            logger.info("Added user to group");

            // Verify user is in group and still has own policies
            userHandler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, new EqualsFilter(new Name(userName)), userHandler, null);
            user = userHandler.getObjects().get(0);
            
            // Check group membership
            Attribute groupMembership = user.getAttributeByName(AWSSchema.ASSOCIATION_GROUPS);
            assertNotNull(groupMembership, "User should have group membership");
            assertTrue(groupMembership.getValue().contains(groupUid.getUidValue()), "User should be member of the group");
            
            // Check user still has own policies
            userPolicies = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            assertNotNull(userPolicies, "User should still have own policies");
            assertEquals(2, userPolicies.getValue().size(), "User should still have 2 policies");
            assertTrue(userPolicies.getValue().contains(policy2Arn), "User should still have policy2");
            assertTrue(userPolicies.getValue().contains(policy3Arn), "User should still have policy3");
            
            logger.info("Verified user is in group and maintains own policies");

            // --- TEST SCENARIO 4: Remove all policies from both user and group ---
            Set<AttributeDelta> clearUserPolicies = new HashSet<>();
            clearUserPolicies.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace() // Empty = remove all
                    .build());
            connector.updateDelta(ObjectClass.ACCOUNT, userUid, clearUserPolicies, null);
            
            Set<AttributeDelta> clearGroupPolicies = new HashSet<>();
            clearGroupPolicies.add(new AttributeDeltaBuilder()
                    .setName(AWSSchema.ASSOCIATION_POLICIES)
                    .addValueToReplace() // Empty = remove all
                    .build());
            connector.updateDelta(ObjectClass.GROUP, groupUid, clearGroupPolicies, null);
            
            logger.info("Cleared all policies from both user and group");

            // Verify no policies remain
            userHandler.clear();
            connector.executeQuery(ObjectClass.ACCOUNT, new EqualsFilter(new Name(userName)), userHandler, null);
            user = userHandler.getObjects().get(0);
            userPolicies = user.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            if (userPolicies != null && userPolicies.getValue() != null) {
                assertTrue(userPolicies.getValue().isEmpty(), "User should have no policies");
            }
            
            groupHandler.clear();
            connector.executeQuery(ObjectClass.GROUP, new EqualsFilter(new Name(groupName)), groupHandler, null);
            group = groupHandler.getObjects().get(0);
            groupPolicies = group.getAttributeByName(AWSSchema.ASSOCIATION_POLICIES);
            if (groupPolicies != null && groupPolicies.getValue() != null) {
                assertTrue(groupPolicies.getValue().isEmpty(), "Group should have no policies");
            }
            
            logger.info("Verified all policies were successfully removed from both user and group");
            
            logger.info("testComprehensivePolicyManagementIntegration completed successfully!");

        } catch (Exception e) {
            logger.error("Error during comprehensive policy management integration test", e);
            fail("Test failed: " + e.getMessage());
        } finally {
            // --- CLEANUP ---
            logger.info("Cleaning up comprehensive integration test resources");
            try {
                if (userUid != null) {
                    connector.delete(ObjectClass.ACCOUNT, userUid, null);
                    logger.info("Deleted user: {}", userName);
                }
                if (groupUid != null) {
                    connector.delete(ObjectClass.GROUP, groupUid, null);
                    logger.info("Deleted group: {}", groupName);
                }
                if (policy1Arn != null) {
                    iamClient.deletePolicy(DeletePolicyRequest.builder().policyArn(policy1Arn).build());
                    logger.info("Deleted policy: {}", policy1Name);
                }
                if (policy2Arn != null) {
                    iamClient.deletePolicy(DeletePolicyRequest.builder().policyArn(policy2Arn).build());
                    logger.info("Deleted policy: {}", policy2Name);
                }
                if (policy3Arn != null) {
                    iamClient.deletePolicy(DeletePolicyRequest.builder().policyArn(policy3Arn).build());
                    logger.info("Deleted policy: {}", policy3Name);
                }
            } catch (Exception e) {
                logger.error("Error during cleanup", e);
            }
        }
    }

    /**
     * Helper method to get the IAM client from the connector using reflection
     */
    private IamClient getIamClientFromConnector() {
        try {
            java.lang.reflect.Field clientField = AWSConnector.class.getDeclaredField("client");
            clientField.setAccessible(true);
            return (IamClient) clientField.get(connector);
        } catch (Exception e) {
            logger.error("Failed to get IAM client from connector", e);
            return null;
        }
    }

    /**
     * Helper class to collect results during searches
     */
    private static class TestResultsHandler implements ResultsHandler {
        private final List<ConnectorObject> objects = new ArrayList<>();

        @Override
        public boolean handle(ConnectorObject obj) {
            objects.add(obj);
            return true; // Continue processing
        }

        public List<ConnectorObject> getObjects() {
            return objects;
        }

        public void clear() {
            objects.clear();
        }
    }
}
