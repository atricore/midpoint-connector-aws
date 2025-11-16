package com.atricore.iam.midpoint.connector.aws;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.*;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class AWSSchema {

    private static final Log LOG = Log.getLog(AWSSchema.class);

    private static Set<String> accountAttributeNames;
    private static Set<String> groupAttributeNames;
    private static Set<String> policyAttributeNames;
    private static Set<String> roleAttributeNames;

    // Connector schema instance, built on-demand.
    private static Schema schema;

    //--- Schema Object Classes ----------------------------------------------------------------------------------------

    public static final ObjectClass ROLE_OBJECT_CLASS = new ObjectClass("AWSRole");

    public static final String ATTRIBUTE_AWS_ID = "awsId";

    // Define a custom ObjectClass for policies
    public static final ObjectClass POLICY_OBJECT_CLASS = new ObjectClass("AWSPolicy");

    // Define policy-specific attributes
    public static final String ATTRIBUTE_POLICY_ID = "policyId";
    public static final String ATTRIBUTE_POLICY_TYPE = "policyType";
    public static final String ATTRIBUTE_DESCRIPTION = "description";
    public static final String ATTRIBUTE_DEFAULT_VERSION_ID = "defaultVersionId";
    public static final String ATTRIBUTE_ATTACHMENT_COUNT = "attachmentCount";
    public static final String ATTRIBUTE_PERMISSIONS_BOUNDARY_USAGE_COUNT = "permissionsBoundaryUsageCount";
    public static final String ATTRIBUTE_IS_ATTACHABLE = "isAttachable";

    public static final String ATTRIBUTE_ARN = "arn";
    public static final String ATTRIBUTE_PATH = "path";
    public static final String ATTRIBUTE_TAGS = "tags";
    public static final String ATTRIBUTE_CREATE_DATE = "createDate";
    public static final String ATTRIBUTE_PASSWORD_LAST_USED = "passwordLastUsed";

    // Association between User/Group and Policies
    public static final String ASSOCIATION_POLICIES = "attachedPolicies";

    public static final String ASSOCIATION_GROUPS = "awsGroups";

    public static Schema getSchema(AWSConfiguration configuration) {
        createSchema(configuration);
        return schema;
    }

    public static Set<String> getAccountAttributeNames(AWSConfiguration configuration) {
        createSchema(configuration);
        return accountAttributeNames;
    }

    public static Set<String> getGroupAttributeNames(AWSConfiguration configuration) {
        createSchema(configuration);
        return groupAttributeNames;
    }

    public static Set<String> getPolicyAttributeNames(AWSConfiguration configuration) {
        createSchema(configuration);
        return policyAttributeNames;
    }

    public static Set<String> getRoleAttributeNames(AWSConfiguration configuration) {
        createSchema(configuration);
        return roleAttributeNames;
    }

    private static void createSchema(AWSConfiguration configuration) {

        if (schema != null) {
            return;
        }

        LOG.info("Creating AWS connector schema ... ");

        // Build schema
        SchemaBuilder schemaBuilder = new SchemaBuilder(AWSConnector.class);

        // -----------------------------------------------
        // Build Account schema
        // -----------------------------------------------
        ObjectClassInfo account = buildAccountClassInfo();
        schemaBuilder.defineObjectClass(ObjectClass.ACCOUNT_NAME, account.getAttributeInfo());
        accountAttributeNames = createAttributeNames(account);

        // -----------------------------------------------
        // Build GROUP schema
        // -----------------------------------------------
        ObjectClassInfo group = buildGroupClassInfo();
        schemaBuilder.defineObjectClass(ObjectClass.GROUP_NAME, group.getAttributeInfo());
        groupAttributeNames = createAttributeNames(group);

        // -----------------------------------------------
        // Build POLICY schema
        // -----------------------------------------------
        ObjectClassInfo policy = buildPolicyClassInfo();
        schemaBuilder.defineObjectClass(POLICY_OBJECT_CLASS.getObjectClassValue(), policy.getAttributeInfo());
        policyAttributeNames = createAttributeNames(policy);

        // -----------------------------------------------
        // Build Role schema
        // -----------------------------------------------
        ObjectClassInfo role = buildRoleClassInfo();
        schemaBuilder.defineObjectClass(ROLE_OBJECT_CLASS.getObjectClassValue(), role.getAttributeInfo());
        roleAttributeNames = createAttributeNames(role);

        // BUILD SCHEMA
        schema = schemaBuilder.build();
        LOG.info("Created AWS connector schema ... " + schema);
    }

    protected static ObjectClassInfo buildAccountClassInfo() {
        // -----------------------------------------------
        // Build Account schema
        // -----------------------------------------------
        ObjectClassInfoBuilder accountClassBuilder = new ObjectClassInfoBuilder();
        accountClassBuilder.setType(ObjectClass.ACCOUNT_NAME);

        accountClassBuilder.addAttributeInfo(Name.INFO);
        accountClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_ARN).build());
        accountClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_AWS_ID).build());
        accountClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_PATH).setUpdateable(true).setCreateable(true).build());
        accountClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_CREATE_DATE).build());
        accountClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_PASSWORD_LAST_USED).build());

        // Define group membership association - user to group relationship
        AttributeInfo GROUPS = AttributeInfoBuilder.build(ASSOCIATION_GROUPS, String.class, EnumSet.of(AttributeInfo.Flags.MULTIVALUED));
        accountClassBuilder.addAttributeInfo(GROUPS);

        // Define policy association - user to policy relationship
        AttributeInfo userPolicies = AttributeInfoBuilder.build(AWSSchema.ASSOCIATION_POLICIES, String.class, EnumSet.of(AttributeInfo.Flags.MULTIVALUED));
        accountClassBuilder.addAttributeInfo(userPolicies);

        return accountClassBuilder.build();

    }

    protected static ObjectClassInfo buildGroupClassInfo() {
        ObjectClassInfoBuilder groupClassBuilder = new ObjectClassInfoBuilder();
        groupClassBuilder.setType(ObjectClass.GROUP_NAME);

        groupClassBuilder.addAttributeInfo(Name.INFO);
        groupClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_ARN).build());
        groupClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_AWS_ID).build());
        groupClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_PATH).setUpdateable(true).setCreateable(true).build());
        groupClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_CREATE_DATE).build());

        // Define policy association - group to policy relationship
        AttributeInfo groupPolicies = AttributeInfoBuilder.build(ASSOCIATION_POLICIES, String.class, EnumSet.of(AttributeInfo.Flags.MULTIVALUED));
        groupClassBuilder.addAttributeInfo(groupPolicies);

        return groupClassBuilder.build();
    }

    protected static ObjectClassInfo buildRoleClassInfo() {
        ObjectClassInfoBuilder roleClassBuilder = new ObjectClassInfoBuilder();
        roleClassBuilder.setType(ROLE_OBJECT_CLASS.getObjectClassValue());

        roleClassBuilder.addAttributeInfo(Name.INFO);
        roleClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_AWS_ID).build());
        roleClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_ARN).build());
        roleClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_PATH).setUpdateable(true).setCreateable(true).build());
        roleClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_CREATE_DATE).build());
        roleClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_DESCRIPTION).build());

        // Define policy association - group to policy relationship
        AttributeInfo rolePolicies = AttributeInfoBuilder.build(ASSOCIATION_POLICIES, String.class, EnumSet.of(AttributeInfo.Flags.MULTIVALUED));
        roleClassBuilder.addAttributeInfo(rolePolicies);

        return roleClassBuilder.build();
    }

    protected static ObjectClassInfo buildPolicyClassInfo() {
        ObjectClassInfoBuilder policyClassBuilder = new ObjectClassInfoBuilder();
        policyClassBuilder.setType(POLICY_OBJECT_CLASS.getObjectClassValue());

        policyClassBuilder.addAttributeInfo(Name.INFO);
        // ARN is used as NAME
        policyClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_ARN).setRequired(true).build());
        policyClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_PATH).build());
        policyClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_CREATE_DATE).build());

        // Add policy-specific attributes
        policyClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_POLICY_ID).build());
        policyClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_POLICY_TYPE).build());
        policyClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_DESCRIPTION).build());
        policyClassBuilder.addAttributeInfo(createSimpleAttribute(ATTRIBUTE_DEFAULT_VERSION_ID).build());

        // Add multi-valued tag attribute
        AttributeInfoBuilder tagsAttrBuilder = new AttributeInfoBuilder(ATTRIBUTE_TAGS);
        tagsAttrBuilder.setType(String.class);
        tagsAttrBuilder.setMultiValued(true);
        tagsAttrBuilder.setCreateable(false);
        tagsAttrBuilder.setUpdateable(false);
        policyClassBuilder.addAttributeInfo(tagsAttrBuilder.build());

        // Add numeric attributes
        AttributeInfoBuilder attachmentCountAttr = new AttributeInfoBuilder(ATTRIBUTE_ATTACHMENT_COUNT);
        attachmentCountAttr.setType(Integer.class);
        attachmentCountAttr.setCreateable(false);
        attachmentCountAttr.setUpdateable(false);
        policyClassBuilder.addAttributeInfo(attachmentCountAttr.build());

        AttributeInfoBuilder permBoundaryUsageCountAttr = new AttributeInfoBuilder(ATTRIBUTE_PERMISSIONS_BOUNDARY_USAGE_COUNT);
        permBoundaryUsageCountAttr.setType(Integer.class);
        permBoundaryUsageCountAttr.setCreateable(false);
        permBoundaryUsageCountAttr.setUpdateable(false);
        policyClassBuilder.addAttributeInfo(permBoundaryUsageCountAttr.build());

        // Add boolean attributes
        AttributeInfoBuilder isAttachableAttr = new AttributeInfoBuilder(ATTRIBUTE_IS_ATTACHABLE);
        isAttachableAttr.setType(Boolean.class);
        isAttachableAttr.setCreateable(false);
        isAttachableAttr.setUpdateable(false);
        policyClassBuilder.addAttributeInfo(isAttachableAttr.build());

        return policyClassBuilder.build();
    }

    private static Set<String> createAttributeNames(ObjectClassInfo oci) {
        Set<String> result = new HashSet<String>();
        Iterator<AttributeInfo> iterator = oci.getAttributeInfo().iterator();

        while (iterator.hasNext()) {
            AttributeInfo a = iterator.next();
            result.add(a.getName());
        }
        return result;
    }


    private static AttributeInfoBuilder createSimpleAttribute(String name) {
        AttributeInfoBuilder aib = new AttributeInfoBuilder();
        aib.setName(name);
        aib.setType(String.class);
        aib.setUpdateable(false);
        aib.setCreateable(false);

        return aib;
    }

    private static AttributeInfoBuilder createDateAttribute(String name) {
        AttributeInfoBuilder aib = new AttributeInfoBuilder();
        aib.setName(name);
        aib.setType(java.util.Date.class);
        aib.setUpdateable(false);
        aib.setCreateable(false);

        return aib;
    }
}
