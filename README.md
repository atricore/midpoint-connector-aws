# MidPoint AWS IAM Connector

A connector for integrating [Evolveum midPoint](https://evolveum.com/midpoint/) with Amazon Web Services (AWS) Identity and Access Management (IAM). Manage AWS IAM users, groups, and policies directly from midPoint.

## Prerequisites

- MidPoint 4.x or later
- AWS account with appropriate IAM permissions
- AWS access credentials (Access Key ID and Secret Access Key)

## Installation

1. Build the connector:
   ```bash
   mvn clean package
   ```

2. Copy the connector JAR to your midPoint installation:
   ```bash
   cp target/connector-aws-*.jar /opt/midpoint/var/icf-connectors/
   ```

3. Restart midPoint or reload connectors from the GUI

4. Verify the connector appears in: **Configuration → Repository Objects → Connectors**

## Configuration

### Required AWS Permissions

Create an IAM user or role with the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetUser",
        "iam:CreateUser",
        "iam:UpdateUser",
        "iam:DeleteUser",
        "iam:ListGroups",
        "iam:GetGroup",
        "iam:CreateGroup",
        "iam:UpdateGroup",
        "iam:DeleteGroup",
        "iam:AddUserToGroup",
        "iam:RemoveUserFromGroup",
        "iam:ListGroupsForUser",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:ListPolicyTags",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:DetachGroupPolicy",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:DeleteLoginProfile",
        "iam:GetLoginProfile"
      ],
      "Resource": "*"
    }
  ]
}
```

### Connector Properties

| Property | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `awsAccessKeyId` | String | Yes | - | AWS access key ID |
| `awsSecretAccessKey` | GuardedString | Yes | - | AWS secret access key (encrypted) |
| `awsRegion` | String | No | `us-east-1` | AWS region |
| `allowCache` | Boolean | No | `false` | Enable caching for performance |
| `maxCacheTTL` | Long | No | `300000` | Cache TTL in milliseconds (5 min) |
| `endpointOverride` | String | No | - | Custom endpoint (for testing) |

### Basic Configuration Example

```xml
<connectorConfiguration>
    <icfc:configurationProperties
        xmlns:icfcga="http://midpoint.evolveum.com/xml/ns/public/connector/icf-1/bundle/com.atricore.iam.evolveum.connector.connector-aws/com.atricore.iam.midpoint.connector.aws.AWSConnector">
        <icfcga:awsAccessKeyId>AKIAIOSFODNN7EXAMPLE</icfcga:awsAccessKeyId>
        <icfcga:awsSecretAccessKey>
            <t:clearValue>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</t:clearValue>
        </icfcga:awsSecretAccessKey>
        <icfcga:awsRegion>us-east-1</icfcga:awsRegion>
        <icfcga:allowCache>false</icfcga:allowCache>
    </icfc:configurationProperties>
</connectorConfiguration>
```

See `examples/aws-inbound.xml` for a complete resource configuration.

## Supported Entities

### Users (IAM Users)

**Object Class:** `AccountObjectClass`

**Supported Operations:** Create, Read, Update, Delete, Search

**Key Attributes:**
- `__UID__` - Username (used as unique identifier)
- `__NAME__` - Username
- `awsId` - AWS User ID (read-only)
- `arn` - Amazon Resource Name (read-only)
- `path` - User path (e.g., `/`, `/division/`)
- `__PASSWORD__` - Login password (write-only)
- `createDate` - User creation timestamp (read-only)
- `passwordLastUsed` - Last password use timestamp (read-only)
- `attachedPolicies` - List of attached policy ARNs
- `groups` - List of group memberships (group names)

### Groups (IAM Groups)

**Object Class:** `GroupObjectClass`

**Supported Operations:** Create, Read, Update, Delete, Search

**Key Attributes:**
- `__UID__` - Group name (used as unique identifier)
- `__NAME__` - Group name
- `awsId` - AWS Group ID (read-only)
- `arn` - Amazon Resource Name (read-only)
- `path` - Group path (e.g., `/`, `/department/`)
- `createDate` - Group creation timestamp (read-only)
- `attachedPolicies` - List of attached policy ARNs

### Policies (IAM Policies)

**Object Class:** `CustomAWSPolicyObjectClass`

**Supported Operations:** Read, Search (read-only)

**Key Attributes:**
- `__UID__` - Policy ARN (used as unique identifier)
- `__NAME__` - Policy name
- `policyId` - AWS Policy ID (read-only)
- `arn` - Amazon Resource Name (read-only)
- `policyType` - `AWS` or `CUSTOMER` (read-only)
- `path` - Policy path (read-only)
- `description` - Policy description (read-only)
- `isAttachable` - Whether policy can be attached (read-only)
- `attachmentCount` - Number of entities using this policy (read-only)
- `tags` - Policy tags as key=value pairs (read-only)

### Roles (IAM Roles)

**Object Class:** `CustomAWSRoleObjectClass`

**Status:** In development

## Capabilities

### Supported Operations

| Entity | Create | Read | Update | Delete | Search | Associations |
|--------|--------|------|--------|--------|--------|--------------|
| **Users** | ✓ | ✓ | ✓ | ✓ | ✓ | Policies, Groups |
| **Groups** | ✓ | ✓ | ✓ | ✓ | ✓ | Policies |
| **Policies** | ✗ | ✓ | ✗ | ✗ | ✓ | - |
| **Roles** | ✗ | ✓ | ✗ | ✗ | ✓ | In development |

### Additional Capabilities

- **Password Management:** Create and update IAM user passwords
- **Group Membership:** Add/remove users from groups
- **Policy Attachment:** Attach/detach policies to users and groups
- **Schema Discovery:** Automatic detection of supported attributes
- **Paging Support:** Efficient handling of large result sets
- **Delta Updates:** Update only changed attributes
- **Caching:** Optional caching for improved performance

### Search and Filtering

The connector supports searching by:
- **Users:** Username, User ID, AWS ID, or list all
- **Groups:** Group name, Group ID, AWS ID, or list all
- **Policies:** Policy name, Policy ARN, Policy ID, Policy type, or list all

## Usage Notes

### Important Behaviors

1. **Unique Identifiers:**
   - Users: `__UID__` is the **username** (not the AWS User ID)
   - Groups: `__UID__` is the **group name** (not the AWS Group ID)
   - Policies: `__UID__` is the **policy ARN**

2. **Group Membership:**
   - When creating a user with group membership, provide **group IDs** or **group names**
   - The `groups` attribute returns **group names** (not IDs)

3. **Policy Management:**
   - Policies are **read-only** - they cannot be created or modified through the connector
   - Policies can be **attached/detached** from users and groups
   - Use policy ARNs for attachments

4. **User Deletion:**
   - Users with attached policies or group memberships must have those removed before deletion
   - The connector does not automatically clean up associations

### Security Best Practices

- **Use IAM Roles:** Prefer IAM roles over access keys when possible
- **Rotate Credentials:** Regularly rotate access keys
- **Least Privilege:** Grant only necessary permissions
- **Enable CloudTrail:** Log all IAM API calls for auditing
- **Use GuardedString:** Always encrypt the secret access key in midPoint

## Complete Example

See `examples/aws-inbound.xml` for a full resource configuration including:
- Connector configuration
- Schema handling
- User synchronization
- Group management
- Policy associations
- Attribute mappings
- Correlation rules

## Troubleshooting

### Connection Test Fails

**Issue:** Unable to authenticate to AWS

**Solutions:**
- Verify access key ID and secret access key are correct
- Check IAM permissions match the required list above
- Ensure AWS region is valid
- Test network connectivity to AWS endpoints

### Permission Denied Errors

**Issue:** 403 Access Denied during operations

**Solutions:**
- Review IAM user permissions
- Check for AWS Organizations Service Control Policies (SCPs)
- Verify resource-based policies don't restrict access

### Changes Not Appearing

**Issue:** Updates in AWS not reflected in midPoint

**Solutions:**
- Disable caching (`allowCache=false`)
- Run manual reconciliation
- Check synchronization tasks are running
- Review midPoint logs for errors

## Resources

- [Example Configuration](examples/aws-inbound.xml)
- [MidPoint Documentation](https://docs.evolveum.com/midpoint/)
- [AWS IAM Documentation](https://docs.aws.amazon.com/iam/)

## License

Apache License 2.0

## Support

For issues or questions, please contact Atricore or visit the project repository.
