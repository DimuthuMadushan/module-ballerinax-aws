// Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import aws;

# Instructs the credential provider to resolve credentials via the AWS default
# credential provider chain: JVM system properties, environment variables, web identity token,
# IAM Identity Center (SSO), shared config/credentials files, external process,
# container credentials (ECS/EKS), and EC2 instance profile (IMDS) — in order,
# taking the first source that yields credentials.
public const DEFAULT_CREDENTIALS = "DEFAULT_CREDENTIALS";

# Represents the supported AWS credential source configurations.
public type AuthConfig StaticAuthConfig|ProfileAuthConfig|AssumeRoleConfig|WebIdentityConfig|SsoAuthConfig|ProcessAuthConfig|DEFAULT_CREDENTIALS;

# Represents static AWS credentials.
public type StaticAuthConfig record {|
    # AWS access key ID
    string accessKeyId;
    # AWS secret access key
    string secretAccessKey;
    # AWS session token, required only for temporary credentials
    string sessionToken?;
|};

# Represents AWS credentials loaded from a named profile in a local AWS
# credentials file (as created by `aws configure`).
public type ProfileAuthConfig record {|
    # The named profile to use
    string profileName = "default";
    # Path to the AWS credentials file
    string credentialsFilePath = "~/.aws/credentials";
|};

# Represents temporary credentials obtained by assuming an IAM role via AWS STS.
public type AssumeRoleConfig record {|
    # ARN of the IAM role to assume
    string roleArn;
    # Identifier for the assumed-role session; a unique `ballerina-aws-auth-<timestamp>`
    # name is generated if not provided
    string roleSessionName?;
    # External ID for third-party cross-account trust, if the role requires one
    string externalId?;
    # Validity period of each assumed-role session in seconds
    int duration = 3600;
    # Region of the STS endpoint to call
    aws:Region|string stsRegion = aws:US_EAST_1;
    # Optional STS endpoint options: FIPS/dualstack variants, or a custom endpoint override
    aws:EndpointConfig stsEndpoint?;
    # Credential source used to authenticate the AssumeRole call
    AuthConfig sourceCredentials = DEFAULT_CREDENTIALS;
|};

# Represents temporary credentials obtained by exchanging a web identity (OIDC)
# token for an IAM role via AWS STS
public type WebIdentityConfig record {|
    # ARN of the IAM role to assume
    string roleArn;
    # Path to the file containing the OIDC token (JWT)
    string webIdentityTokenFile;
    # Identifier for the assumed-role session; a unique `ballerina-aws-auth-<timestamp>`
    # name is generated if not provided
    string roleSessionName?;
    # Region of the STS endpoint to call
    aws:Region|string stsRegion = aws:US_EAST_1;
    # Optional STS endpoint options: FIPS/dualstack variants, or a custom endpoint override
    aws:EndpointConfig stsEndpoint?;
|};

# Represents credentials obtained from an AWS IAM Identity Center (SSO) session.
# Requires an active session created out-of-band with `aws sso login`; the cached
# session token in `~/.aws/sso/cache` is exchanged for role credentials.
public type SsoAuthConfig record {|
    # The Identity Center start URL (e.g. `https://myorg.awsapps.com/start`)
    string ssoStartUrl;
    # Region in which IAM Identity Center is configured
    aws:Region|string ssoRegion;
    # AWS account ID to get credentials for
    string accountId;
    # Permission-set role name to get credentials for
    string roleName;
    # Name of the `sso-session` in `~/.aws/config`
    # When set, used token cached under the session name, enables automatic token refresh.
    # When absent, the legacy token cached under the start URL is used as is
    string ssoSessionName?;
|};

# Represents credentials supplied by an external process (the AWS
# `credential_process` contract). The command is executed and must print a JSON
# credential document to stdout.
#
# Security note: the configured command is executed with the privileges of the
# running program. Prefer declaring it in `~/.aws/config` (`credential_process`)
# and using `ProfileAuthConfig`/`DEFAULT_CREDENTIALS` where possible.
public type ProcessAuthConfig record {|
    # The command to execute, as separate arguments with the executable first
    # (e.g. `["/usr/local/bin/aws_signing_helper", "credential-process", "--certificate", ...]`).
    # Executed directly, without a shell
    string[] command;
|};

# Represents resolved AWS credentials, as returned by the `CredentialProvider`.
public type Credentials record {
    # AWS access key ID
    string accessKeyId;
    # AWS secret access key
    string secretAccessKey;
    # Session token, present only for temporary credentials
    string sessionToken?;
};

# An HTTP request to be signed with AWS Signature Version 4.
public type SignatureRequest record {|
    # HTTP method in upper case (`GET`, `POST`, ...)
    string method;
    # Target host (e.g. `sns.us-east-1.amazonaws.com`)
    string host;
    # Request path, unencoded
    string path = "/";
    # Query parameters, unencoded
    map<string> queryParams = {};
    # Additional headers to sign (e.g. `content-type`); `host` and `x-amz-date` are always added
    map<string> headers = {};
    # Request body
    byte[] payload = [];
    # Sign the payload as `UNSIGNED-PAYLOAD` (S3 streaming)
    boolean unsignedPayload = false;
    # Use S3 path semantics: segments encoded once and not normalized
    boolean s3PathMode = false;
|};
