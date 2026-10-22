# Specification: Ballerina AWS Library

_Authors_: [@DimuthuMadushan](https://github.com/DimuthuMadushan) \
_Reviewers_: [@daneshk](https://github.com/daneshk) \
_Created_: 2026/07/23 \
_Updated_: 2026/07/23 \
_Edition_: Swan Lake

## Introduction

This is the specification for the `ballerinax/aws` package of the [Ballerina language](https://ballerina.io), which provides the shared AWS authentication, request-signing, and region/endpoint utilities used by the `ballerinax/aws.*` connector family, and directly by user code that needs to call an AWS service with no dedicated connector yet.

The `ballerinax/aws` package follows the general format proposed by Ballerina, which specifies the syntax and semantics of a Ballerina library.

The conforming implementation of the specification is released. Any deviation from the specification is considered a bug.

## Table of Contents

1. [Overview](#1-overview)
2. [Components](#2-components)
    * 2.1 [Root Module](#21-root-module)
        * 2.1.1 [`Region` Type](#211-region-type)
        * 2.1.2 [Endpoint Resolution](#212-endpoint-resolution)
    * 2.2 [Auth Submodule](#22-auth-submodule)
        * 2.2.1 [`CredentialProvider`](#221-credentialprovider)
        * 2.2.2 [Signer](#222-signer)
3. [Credential Configuration](#3-credential-configuration)
    * 3.1 [`StaticAuthConfig`](#31-staticauthconfig)
    * 3.2 [`ProfileAuthConfig`](#32-profileauthconfig)
    * 3.3 [`AssumeRoleConfig`](#33-assumeroleconfig)
    * 3.4 [`WebIdentityConfig`](#34-webidentityconfig)
    * 3.5 [`SsoAuthConfig`](#35-ssoauthconfig)
    * 3.6 [`ProcessAuthConfig`](#36-processauthconfig)
    * 3.7 [`DEFAULT_CREDENTIALS`](#37-default_credentials)
4. [Types](#4-types)
    * 4.1 [`Credentials`](#41-credentials)
    * 4.2 [`SignatureRequest`](#42-signaturerequest)
    * 4.3 [`EndpointConfig`](#43-endpointconfig)
    * 4.4 [`ErrorDetails`](#44-errordetails)
5. [Errors](#5-errors)
    * 5.1 [`Error`](#51-error)
    * 5.2 [`CredentialResolutionError`](#52-credentialresolutionerror)
    * 5.3 [`SigningError`](#53-signingerror)
6. [Functions](#6-functions)
    * 6.1 [`resolveEndpoint`](#61-resolveendpoint)
    * 6.2 [`resolveEndpointHost`](#62-resolveendpointhost)
    * 6.3 [`getSignedHeaders`](#63-getsignedheaders)
7. [Security](#7-security)
    * 7.1 [Credential Handling](#71-credential-handling)
    * 7.2 [External Credential Processes](#72-external-credential-processes)
    * 7.3 [Resource Cleanup](#73-resource-cleanup)
    * 7.4 [STS Role-Chaining Cycles](#74-sts-role-chaining-cycles)
8. [Usage Patterns](#8-usage-patterns)
    * 8.1 [As a Connector Dependency](#81-as-a-connector-dependency)
    * 8.2 [Calling a Service With No Dedicated Connector](#82-calling-a-service-with-no-dedicated-connector)
9. [Advanced Features](#9-advanced-features)
    * 9.1 [Automatic Credential Refresh](#91-automatic-credential-refresh)
    * 9.2 [Endpoint Metadata and Fallback](#92-endpoint-metadata-and-fallback)
    * 9.3 [GraalVM Compatibility](#93-graalvm-compatibility)

## 1. Overview

[AWS](https://aws.amazon.com/) is a comprehensive cloud computing platform offering over 200 services, all authenticated through a common scheme: IAM credentials and [AWS Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html) (SigV4) request signing. Every `ballerinax/aws.*` connector needs the same three things to talk to its service: a way to resolve credentials from whichever source the caller is running on, a way to sign requests with those credentials, and a way to resolve the target service's regional endpoint.

The `ballerinax/aws` package factors these three concerns out into a single shared library with two modules:

- The **root module** (`ballerinax/aws`) provides the `Region` type and region-based endpoint resolution.
- The **`auth` submodule** (`ballerinax/aws.auth`) provides credential resolution across all AWS-standardized credential sources — with automatic refresh of expiring temporary credentials — and AWS Signature Version 4 request signing.

Each credential source follows AWS's own published format and protocol for that source (STS `AssumeRole`/`AssumeRoleWithWebIdentity`, SSO `GetRoleCredentials`, the `credential_process` contract, SigV4 signing). The exact resolution order for `DEFAULT_CREDENTIALS` is documented in [section 3.7](#37-default_credentials).

Beyond functional requirements, the library addresses non-functional concerns including the security of credential handling described in the [Security](#7-security) section.

## 2. Components

### 2.1 Root Module

The root module (`ballerinax/aws`) provides two things: the `Region` enum and endpoint resolution.

#### 2.1.1 `Region` Type

`Region` is an enum covering every region known at build time across the commercial, China, GovCloud, and ISO (government/defense-only) partitions, plus the partition-wide pseudo-regions used by global services (e.g. IAM, CloudFront):

```ballerina
public enum Region {
    AF_SOUTH_1 = "af-south-1",
    AP_EAST_1 = "ap-east-1",
    ...
    US_WEST_2 = "us-west-2"
}
```

Every API in this package that takes a region accepts `Region|string` rather than `Region` alone, so a region added by AWS after this package's release can still be passed as a plain string without a new package version.

#### 2.1.2 Endpoint Resolution

Endpoint resolution is covered by the [`resolveEndpoint`](#61-resolveendpoint) and [`resolveEndpointHost`](#62-resolveendpointhost) functions (see [Functions](#6-functions)) and the [`EndpointConfig`](#43-endpointconfig) type (see [Types](#4-types)).

### 2.2 Auth Submodule

The `auth` submodule (`ballerinax/aws.auth`) provides credential resolution and request signing.

#### 2.2.1 `CredentialProvider`

The `auth:CredentialProvider` is the central abstraction for credential resolution.

```ballerina
public isolated class CredentialProvider {
    public isolated function init(AuthConfig config) returns CredentialResolutionError?;
    public isolated function getCredentials() returns Credentials|CredentialResolutionError;
    public isolated function close() returns Error?;
}
```

A `CredentialProvider` is long-lived — constructed once (typically alongside a connector client) and reused for the lifetime of the program. Each call to `getCredentials()` returns credentials that are valid at the time of the call: if the underlying source produces temporary credentials (STS assume-role, SSO, EC2/ECS instance profile), the provider refreshes them transparently before they expire, and cached, still-valid credentials are served without a new network call.

`close()` releases resources held by the underlying provider (background refresh threads, HTTP connections opened for STS/SSO calls). See [Resource Cleanup](#73-resource-cleanup).

#### 2.2.2 Signer

Request signing is a plain function, [`getSignedHeaders`](#63-getsignedheaders) (see [Functions](#6-functions)), rather than a class — signing is stateless given a request, credentials, region, and service name, so no signer instance needs to be constructed or held alongside the `CredentialProvider`.

## 3. Credential Configuration

The `AuthConfig` is a closed union of the seven credential source configurations AWS standardizes across its own SDKs and CLI. Passing a value of this union to `CredentialProvider.init` selects, at compile time, which credential source is used:

```ballerina
public type AuthConfig StaticAuthConfig|ProfileAuthConfig|AssumeRoleConfig|WebIdentityConfig|SsoAuthConfig|ProcessAuthConfig|DEFAULT_CREDENTIALS;
```

### 3.1 `StaticAuthConfig`

Long-lived (or already-issued temporary) credentials supplied directly by the caller.

| Field | Type | Description |
|---|---|---|
| `accessKeyId` | `string` | AWS access key ID |
| `secretAccessKey` | `string` | AWS secret access key |
| `sessionToken` | `string?` | Session token; required only when the pair is a temporary credential |

>**Note:** Static credentials never expire on their own from the provider's point of view (there is nothing to refresh), so this is the one `AuthConfig` variant whose `getCredentials()` call never triggers a network call after `init`.

*AWS documentation:* [Managing access keys for IAM users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)

### 3.2 `ProfileAuthConfig`

Credentials loaded from a named profile in a local AWS credentials file, as created by `aws configure`.

| Field | Type | Default | Description |
|---|---|---|---|
| `profileName` | `string` | `"default"` | The named profile to use |
| `credentialsFilePath` | `string` | `"~/.aws/credentials"` | Path to the credentials file; `~` is expanded against the resolved home directory |

*AWS documentation:* [Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

### 3.3 `AssumeRoleConfig`

Temporary credentials obtained by assuming an IAM role via AWS STS (`AssumeRole`).

| Field | Type | Default | Description |
|---|---|---|---|
| `roleArn` | `string` | — | ARN of the IAM role to assume |
| `roleSessionName` | `string?` | a generated `ballerina-aws-auth-<timestamp>` | Identifier for the assumed-role session |
| `externalId` | `string?` | — | External ID for third-party cross-account trust, if the role's trust policy requires one |
| `duration` | `int` | `3600` | Validity period of each assumed-role session, in seconds |
| `stsRegion` | `Region\|string` | `US_EAST_1` | Region of the STS endpoint to call |
| `stsEndpoint` | `EndpointConfig?` | — | STS endpoint options: FIPS/dualstack variants, or a custom endpoint override. See [Custom STS Endpoints](#custom-sts-endpoints) |
| `sourceCredentials` | `AuthConfig` | `DEFAULT_CREDENTIALS` | Credential source used to authenticate the `AssumeRole` call itself |

The `sourceCredentials` being an `AuthConfig` means an `AssumeRoleConfig` can nest another `AssumeRoleConfig`, chaining role assumption. See [STS Role-Chaining Cycles](#74-sts-role-chaining-cycles) for the cycle protection this requires.

*AWS documentation:* [AssumeRole - AWS STS API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html), [Temporary security credentials in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)

#### Custom STS Endpoints

By default, the STS call goes to the regional endpoint for `stsRegion` (`sts.<stsRegion>.amazonaws.com`). `stsEndpoint` (on both `AssumeRoleConfig` and `WebIdentityConfig`) takes the same [`EndpointConfig`](#43-endpointconfig) used for service endpoints:

* `fips` / `dualstack` select the FIPS (`sts-fips.<region>...`) or dualstack variant of the STS endpoint.
* `customEndpoint` sends the STS call to the given URL as-is (e.g. a VPC interface endpoint without private DNS, or LocalStack). `stsRegion` is still used as the signing region.

`customEndpoint` must be an absolute `http` or `https` URL with a host; any other value (for example `localhost:4566`) makes the provider initialization fail. With `http`, the request and the temporary credentials returned by STS are sent unencrypted, so use it only for local testing such as LocalStack.

```ballerina
auth:CredentialProvider credProvider = check new ({
    roleArn: "arn:aws:iam::123456789012:role/reporting-read-only",
    stsRegion: aws:EU_WEST_1,
    stsEndpoint: {customEndpoint: "https://vpce-0abc123-xyz.sts.eu-west-1.vpce.amazonaws.com"}
});
```

`stsEndpoint` is independent of a connector's own service endpoint: setting `customEndpoint` on a connector does not redirect STS, and vice versa. In a chained assume-role configuration, each hop uses its own `stsEndpoint`.

When `stsEndpoint` is not set, the AWS SDK's environment- and profile-based endpoint settings still apply (`AWS_ENDPOINT_URL_STS`, `AWS_ENDPOINT_URL`, `AWS_USE_FIPS_ENDPOINT`). These also cover the STS calls made internally by `ProfileAuthConfig` profiles with `role_arn` and by the web identity source of `DEFAULT_CREDENTIALS`, which `stsEndpoint` does not reach.

> **Note:** A path in an STS endpoint set through these environment or profile settings (e.g. `AWS_ENDPOINT_URL_STS=http://gateway:9090/sts/v1`) is dropped, and the call is sent to the root of the host. This is a bug in the AWS SDK for Java ([aws/aws-sdk-java-v2#3387](https://github.com/aws/aws-sdk-java-v2/issues/3387)) that this package works around only for `stsEndpoint.customEndpoint`. Until it is fixed, set a path-prefixed STS endpoint through `stsEndpoint.customEndpoint`.

### 3.4 `WebIdentityConfig`

Temporary credentials obtained by exchanging a web identity (OIDC) token for an IAM role via AWS STS (`AssumeRoleWithWebIdentity`) — the mechanism behind EKS IAM Roles for Service Accounts (IRSA) and OIDC-federated CI/CD systems.

| Field | Type | Default | Description |
|---|---|---|---|
| `roleArn` | `string` | — | ARN of the IAM role to assume |
| `webIdentityTokenFile` | `string` | — | Path to the file containing the OIDC token (JWT); `~` is expanded |
| `roleSessionName` | `string?` | a generated `ballerina-aws-auth-<timestamp>` | Identifier for the assumed-role session |
| `stsRegion` | `Region\|string` | `US_EAST_1` | Region of the STS endpoint to call |
| `stsEndpoint` | `EndpointConfig?` | — | STS endpoint options: FIPS/dualstack variants, or a custom endpoint override. See [Custom STS Endpoints](#custom-sts-endpoints) |

>**Note:** `AssumeRoleWithWebIdentity` is called unsigned — a web identity token is itself the proof of identity, so no SigV4 credentials are needed to make the call.

*AWS documentation:* [AssumeRoleWithWebIdentity - AWS STS API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html), [IAM roles for service accounts (EKS IRSA)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)

### 3.5 `SsoAuthConfig`

Credentials obtained from an AWS IAM Identity Center (SSO) session, exchanging a cached session token for role credentials (`GetRoleCredentials`).

| Field | Type | Description |
|---|---|---|
| `ssoStartUrl` | `string` | The Identity Center start URL (e.g. `https://myorg.awsapps.com/start`) |
| `ssoRegion` | `Region\|string` | Region in which IAM Identity Center is configured |
| `accountId` | `string` | AWS account ID to get credentials for |
| `roleName` | `string` | Permission-set role name to get credentials for |
| `ssoSessionName` | `string?` | Name of the `sso-session` block in `~/.aws/config` |
| `ssoEndpoint` | `EndpointConfig?` | SSO portal endpoint options (`GetRoleCredentials`): FIPS/dualstack variants, or a custom endpoint override |
| `ssoOidcEndpoint` | `EndpointConfig?` | SSO-OIDC endpoint options (token refresh): FIPS/dualstack variants, or a custom endpoint override. Used only when `ssoSessionName` is set |

This requires an active session created out-of-band with `aws sso login`. There are two supported cache-lookup modes, selected by whether `ssoSessionName` is set:

- **Set** (modern `sso-session` flow): the token cached under the session name is used, and — via SSO-OIDC — refreshed automatically as it nears expiry.
- **Absent** (legacy flow): the token cached under the SHA-1 hash of `ssoStartUrl` is used as-is, with no automatic refresh; re-running `aws sso login` is required once it expires.

If no cached session is found (or, for the legacy flow, the cached token is invalid), `getCredentials()` returns a `CredentialResolutionError` with a message instructing the caller to run `aws sso login`.

The SSO flow talks to two services with separate endpoints, the SSO portal (`portal.sso.<ssoRegion>.amazonaws.com`) and SSO-OIDC (`oidc.<ssoRegion>.amazonaws.com`) — so each has its own [`EndpointConfig`](#43-endpointconfig) field. A single URL that serves both (e.g. LocalStack) is set on both fields. A `customEndpoint` follows the same rules as for [`stsEndpoint`](#custom-sts-endpoints): it must be an absolute `http` or `https` URL, and `http` is only suitable for local testing. When a field is not set, the AWS SDK's environment- and profile-based endpoint settings still apply (`AWS_ENDPOINT_URL_SSO`, `AWS_ENDPOINT_URL_SSO_OIDC`, `AWS_ENDPOINT_URL`).

*AWS documentation:* [GetRoleCredentials - IAM Identity Center Portal API Reference](https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/API_GetRoleCredentials.html), [Configure the AWS CLI to use IAM Identity Center](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)

### 3.6 `ProcessAuthConfig`

Credentials supplied by an external process implementing the AWS `credential_process` contract.

| Field | Type | Description |
|---|---|---|
| `command` | `string[]` | The command to execute, as separate arguments with the executable first |

The command is executed directly, without a shell — arguments are passed as an argument vector, so no shell metacharacter interpretation can occur. The process must print a JSON credential document to stdout. See [External Credential Processes](#72-external-credential-processes) for the security implications of this variant.

*AWS documentation:* [Sourcing credentials with an external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)

### 3.7 `DEFAULT_CREDENTIALS`

```ballerina
public const DEFAULT_CREDENTIALS = "DEFAULT_CREDENTIALS";
```

A string constant instructing the provider to resolve credentials via the standard default credential provider chain, trying each of the following in order and taking the first that yields a result:

1. JVM system properties (`aws.accessKeyId`/`aws.secretAccessKey`, and `aws.sessionToken` if set)
2. Environment variables (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, and `AWS_WEB_IDENTITY_TOKEN_FILE` if set)
3. The shared config/credentials file's active profile (`AWS_PROFILE`, or `default` if unset) — which may itself resolve via SSO
, an external process, or a chained `AssumeRole` call, depending on that profile's configuration
4. Container credentials (ECS/EKS)
5. EC2 instance profile (IMDS)

>**Note:** This is the precedence of the standard default credential provider chain that this library relies on for `DEFAULT_CREDENTIALS`; other AWS SDKs or the AWS CLI may order or nest these sub-steps slightly differently in edge cases. Configuring an explicit `AuthConfig` variant ([sections 3.1–3.6](#3-credential-configuration)) instead of `DEFAULT_CREDENTIALS` avoids depending on this precedence at all.

`DEFAULT_CREDENTIALS` is the right choice for code that runs on AWS infrastructure (EC2, ECS, EKS) or in a CI system with OIDC federation, since it needs no configuration and adapts to whichever identity the runtime environment already provides.

*AWS documentation:* [Standardized credential providers](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html) 

## 4. Types

### 4.1 `Credentials`

The value returned by `CredentialProvider.getCredentials()` — a resolved, currently-valid AWS credential:

```ballerina
public type Credentials record {
    string accessKeyId;
    string secretAccessKey;
    string sessionToken?;
};
```

`sessionToken` is present only when the resolved credential is temporary (STS, SSO, instance profile); it is absent for static long-lived credentials.

### 4.2 `SignatureRequest`

The input to [`getSignedHeaders`](#63-getsignedheaders) — an HTTP request description to sign with SigV4:

| Field | Type | Default | Description |
|---|---|---|---|
| `method` | `string` | — | HTTP method in upper case (`GET`, `POST`, ...) |
| `host` | `string` | — | Target host (e.g. `sns.us-east-1.amazonaws.com`) |
| `path` | `string` | `"/"` | Request path, unencoded |
| `queryParams` | `map<string>` | `{}` | Query parameters, unencoded |
| `headers` | `map<string>` | `{}` | Additional headers to sign (e.g. `content-type`); `host` and `x-amz-date` are always added |
| `payload` | `byte[]` | `[]` | Request body |
| `unsignedPayload` | `boolean` | `false` | Sign the payload as `UNSIGNED-PAYLOAD` (used for S3 streaming uploads) |
| `s3PathMode` | `boolean` | `false` | Use S3 path semantics: path segments encoded once and not normalized |

### 4.3 `EndpointConfig`

Options controlling endpoint resolution, accepted by [`resolveEndpoint`](#61-resolveendpoint) and [`resolveEndpointHost`](#62-resolveendpointhost):

| Field | Type | Default | Description |
|---|---|---|---|
| `fips` | `boolean` | `false` | Use the FIPS 140-validated endpoint variant (`{service}-fips.{region}...`) |
| `dualstack` | `boolean` | `false` | Use the dualstack (IPv4/IPv6) endpoint variant |
| `customEndpoint` | `string?` | — | Full endpoint URL override (e.g. `http://localhost:4566` for LocalStack). When set, all other options are ignored |

### 4.4 `ErrorDetails`

The shared error details type for connectors. All AWS services report failures through the same envelope, so a single detail record lets user code handle errors uniformly across services.

```ballerina
public type ErrorDetails record {|
    int httpStatusCode?;
    string httpStatusText?;
    string errorCode?;
    string errorMessage?;
    string requestId?;
|};
```

## 5. Errors

### 5.1 `Error`

The common base error type of the `auth` submodule.

```ballerina
public type Error distinct error;
```

### 5.2 `CredentialResolutionError`

Returned when a credential-related error occurs in the `aws.auth` module.

```ballerina
public type CredentialResolutionError distinct Error & error<aws:ErrorDetails>;
```
Error details are populated only when the failure originates from an AWS service call (STS `AssumeRole`/`AssumeRoleWithWebIdentity`, SSO `GetRoleCredentials`); absent for purely local failures (a missing credentials file, a cyclic role chain).

### 5.3 `SigningError`

```ballerina
public type SigningError distinct Error;
```

Returned by [`getSignedHeaders`](#63-getsignedheaders) when signing fails.

## 6. Functions

### 6.1 `resolveEndpoint`

```ballerina
public isolated function resolveEndpoint(string serviceName, Region|string region,
        EndpointConfig config = {}) returns string;
```

Resolves the full HTTPS endpoint URL for an AWS service in a region, using AWS's own published endpoint metadata — covering all partitions and per-service exceptions (e.g. GovCloud SQS's FIPS endpoint being identical to its standard one, or S3 China's dualstack endpoint using a different infix than the standard pattern) — with a pattern-based fallback for services or regions newer than the bundled metadata. A `customEndpoint` in `config` overrides both and is returned as-is.

###### Example: Resolving a standard endpoint

```ballerina
string url = aws:resolveEndpoint("sns", aws:US_EAST_1);
// "https://sns.us-east-1.amazonaws.com"
```

###### Example: Overriding with a custom endpoint (e.g. LocalStack)

```ballerina
string testUrl = aws:resolveEndpoint("sqs", aws:US_EAST_1, {customEndpoint: "http://localhost:4566"});
// "http://localhost:4566"
```

### 6.2 `resolveEndpointHost`

```ballerina
public isolated function resolveEndpointHost(string serviceName, Region|string region,
        EndpointConfig config = {}) returns string;
```

Resolves only the host part of the endpoint — no `http://`/`https://` scheme prefix. Use this when code needs to set the `Host` header explicitly. The returned value is not itself a URL and cannot be passed to `http:Client`'s constructor as-is.

###### Example:

```ballerina
string host = aws:resolveEndpointHost("sns", aws:US_EAST_1);
// "sns.us-east-1.amazonaws.com"
```

### 6.3 `getSignedHeaders`

```ballerina
public isolated function getSignedHeaders(SignatureRequest req, Credentials credentials, Region|string region,
        string serviceName) returns map<string>|SigningError;
```

Signs a request with AWS Signature Version 4 and returns the headers to set on the outbound request: `authorization`, `x-amz-date`, `x-amz-content-sha256`, and — for temporary credentials — `x-amz-security-token`. Header names are lowercase. Validated against the official SigV4 test vectors.

###### Example:

```ballerina
auth:Credentials credentials = check credProvider.getCredentials();
map<string> signedHeaders = check auth:getSignedHeaders({
    method: "POST",
    host: "sns.us-east-1.amazonaws.com",
    headers: {"content-type": "application/x-www-form-urlencoded"},
    payload: "Action=CreateTopic&Name=orders".toBytes()
}, credentials, aws:US_EAST_1, "sns");
```

## 7. Security

### 7.1 Credential Handling

Credential resolution, caching, refresh, and any cryptographic verification of STS/SSO responses are not reimplemented by this package — behavior for those follows AWS's own standard providers. `StaticAuthConfig` credentials are held in memory only for the lifetime of the `CredentialProvider` and are never logged; error messages produced by this package do not include the resolved `accessKeyId`/`secretAccessKey`/`sessionToken` values.

### 7.2 External Credential Processes

`ProcessAuthConfig`'s configured command is executed with the privileges of the running Ballerina program. The command is invoked directly as an argument vector, without a shell, so it cannot be subverted via shell metacharacter injection from the configuration values themselves — but the command itself runs with the calling program's full privileges. Prefer declaring the process in `~/.aws/config`'s `credential_process` setting and using `ProfileAuthConfig` or `DEFAULT_CREDENTIALS` instead of `ProcessAuthConfig` directly where possible, since that keeps the command's invocation under the AWS CLI's own configuration rather than in application code.

### 7.3 Resource Cleanup

Credential providers built for `AssumeRoleConfig`, `WebIdentityConfig`, and `SsoAuthConfig` hold background resources: an HTTP client for STS/SSO calls, and — for `AssumeRoleConfig` — an asynchronous credential-refresh thread. `CredentialProvider.close()` releases these. Callers that construct a `CredentialProvider` for the lifetime of a longer-lived client (the common pattern — see [As a Connector Dependency](#81-as-a-connector-dependency)) should close it when that client is closed, to avoid leaking the refresh thread and HTTP connections.

### 7.4 STS Role-Chaining Cycles

Because `AssumeRoleConfig.sourceCredentials` accepts the full `AuthConfig` union, a chain of nested `AssumeRoleConfig` values could reference itself, directly or transitively (role A's source is role B's config, whose source is role A's config again). Unbounded recursion here would either stack-overflow or hang attempting the chained `AssumeRole` calls. `CredentialProvider.init` detects this at construction time — using an identity-based visited-set walk of the `sourceCredentials` chain — and returns a `CredentialResolutionError` ("Circular sourceCredentials reference detected in the assume-role configuration chain") rather than recursing.

>**Note:** AWS STS itself limits the session duration of a *chained* (non-root) assumed role to one hour, regardless of the `duration` requested on the intermediate `AssumeRoleConfig` values. Only the root of the chain (the identity that isn't itself an assumed role) can request up to the role's configured maximum session duration.

## 8. Usage Patterns

### 8.1 As a Connector Dependency

A `ballerinax/aws.*` connector's `ConnectionConfig` embeds `auth:AuthConfig` directly, so the connector's own credential handling is just: resolve credentials once from the supplied `AuthConfig`, hand them to the underlying service client, and release them when the connector's client is closed.

```ballerina
public type ConnectionConfig record {|
    auth:AuthConfig auth;
    aws:Region region;
    aws:EndpointConfig endpoint?;
|};
```

This is the pattern used by `ballerinax/aws.sqs`; connectors adopting this package expose the same seven credential sources without reimplementing any of them.

### 8.2 Calling a Service With No Dedicated Connector

Because credential resolution, endpoint resolution, and signing are each usable standalone, this package can call any AWS service directly over a plain `http:Client`, without waiting for a dedicated Ballerina connector to exist:

```ballerina
import ballerina/http;
import ballerinax/aws;
import ballerinax/aws.auth;

public function main() returns error? {
    auth:CredentialProvider credProvider = check new (auth:DEFAULT_CREDENTIALS);
    string host = aws:resolveEndpointHost("events", aws:US_EAST_1);
    http:Client eventBridge = check new ("https://" + host);

    json putEventsRequest = {
        "Entries": [
            {"Source": "com.mycompany.orders", "DetailType": "OrderPlaced", "Detail": {"orderId": "o-1234"}.toJsonString()}
        ]
    };
    byte[] payload = putEventsRequest.toJsonString().toBytes();

    auth:Credentials credentials = check credProvider.getCredentials();
    map<string> signedHeaders = check auth:getSignedHeaders({
        method: "POST",
        host,
        headers: {"content-type": "application/x-amz-json-1.1", "x-amz-target": "AWSEvents.PutEvents"},
        payload
    }, credentials, aws:US_EAST_1, "events");

    http:Request request = new;
    request.setBinaryPayload(payload);
    foreach [string, string] [name, value] in signedHeaders.entries() {
        request.setHeader(name, value);
    }
    http:Response response = check eventBridge->execute("POST", "/", request);
}
```

## 9. Advanced Features

### 9.1 Automatic Credential Refresh

For every temporary-credential source (`AssumeRoleConfig`, `WebIdentityConfig`, `SsoAuthConfig`, and the instance-profile/container branches of `DEFAULT_CREDENTIALS`), the credential's expiry is tracked and a new one is transparently fetched ahead of expiry on the next `getCredentials()` call — the caller never observes an expired credential or needs to re-initialize the `CredentialProvider`.

### 9.2 Endpoint Metadata and Fallback

Endpoint resolution uses AWS's own published service-endpoint metadata, which correctly handles per-service partition exceptions that a hand-written pattern would miss — for example, GovCloud SQS's FIPS-variant hostname being identical to its standard hostname, and S3 China's dualstack endpoint using a legacy `s3.dualstack.` infix instead of the standard pattern. For a service or region not present in that metadata (typically a newly-added region), [`resolveEndpoint`](#61-resolveendpoint) falls back to standard pattern construction (`{service}[-fips].{region}.{dnsSuffix}`) rather than failing outright.

### 9.3 GraalVM Compatibility

The package is built and tested for GraalVM native-image compatibility, so connectors depending on it do not lose native-image support by adopting shared credential/signing handling in place of their own.
