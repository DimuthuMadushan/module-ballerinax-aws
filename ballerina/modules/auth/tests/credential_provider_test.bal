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

import ballerina/test;

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testDefaultCredentialsInitSucceeds() returns error? {
    CredentialProvider _ = check new (DEFAULT_CREDENTIALS);
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testStaticCredentialProvider() returns error? {
    CredentialProvider provider = check new (staticAuth);
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, dummyAccessKeyId);
    test:assertEquals(credentials.secretAccessKey, dummySecretAccessKey);
    test:assertEquals(credentials?.sessionToken, ());
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testStaticProviderWithSessionToken() returns error? {
    CredentialProvider provider = check new ({
        accessKeyId: dummyAccessKeyId,
        secretAccessKey: dummySecretAccessKey,
        sessionToken: "EXAMPLETOKEN"
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials?.sessionToken, "EXAMPLETOKEN");
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testProfileCredentialProvider() returns error? {
    CredentialProvider provider = check new ({
        profileName: "test-profile",
        credentialsFilePath: "modules/auth/tests/resources/credentials"
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, "AKIDPROFILEEXAMPLE");
    test:assertEquals(credentials.secretAccessKey, "profileSecretAccessKey");
    test:assertEquals(credentials?.sessionToken, ());
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testProfileProviderWithSessionToken() returns error? {
    CredentialProvider provider = check new ({
        profileName: "test-profile-session",
        credentialsFilePath: "modules/auth/tests/resources/credentials"
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, "AKIDPROFILESESSION");
    test:assertEquals(credentials.secretAccessKey, "profileSessionSecretKey");
    test:assertEquals(credentials?.sessionToken, "profileSessionToken");
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testProcessCredentialProvider() returns error? {
    // The command prints a credential JSON document to stdout.
    CredentialProvider provider = check new ({
        command: ["cat", "modules/auth/tests/resources/process-credentials.json"]
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, "AKIDPROCESSEXAMPLE");
    test:assertEquals(credentials.secretAccessKey, "processSecretAccessKey");
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testWebIdentityInitSucceeds() returns error? {
    CredentialProvider _ = check new ({
        roleArn: "arn:aws:iam::111111111111:role/web-identity-role",
        webIdentityTokenFile: "modules/auth/tests/resources/web-identity-token"
    });
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testSsoMissingCachedSessionReturnsError() returns error? {
    CredentialProvider provider = check new ({
        ssoStartUrl: "https://ballerina-aws-auth-test.awsapps.com/start",
        ssoRegion: "us-east-1",
        accountId: "111111111111",
        roleName: "TestRole"
    });
    Credentials|Error credentials = provider.getCredentials();
    if credentials is Credentials {
        test:assertFail("Expected an error for a missing cached SSO session");
    } else {
        test:assertEquals(credentials.message(), "Error occurred while resolving the AWS credentials");
        error? cause = credentials.cause();
        string causeMessage = cause is error ? cause.message() : "";
        test:assertTrue(causeMessage.includes("No cached SSO session found"),
            "Unexpected cause message: " + causeMessage);
    }
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testSsoSessionMissingCachedTokenReturnsError() returns error? {
    // The modern sso-session flow: the token cache is looked up by the session name
    CredentialProvider provider = check new ({
        ssoStartUrl: "https://ballerina-aws-auth-test.awsapps.com/start",
        ssoRegion: "us-east-1",
        accountId: "111111111111",
        roleName: "TestRole",
        ssoSessionName: "ballerina-aws-auth-nonexistent-session"
    });
    Credentials|Error credentials = provider.getCredentials();
    if credentials is Credentials {
        test:assertFail("Expected an error for a missing sso-session token");
    } else {
        test:assertEquals(credentials.message(), "Error occurred while resolving the AWS credentials");
        error? cause = credentials.cause();
        string causeMessage = cause is error ? cause.message() : "";
        test:assertTrue(causeMessage.includes("Unable to load SSO token"),
            "Unexpected cause message: " + causeMessage);
    }
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testChainedAssumeRoleInitSucceeds() returns error? {
    CredentialProvider _ = check new ({
        roleArn: "arn:aws:iam::222222222222:role/spoke",
        sourceCredentials: {
            roleArn: "arn:aws:iam::111111111111:role/hub",
            sourceCredentials: staticAuth
        }
    });
}

const UNREACHABLE_STS_ENDPOINT = "http://127.0.0.1:1";

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testAssumeRoleUsesCustomStsEndpoint() returns error? {
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::111111111111:role/test-role",
        stsEndpoint: {customEndpoint: UNREACHABLE_STS_ENDPOINT},
        sourceCredentials: staticAuth
    });
    assertCallRoutedTo(provider.getCredentials(), "127.0.0.1:1");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testWebIdentityUsesCustomStsEndpoint() returns error? {
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::111111111111:role/web-identity-role",
        webIdentityTokenFile: "modules/auth/tests/resources/web-identity-token",
        stsEndpoint: {customEndpoint: UNREACHABLE_STS_ENDPOINT}
    });
    assertCallRoutedTo(provider.getCredentials(), "127.0.0.1:1");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testChainedAssumeRoleUsesPerHopStsEndpoint() returns error? {
    // The inner hop is resolved first, so its endpoint is the one contacted
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::222222222222:role/spoke",
        sourceCredentials: {
            roleArn: "arn:aws:iam::111111111111:role/hub",
            stsEndpoint: {customEndpoint: "http://127.0.0.1:2"},
            sourceCredentials: staticAuth
        }
    });
    assertCallRoutedTo(provider.getCredentials(), "127.0.0.1:2");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testCustomStsEndpointTakesPrecedenceOverFips() returns error? {
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::111111111111:role/test-role",
        stsEndpoint: {customEndpoint: UNREACHABLE_STS_ENDPOINT, fips: true, dualstack: true},
        sourceCredentials: staticAuth
    });
    assertCallRoutedTo(provider.getCredentials(), "127.0.0.1:1");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testAssumeRoleWithFipsStsEndpointInitSucceeds() returns error? {
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::111111111111:role/test-role",
        stsRegion: "us-gov-west-1",
        stsEndpoint: {fips: true},
        sourceCredentials: staticAuth
    });
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testInvalidStsEndpointReturnsError() {
    CredentialProvider|Error provider = new ({
        roleArn: "arn:aws:iam::111111111111:role/test-role",
        stsEndpoint: {customEndpoint: "sts endpoint"},
        sourceCredentials: staticAuth
    });
    if provider is CredentialProvider {
        test:assertFail("Expected an error for an invalid STS endpoint");
    } else {
        test:assertEquals(provider.message(), "Error occurred while initializing the credential provider");
    }
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testStsEndpointWithoutSchemeReturnsError() {
    // Parses as scheme `localhost` with no host; rejected at init instead of on the first call
    assertInvalidStsEndpointRejected("localhost:4566");
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testStsEndpointWithUnderscoreHostReturnsError() {
    // Underscores are not valid in hostnames, so the URL has no parsable host
    assertInvalidStsEndpointRejected("http://localstack_main:4566");
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testStsEndpointWithNonHttpSchemeReturnsError() {
    assertInvalidStsEndpointRejected("ftp://localhost:4566");
}

isolated function assertInvalidStsEndpointRejected(string endpoint) {
    CredentialProvider|Error provider = new ({
        roleArn: "arn:aws:iam::111111111111:role/test-role",
        stsEndpoint: {customEndpoint: endpoint},
        sourceCredentials: staticAuth
    });
    if provider is CredentialProvider {
        test:assertFail("Expected an error for the invalid STS endpoint: " + endpoint);
    }
    test:assertEquals(provider.message(), "Error occurred while initializing the credential provider");
    error? cause = provider.cause();
    string causeMessage = cause is error ? cause.message() : "";
    test:assertTrue(causeMessage.includes(string `Invalid custom endpoint '${endpoint}'`),
        "Unexpected cause message: " + causeMessage);
}

isolated function assertCallRoutedTo(Credentials|Error credentials, string address) {
    if credentials is Credentials {
        test:assertFail("Expected an error for an unreachable endpoint");
    }
    test:assertEquals(credentials.message(), "Error occurred while resolving the AWS credentials");
    error? cause = credentials.cause();
    string causeMessage = cause is error ? cause.message() : "";
    test:assertTrue(causeMessage.includes(address), "Unexpected cause message: " + causeMessage);
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testCyclicSourceCredentialsRejected() {
    AssumeRoleConfig roleA = {roleArn: "arn:aws:iam::111111111111:role/A"};
    AssumeRoleConfig roleB = {roleArn: "arn:aws:iam::222222222222:role/B", sourceCredentials: roleA};
    roleA.sourceCredentials = roleB;
    CredentialProvider|Error provider = new (roleA);
    if provider is CredentialProvider {
        test:assertFail("Expected an error for a cyclic sourceCredentials chain");
    } else {
        test:assertEquals(provider.message(), "Error occurred while initializing the credential provider");
        error? cause = provider.cause();
        string causeMessage = cause is error ? cause.message() : "";
        test:assertTrue(causeMessage.includes("Circular sourceCredentials"),
            "Unexpected cause message: " + causeMessage);
    }
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testMissingProfileReturnsError() {
    CredentialProvider|Error provider = new ({
        profileName: "nonexistent-profile-for-testing",
        credentialsFilePath: "/tmp/nonexistent-aws-credentials-file"
    });
    test:assertTrue(provider is Error, "Expected an error for a missing credentials file");
    Error err = <Error>provider;
    test:assertEquals(err.message(), "Error occurred while initializing the credential provider");
    error? cause = err.cause();
    string causeMessage = cause is error ? cause.message() : "";
    test:assertTrue(causeMessage.includes("nonexistent-aws-credentials-file' does not exist."),
        "Unexpected cause message: " + causeMessage);
}

@test:Config {
    groups: ["credentialProvider", "live"],
    enable: liveTestsEnabled
}
isolated function testEnvStaticCredentialProvider() returns error? {
    CredentialProvider provider = check new ({
        accessKeyId: testAccessKeyId,
        secretAccessKey: testSecretAccessKey
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, testAccessKeyId);
    test:assertEquals(credentials.secretAccessKey, testSecretAccessKey);
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testCloseReleasesProvider() returns error? {
    // Closeable provider (the default chain implements SdkAutoCloseable).
    CredentialProvider chainProvider = check new (DEFAULT_CREDENTIALS);
    check chainProvider.close();

    // Non-closeable provider (static) — close must be a safe no-op.
    CredentialProvider staticProvider = check new (staticAuth);
    Credentials _ = check staticProvider.getCredentials();
    check staticProvider.close();

    Credentials|Error credentials = staticProvider.getCredentials();
    if credentials is Credentials {
        test:assertFail("Expected an error when resolving credentials after close");
    } else {
        test:assertEquals(credentials.message(), "Error occurred while resolving the AWS credentials");
        error? cause = credentials.cause();
        string causeMessage = cause is error ? cause.message() : "";
        test:assertTrue(causeMessage.includes("already closed"),
            "Unexpected cause message: " + causeMessage);
    }
}
