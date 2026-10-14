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

import ballerina/file;
import ballerina/io;
import ballerina/os;
import ballerina/test;

// The SSO token cache lives under the user's home directory and is keyed by the
// SHA-1 hex digest of the start URL (legacy) or the sso-session name. The fixtures
// use test-only names, so they never collide with real cached sessions.
const SSO_ENDPOINT_TEST_START_URL = "https://ballerina-aws-auth-endpoint-test.awsapps.com/start";
const SSO_ENDPOINT_TEST_SESSION_NAME = "ballerina-aws-auth-endpoint-test-session";
const SSO_ENDPOINT_TEST_START_URL_DIGEST = "c14aa0662cc01d93039e71d5b8d45c0a649cd633";
const SSO_ENDPOINT_TEST_SESSION_NAME_DIGEST = "5c59f4f44b66ff5cbbe186d916c32eed2054e8f3";

@test:BeforeGroups {value: ["ssoEndpoint"]}
function writeSsoCacheFixtures() returns error? {
    string cacheDir = check ssoCacheDir();
    check file:createDir(cacheDir, file:RECURSIVE);
    // Legacy cache entry: the token is used as is
    check io:fileWriteJson(check file:joinPath(cacheDir, SSO_ENDPOINT_TEST_START_URL_DIGEST + ".json"), {
        accessToken: "test-access-token",
        expiresAt: "2099-01-01T00:00:00Z",
        region: "us-east-1",
        startUrl: SSO_ENDPOINT_TEST_START_URL
    });
    // sso-session cache entry with an expired token, forcing an SSO-OIDC refresh
    check io:fileWriteJson(check file:joinPath(cacheDir, SSO_ENDPOINT_TEST_SESSION_NAME_DIGEST + ".json"), {
        accessToken: "test-expired-access-token",
        expiresAt: "2020-01-01T00:00:00Z",
        refreshToken: "test-refresh-token",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        registrationExpiresAt: "2099-01-01T00:00:00Z",
        region: "us-east-1",
        startUrl: SSO_ENDPOINT_TEST_START_URL
    });
}

@test:AfterGroups {value: ["ssoEndpoint"], alwaysRun: true}
function removeSsoCacheFixtures() returns error? {
    string cacheDir = check ssoCacheDir();
    foreach string digest in [SSO_ENDPOINT_TEST_START_URL_DIGEST, SSO_ENDPOINT_TEST_SESSION_NAME_DIGEST] {
        string path = check file:joinPath(cacheDir, digest + ".json");
        if check file:test(path, file:EXISTS) {
            check file:remove(path);
        }
    }
}

@test:Config {
    groups: ["credentialProvider", "ssoEndpoint"]
}
isolated function testSsoUsesCustomPortalEndpoint() returns error? {
    CredentialProvider provider = check new ({
        ssoStartUrl: SSO_ENDPOINT_TEST_START_URL,
        ssoRegion: "us-east-1",
        accountId: "111111111111",
        roleName: "TestRole",
        ssoEndpoint: {customEndpoint: "http://127.0.0.1:1"}
    });
    assertCallRoutedTo(provider.getCredentials(), "127.0.0.1:1");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider", "ssoEndpoint"]
}
isolated function testSsoSessionUsesCustomOidcEndpoint() returns error? {
    CredentialProvider provider = check new ({
        ssoStartUrl: SSO_ENDPOINT_TEST_START_URL,
        ssoRegion: "us-east-1",
        accountId: "111111111111",
        roleName: "TestRole",
        ssoSessionName: SSO_ENDPOINT_TEST_SESSION_NAME,
        ssoEndpoint: {customEndpoint: "http://127.0.0.1:1"},
        ssoOidcEndpoint: {customEndpoint: "http://127.0.0.1:2"}
    });
    // The expired token is refreshed first, so the OIDC endpoint is the one contacted
    assertCallRoutedTo(provider.getCredentials(), "127.0.0.1:2");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider"]
}
isolated function testInvalidSsoEndpointReturnsError() {
    CredentialProvider|Error provider = new ({
        ssoStartUrl: SSO_ENDPOINT_TEST_START_URL,
        ssoRegion: "us-east-1",
        accountId: "111111111111",
        roleName: "TestRole",
        ssoEndpoint: {customEndpoint: "sso endpoint"}
    });
    if provider is CredentialProvider {
        test:assertFail("Expected an error for an invalid SSO endpoint");
    } else {
        test:assertEquals(provider.message(), "Error occurred while initializing the credential provider");
    }
}

// Mirrors the SDK's home directory resolution (HOME first, then USERPROFILE).
function ssoCacheDir() returns string|error {
    string home = os:getEnv("HOME");
    if home == "" {
        home = os:getEnv("USERPROFILE");
    }
    return file:joinPath(home, ".aws", "sso", "cache");
}
