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

import ballerina/http;
import ballerina/test;

// A mock STS mounted under a path prefix, as when STS is fronted by a gateway.
// The SDK's Query protocol client drops the custom endpoint's path, so these
// tests only receive credentials if the path is restored.
const MOCK_STS_PORT = 9097;
const MOCK_STS_PATH_ENDPOINT = "http://localhost:9097/wso2/sts/v1";

listener http:Listener mockStsListener = new (MOCK_STS_PORT);

service /wso2/sts/v1 on mockStsListener {
    resource function post .(http:Request req) returns http:Response|error {
        map<string> params = check req.getFormParams();
        string action = params["Action"] ?: "";
        http:Response res = new;
        res.setTextPayload(string `<${action}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <${action}Result>
    <Credentials>
      <AccessKeyId>ASIAMOCK${action}</AccessKeyId>
      <SecretAccessKey>mockSecretAccessKey</SecretAccessKey>
      <SessionToken>mockSessionToken</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </${action}Result>
  <ResponseMetadata><RequestId>mock-request</RequestId></ResponseMetadata>
</${action}Response>`, "text/xml");
        return res;
    }
}

@test:Config {
    groups: ["credentialProvider", "stsEndpoint"]
}
isolated function testAssumeRoleKeepsCustomStsEndpointPath() returns error? {
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::111111111111:role/test-role",
        stsEndpoint: {customEndpoint: MOCK_STS_PATH_ENDPOINT},
        sourceCredentials: staticAuth
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, "ASIAMOCKAssumeRole");
    test:assertEquals(credentials.sessionToken, "mockSessionToken");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider", "stsEndpoint"]
}
isolated function testAssumeRoleKeepsCustomStsEndpointPathWithTrailingSlash() returns error? {
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::111111111111:role/test-role",
        stsEndpoint: {customEndpoint: MOCK_STS_PATH_ENDPOINT + "/"},
        sourceCredentials: staticAuth
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, "ASIAMOCKAssumeRole");
    check provider.close();
}

@test:Config {
    groups: ["credentialProvider", "stsEndpoint"]
}
isolated function testWebIdentityKeepsCustomStsEndpointPath() returns error? {
    CredentialProvider provider = check new ({
        roleArn: "arn:aws:iam::111111111111:role/web-identity-role",
        webIdentityTokenFile: "modules/auth/tests/resources/web-identity-token",
        stsEndpoint: {customEndpoint: MOCK_STS_PATH_ENDPOINT}
    });
    Credentials credentials = check provider.getCredentials();
    test:assertEquals(credentials.accessKeyId, "ASIAMOCKAssumeRoleWithWebIdentity");
    check provider.close();
}
