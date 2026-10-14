/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.ballerina.lib.aws;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;

import java.net.URI;

/**
 * Applies a Ballerina {@code aws:EndpointConfig} value to an AWS SDK
 * service client builder.
 */
public final class EndpointConfigUtils {

    private static final BString CUSTOM_ENDPOINT = StringUtils.fromString("customEndpoint");
    private static final BString FIPS = StringUtils.fromString("fips");
    private static final BString DUALSTACK = StringUtils.fromString("dualstack");

    private EndpointConfigUtils() {
    }

    /**
     * Applies the given endpoint configuration to the client builder.
     *
     * @param builder         the AWS service client builder (e.g. {@code SqsClient.builder()})
     * @param bEndpointConfig the Ballerina {@code aws:EndpointConfig} value
     * @throws IllegalArgumentException if {@code customEndpoint} is not an absolute http or https URL
     */
    public static void applyEndpointConfig(AwsClientBuilder<?, ?> builder,
                                           BMap<BString, Object> bEndpointConfig) {
        if (bEndpointConfig == null) {
            return;
        }
        if (bEndpointConfig.containsKey(CUSTOM_ENDPOINT)) {
            builder.endpointOverride(parseCustomEndpoint(
                    bEndpointConfig.getStringValue(CUSTOM_ENDPOINT).getValue()));
            builder.fipsEnabled(false);
            builder.dualstackEnabled(false);
            return;
        }
        // Set only when explicitly enabled, so the SDK's env/profile-based
        // FIPS/dualstack settings still apply when the flags are unset.
        if (bEndpointConfig.getBooleanValue(FIPS)) {
            builder.fipsEnabled(true);
        }
        if (bEndpointConfig.getBooleanValue(DUALSTACK)) {
            builder.dualstackEnabled(true);
        }
    }

    /**
     * Parses a custom endpoint, rejecting values that are well-formed URIs but cannot
     * be called (e.g. {@code localhost:4566}, which parses as scheme {@code localhost}).
     */
    private static URI parseCustomEndpoint(String endpoint) {
        URI uri = URI.create(endpoint);
        String scheme = uri.getScheme();
        boolean httpScheme = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        if (!httpScheme || uri.getHost() == null) {
            throw new IllegalArgumentException("Invalid custom endpoint '" + endpoint
                    + "': expected an absolute http or https URL with a valid host "
                    + "(e.g. http://localhost:4566)");
        }
        return uri;
    }
}
