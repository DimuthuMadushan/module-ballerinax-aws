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

package io.ballerina.lib.aws.auth;

import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.http.SdkHttpRequest;

import java.net.URI;
import java.util.Optional;

/**
 * Restores the path of a custom endpoint on requests of AWS Query protocol clients (STS).
 * <p>
 * The SDK's Query protocol marshaller resets the request path to empty, so an
 * {@code endpointOverride} such as {@code http://gateway:9090/sts/v1} is called as
 * {@code POST /} (aws/aws-sdk-java-v2#3387). This interceptor prefixes the endpoint
 * path back before the request is signed.
 */
final class EndpointPathInterceptor implements ExecutionInterceptor {

    private final String endpointPath;

    private EndpointPathInterceptor(String endpointPath) {
        this.endpointPath = endpointPath;
    }

    /**
     * Returns an interceptor for the given endpoint, or empty when it has no path to restore.
     */
    static Optional<ExecutionInterceptor> forEndpoint(URI endpoint) {
        String path = endpoint.getRawPath();
        while (path != null && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path == null || path.isEmpty() ? Optional.empty() : Optional.of(new EndpointPathInterceptor(path));
    }

    @Override
    public SdkHttpRequest modifyHttpRequest(Context.ModifyHttpRequest context,
                                            ExecutionAttributes executionAttributes) {
        SdkHttpRequest request = context.httpRequest();
        String requestPath = request.encodedPath();
        // Leave the request untouched if the SDK already kept the path (i.e. once the bug is fixed)
        if (requestPath.equals(endpointPath) || requestPath.startsWith(endpointPath + "/")) {
            return request;
        }
        String suffix = requestPath.isEmpty() || requestPath.equals("/") ? "" :
                (requestPath.startsWith("/") ? requestPath : "/" + requestPath);
        return request.toBuilder().encodedPath(endpointPath + suffix).build();
    }
}
