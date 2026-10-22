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

import io.ballerina.lib.aws.EndpointConfigUtils;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProcessCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sso.SsoClient;
import software.amazon.awssdk.services.sso.SsoClientBuilder;
import software.amazon.awssdk.services.sso.auth.SsoCredentialsProvider;
import software.amazon.awssdk.services.sso.model.GetRoleCredentialsRequest;
import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.ssooidc.SsoOidcClientBuilder;
import software.amazon.awssdk.services.ssooidc.SsoOidcTokenProvider;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.auth.StsWebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.utils.SdkAutoCloseable;
import software.amazon.awssdk.utils.UserHomeDirectoryUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds an AWS credentials provider from a Ballerina {@code aws.auth:AuthConfig} value.
 * 
 */
public final class ProviderFactory {

    private static final BString ACCESS_KEY_ID = StringUtils.fromString("accessKeyId");
    private static final BString SECRET_ACCESS_KEY = StringUtils.fromString("secretAccessKey");
    private static final BString SESSION_TOKEN = StringUtils.fromString("sessionToken");
    private static final BString PROFILE_NAME = StringUtils.fromString("profileName");
    private static final BString CREDENTIALS_FILE_PATH = StringUtils.fromString("credentialsFilePath");
    private static final BString ROLE_ARN = StringUtils.fromString("roleArn");
    private static final BString ROLE_SESSION_NAME = StringUtils.fromString("roleSessionName");
    private static final BString EXTERNAL_ID = StringUtils.fromString("externalId");
    private static final BString DURATION = StringUtils.fromString("duration");
    private static final BString STS_REGION = StringUtils.fromString("stsRegion");
    private static final BString STS_ENDPOINT = StringUtils.fromString("stsEndpoint");
    private static final BString SOURCE_CREDENTIALS = StringUtils.fromString("sourceCredentials");
    private static final BString WEB_IDENTITY_TOKEN_FILE = StringUtils.fromString("webIdentityTokenFile");
    private static final BString SSO_START_URL = StringUtils.fromString("ssoStartUrl");
    private static final BString SSO_REGION = StringUtils.fromString("ssoRegion");
    private static final BString SSO_SESSION_NAME = StringUtils.fromString("ssoSessionName");
    private static final BString SSO_ENDPOINT = StringUtils.fromString("ssoEndpoint");
    private static final BString SSO_OIDC_ENDPOINT = StringUtils.fromString("ssoOidcEndpoint");
    private static final BString ACCOUNT_ID = StringUtils.fromString("accountId");
    private static final BString ROLE_NAME = StringUtils.fromString("roleName");
    private static final BString COMMAND = StringUtils.fromString("command");

    private static final Pattern SSO_ACCESS_TOKEN = Pattern.compile("\"accessToken\"\\s*:\\s*\"([^\"]+)\"");

    private ProviderFactory() {
    }

    /**
     * @param bConfig the Ballerina {@code aws.auth:AuthConfig} value
     * @return the corresponding {@link AwsCredentialsProvider}
     * @throws IllegalArgumentException if the configuration is unsupported or cyclic
     */
    public static AwsCredentialsProvider buildProvider(Object bConfig) {
        return buildProvider(bConfig, Collections.newSetFromMap(new IdentityHashMap<>()));
    }

    /**
     * Releases the resources held by a credentials provider built by this
     * factory (background refresh threads, HTTP connections) when the provider
     * implements {@link SdkAutoCloseable}.
     *
     * @param provider the credentials provider to release
     */
    public static void closeProvider(AwsCredentialsProvider provider) {
        if (provider instanceof SdkAutoCloseable closeable) {
            closeable.close();
        }
    }

    /**
     * Recursive variant; rejects cyclic {@code sourceCredentials} chains.
     */
    @SuppressWarnings("unchecked")
    private static AwsCredentialsProvider buildProvider(Object bConfig, Set<Object> visited) {
        if (bConfig instanceof BString) {
            // The DEFAULT_CREDENTIALS constant.
            return DefaultCredentialsProvider.builder().build();
        }
        BMap<BString, Object> config = (BMap<BString, Object>) bConfig;
        if (!visited.add(config)) {
            throw new IllegalArgumentException(
                    "Circular sourceCredentials reference detected in the assume-role configuration chain");
        }
        if (config.containsKey(ACCESS_KEY_ID)) {
            return buildStaticProvider(config);
        }
        if (config.containsKey(PROFILE_NAME)) {
            return buildProfileProvider(config);
        }
        if (config.containsKey(WEB_IDENTITY_TOKEN_FILE)) {
            return buildWebIdentityProvider(config);
        }
        if (config.containsKey(ROLE_ARN)) {
            return buildAssumeRoleProvider(config, visited);
        }
        if (config.containsKey(SSO_START_URL)) {
            return buildSsoProvider(config);
        }
        if (config.containsKey(COMMAND)) {
            return buildProcessProvider(config);
        }
        throw new IllegalArgumentException("Unsupported authentication configuration");
    }

    private static AwsCredentialsProvider buildStaticProvider(BMap<BString, Object> config) {
        String accessKeyId = config.getStringValue(ACCESS_KEY_ID).getValue();
        String secretAccessKey = config.getStringValue(SECRET_ACCESS_KEY).getValue();
        AwsCredentials credentials = config.containsKey(SESSION_TOKEN)
                ? AwsSessionCredentials.create(accessKeyId, secretAccessKey,
                        config.getStringValue(SESSION_TOKEN).getValue())
                : AwsBasicCredentials.create(accessKeyId, secretAccessKey);
        return StaticCredentialsProvider.create(credentials);
    }

    private static AwsCredentialsProvider buildProfileProvider(BMap<BString, Object> config) {
        String credentialsFilePath = expandHome(config.getStringValue(CREDENTIALS_FILE_PATH).getValue());
        return ProfileCredentialsProvider.builder()
                .profileName(config.getStringValue(PROFILE_NAME).getValue())
                .profileFile(ProfileFile.builder()
                        .content(Paths.get(credentialsFilePath))
                        .type(ProfileFile.Type.CREDENTIALS)
                        .build())
                .build();
    }

    private static AwsCredentialsProvider buildWebIdentityProvider(BMap<BString, Object> config) {
        // AssumeRoleWithWebIdentity is an unsigned call.
        StsClient stsClient = buildStsClient(config, AnonymousCredentialsProvider.create());
        return StsWebIdentityTokenFileCredentialsProvider.builder()
                .stsClient(stsClient)
                .roleArn(config.getStringValue(ROLE_ARN).getValue())
                .roleSessionName(resolveRoleSessionName(config))
                .webIdentityTokenFile(Paths.get(expandHome(
                        config.getStringValue(WEB_IDENTITY_TOKEN_FILE).getValue())))
                .build();
    }

    private static AwsCredentialsProvider buildAssumeRoleProvider(BMap<BString, Object> config,
            Set<Object> visited) {
        AwsCredentialsProvider sourceProvider = buildProvider(config.get(SOURCE_CREDENTIALS), visited);
        StsClient stsClient = buildStsClient(config, sourceProvider);
        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(config.getStringValue(ROLE_ARN).getValue())
                .roleSessionName(resolveRoleSessionName(config))
                .durationSeconds(config.getIntValue(DURATION).intValue());
        if (config.containsKey(EXTERNAL_ID)) {
            request.externalId(config.getStringValue(EXTERNAL_ID).getValue());
        }
        return StsAssumeRoleCredentialsProvider.builder()
                .stsClient(stsClient)
                .refreshRequest(request.build())
                .asyncCredentialUpdateEnabled(true)
                .build();
    }

    /**
     * Builds the STS client for the configured region, applying the optional
     * {@code stsEndpoint} options.
     */
    @SuppressWarnings("unchecked")
    private static StsClient buildStsClient(BMap<BString, Object> config,
            AwsCredentialsProvider credentialsProvider) {
        StsClientBuilder builder = StsClient.builder()
                .region(Region.of(config.getStringValue(STS_REGION).getValue()))
                .credentialsProvider(credentialsProvider);
        applyOptionalEndpoint(builder, config, STS_ENDPOINT);
        // STS uses the Query protocol, whose marshaller drops the custom endpoint's path
        // (aws/aws-sdk-java-v2#3387). Only stsEndpoint.customEndpoint is restored; a path in an
        // endpoint from AWS_ENDPOINT_URL_STS, AWS_ENDPOINT_URL or the profile is still dropped
        // until the SDK bug is fixed.
        if (config.containsKey(STS_ENDPOINT)) {
            EndpointConfigUtils.getCustomEndpoint((BMap<BString, Object>) config.get(STS_ENDPOINT))
                    .flatMap(EndpointPathInterceptor::forEndpoint)
                    .ifPresent(interceptor -> addExecutionInterceptor(builder, interceptor));
        }
        return builder.build();
    }

    /**
     * Applies the {@code aws:EndpointConfig} in the given field, if set. When it is
     * unset, the SDK's env/profile-based endpoint settings (e.g.
     * {@code AWS_ENDPOINT_URL_STS}) still apply.
     */
    @SuppressWarnings("unchecked")
    private static void applyOptionalEndpoint(AwsClientBuilder<?, ?> builder, BMap<BString, Object> config,
            BString field) {
        if (config.containsKey(field)) {
            EndpointConfigUtils.applyEndpointConfig(builder, (BMap<BString, Object>) config.get(field));
        }
    }

    /**
     * Adds an execution interceptor while keeping the builder's existing override
     * configuration. Use this (not {@code overrideConfiguration(Consumer)}, which replaces
     * the whole configuration) for any override set on the auth clients.
     */
    private static void addExecutionInterceptor(AwsClientBuilder<?, ?> builder, ExecutionInterceptor interceptor) {
        builder.overrideConfiguration(builder.overrideConfiguration().toBuilder()
                .addExecutionInterceptor(interceptor)
                .build());
    }

    private static AwsCredentialsProvider buildSsoProvider(BMap<BString, Object> config) {
        String ssoRegion = config.getStringValue(SSO_REGION).getValue();
        SsoClientBuilder ssoBuilder = SsoClient.builder()
                .region(Region.of(ssoRegion));
        applyOptionalEndpoint(ssoBuilder, config, SSO_ENDPOINT);
        SsoClient ssoClient = ssoBuilder.build();
        Supplier<String> accessToken = ssoAccessTokenSupplier(config, ssoRegion);
        // Chain through the public Builder interface
        SsoCredentialsProvider.Builder builder = SsoCredentialsProvider.builder();
        builder = builder.ssoClient(ssoClient)
                .refreshRequest(() -> GetRoleCredentialsRequest.builder()
                        .accountId(config.getStringValue(ACCOUNT_ID).getValue())
                        .roleName(config.getStringValue(ROLE_NAME).getValue())
                        .accessToken(accessToken.get())
                        .build());
        return builder.build();
    }

    /**
     * With {@code ssoSessionName}: token cached under the session name, auto-refreshed
     * via SSO-OIDC. Without: token cached under the start URL, used as is.
     */
    private static Supplier<String> ssoAccessTokenSupplier(BMap<BString, Object> config, String ssoRegion) {
        if (config.containsKey(SSO_SESSION_NAME)) {
            SsoOidcClientBuilder oidcBuilder = SsoOidcClient.builder()
                    .region(Region.of(ssoRegion))
                    .credentialsProvider(AnonymousCredentialsProvider.create());
            applyOptionalEndpoint(oidcBuilder, config, SSO_OIDC_ENDPOINT);
            SsoOidcClient oidcClient = oidcBuilder.build();
            SsoOidcTokenProvider tokenProvider = SsoOidcTokenProvider.builder()
                    .ssoOidcClient(oidcClient)
                    .sessionName(config.getStringValue(SSO_SESSION_NAME).getValue())
                    .build();
            return () -> tokenProvider.resolveToken().token();
        }
        String startUrl = config.getStringValue(SSO_START_URL).getValue();
        return () -> loadCachedSsoAccessToken(startUrl);
    }

    private static AwsCredentialsProvider buildProcessProvider(BMap<BString, Object> config) {
        // The config value is the argv (executable + arguments); executed
        // directly, No shell metacharacter interpretation can occur.
        List<String> command = List.of(config.getArrayValue(COMMAND).getStringArray());
        return ProcessCredentialsProvider.builder()
                .command(command)
                .build();
    }

    /**
     * Reads the token cached by {@code aws sso login}; the file name is the
     * SHA-1 hex digest of the start URL.
     */
    private static String loadCachedSsoAccessToken(String startUrl) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            String fileName = HexFormat.of().formatHex(
                    sha1.digest(startUrl.getBytes(StandardCharsets.UTF_8))) + ".json";
            Path cacheFile = Paths.get(expandHome("~/.aws/sso/cache"), fileName);
            if (!Files.exists(cacheFile)) {
                throw new IllegalStateException(
                        "No cached SSO session found. Run 'aws sso login' and retry.");
            }
            String content = Files.readString(cacheFile, StandardCharsets.UTF_8);
            Matcher matcher = SSO_ACCESS_TOKEN.matcher(content);
            if (!matcher.find()) {
                throw new IllegalStateException(
                        "Cached SSO session is invalid. Run 'aws sso login' and retry.");
            }
            return matcher.group(1);
        } catch (java.io.IOException | java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to read the cached SSO session: " + e.getMessage(), e);
        }
    }

    /**
     * Returns the configured role session name, or generates a unique one.
     */
    private static String resolveRoleSessionName(BMap<BString, Object> config) {
        return config.containsKey(ROLE_SESSION_NAME)
                ? config.getStringValue(ROLE_SESSION_NAME).getValue()
                : "ballerina-aws-auth-" + System.currentTimeMillis();
    }

    private static String expandHome(String path) {
        // Resolve the home directory (HOME env var first, then platform fallbacks)
        // to paths agree with the cache and credential files even
        // when HOME is overridden (containers, CI).
        return path.startsWith("~")
                ? UserHomeDirectoryUtils.userHomeDirectory() + path.substring(1)
                : path;
    }
}
