/*
 *  Copyright 2023 Curity AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package io.curity.plugins.procedure.jwtexchange

import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.annotation.DefaultService
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.HttpClient
import se.curity.identityserver.sdk.service.crypto.AsymmetricSignatureVerificationCryptoStore
import se.curity.identityserver.sdk.service.issuer.AccessTokenIssuer
import java.util.Optional

interface JwtExchangeTokenProcedureConfig : Configuration
{
    @DefaultService
    fun getAccessTokenIssuer(): AccessTokenIssuer

    fun getExceptionFactory(): ExceptionFactory

    fun getIssuer(): String

    fun getSignatureVerificationKey(): Optional<AsymmetricSignatureVerificationCryptoStore>

    fun getJwksEndpoint(): Optional<String>

    @DefaultService
    fun getHttpClient() : HttpClient
}