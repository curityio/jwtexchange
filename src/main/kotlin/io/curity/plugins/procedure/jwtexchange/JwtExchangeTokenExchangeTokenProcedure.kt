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

import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.attribute.token.AccessTokenAttributes
import se.curity.identityserver.sdk.data.tokens.TokenIssuerException
import se.curity.identityserver.sdk.errors.ErrorCode.INVALID_INPUT
import se.curity.identityserver.sdk.procedure.token.TokenExchangeTokenProcedure
import se.curity.identityserver.sdk.procedure.token.context.TokenExchangeTokenProcedurePluginContext
import se.curity.identityserver.sdk.web.ResponseModel
import java.time.Instant


class JwtExchangeTokenExchangeTokenProcedure(
    private val _configuration: JwtExchangeTokenProcedureConfig,
    private val _jwtConsumer: JwtConsumerManagedObject
) : TokenExchangeTokenProcedure
{
    private val _logger = LoggerFactory.getLogger(JwtExchangeTokenExchangeTokenProcedure::class.java)
    override fun run(context: TokenExchangeTokenProcedurePluginContext): ResponseModel
    {
        val subjectToken = context.request.getFormParameterValueOrError("subject_token") { _ ->
            throw _configuration.getExceptionFactory()
                .badRequestException(INVALID_INPUT, "Multiple subject_token in request")
        } ?: throw _configuration.getExceptionFactory()
            .badRequestException(INVALID_INPUT, "No subject_token in request")


        val subjectTokenClaims = _jwtConsumer.validateToClaims(subjectToken, _configuration.getHttpClient())
            ?: throw _configuration.getExceptionFactory()
                .badRequestException(INVALID_INPUT, "Could not validate subject token")
        val accessTokenData = AccessTokenAttributes.fromMap(subjectTokenClaims.claimsMap)

        val accessTokenIssuer = _configuration.getAccessTokenIssuer()
        return try
        {
            val issuedAccessToken = accessTokenIssuer.issue(accessTokenData, context.delegation)

            ResponseModel.mapResponseModel(
                mapOf(
                    "scope" to accessTokenData.scope,
                    "access_token" to issuedAccessToken,
                    "token_type" to "bearer",
                    "expires_in" to accessTokenData.expires.epochSecond - Instant.now().epochSecond
                )
            )
        } catch (e: TokenIssuerException)
        {
            ResponseModel.problemResponseModel("token_issuer_exception", "Could not issue new tokens")
        }
    }
}
