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

import org.jose4j.jwk.HttpsJwks
import org.jose4j.jwt.consumer.JwtConsumer
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.data.tokens.TokenIssuerException
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.procedure.token.TokenExchangeTokenProcedure
import se.curity.identityserver.sdk.procedure.token.context.TokenExchangeTokenProcedurePluginContext
import se.curity.identityserver.sdk.web.ResponseModel
import java.time.Instant


class JwtExchangeTokenExchangeTokenProcedure(private val _configuration: JwtExchangeTokenProcedureConfig) : TokenExchangeTokenProcedure
{
    private val _logger = LoggerFactory.getLogger(JwtExchangeTokenExchangeTokenProcedure::class.java)
    override fun run(context: TokenExchangeTokenProcedurePluginContext): ResponseModel
    {
        val subjectToken= context.request.getFormParameterValueOrError("subject_token") { _ ->
            throw _configuration.getExceptionFactory().badRequestException(ErrorCode.INVALID_INPUT, "Multiple subject_token in request")
        } ?: throw _configuration.getExceptionFactory().badRequestException(ErrorCode.INVALID_INPUT, "No subject_token in request")

        validateJWT(subjectToken)

        val accessTokenIssuer = _configuration.getAccessTokenIssuer()
        val accessTokenData = context.getDefaultAccessTokenData(context.delegation)

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

    private fun validateJWT(jwt: String)
    {
        lateinit var jwtConsumer: JwtConsumer

        //If using a configured signature verification key
        if(_configuration.getSignatureVerificationKey().isPresent) {
            jwtConsumer = JwtConsumerBuilder()
                .setVerificationKey(_configuration.getSignatureVerificationKey().get().publicKey)
                .setExpectedAudience(_configuration.getAudience())
                .setExpectedIssuer(_configuration.getIssuer())
                .build()
        }
        //if using a JWKS Endpoint, NOT TESTED
        else if (_configuration.getJwksEndpoint().isPresent)
        {
            val httpsJkws = HttpsJwks(_configuration.getJwksEndpoint().get())
            val httpsJwksKeyResolver = HttpsJwksVerificationKeyResolver(httpsJkws)

            jwtConsumer = JwtConsumerBuilder()
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .setExpectedAudience(_configuration.getAudience())
                .setExpectedIssuer(_configuration.getIssuer())
                .build()
        }

        jwtConsumer.process(jwt)
    }
}
