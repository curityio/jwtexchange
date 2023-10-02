package io.curity.plugins.procedure.jwtexchange

import se.curity.identityserver.sdk.Nullable
import se.curity.identityserver.sdk.data.tokens.TokenIssuerException
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.procedure.token.TokenExchangeTokenProcedure
import se.curity.identityserver.sdk.procedure.token.context.TokenExchangeTokenProcedurePluginContext
import se.curity.identityserver.sdk.web.ResponseModel
import java.time.Instant

class JwtExchangeTokenExchangeTokenProcedure(private val _configuration: JwtExchangeTokenProcedureConfig) : TokenExchangeTokenProcedure
{

    override fun run(context: TokenExchangeTokenProcedurePluginContext): ResponseModel
    {
        val subjectToken= context.request.getFormParameterValueOrError("subject_token") { _ ->
            throw _configuration.getExceptionFactory().badRequestException(ErrorCode.INVALID_INPUT, "Multiple subject_token in request")
        } ?: throw _configuration.getExceptionFactory().badRequestException(ErrorCode.INVALID_INPUT, "No subject_token in request")

        // TODO: validate token

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
}
