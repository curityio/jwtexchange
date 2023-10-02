package io.curity.plugins.procedure.jwtexchange

import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.annotation.DefaultService
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.crypto.AsymmetricSignatureVerificationCryptoStore
import se.curity.identityserver.sdk.service.issuer.AccessTokenIssuer
import java.util.*

interface JwtExchangeTokenProcedureConfig : Configuration
{
    @DefaultService
    fun getAccessTokenIssuer(): AccessTokenIssuer

    fun getExceptionFactory(): ExceptionFactory

    fun getJwksEndpoint(): Optional<String>

    fun  getSignatureVerificationKey(): Optional<AsymmetricSignatureVerificationCryptoStore>

    fun getAudience(): String

    fun getIssuer(): String
}