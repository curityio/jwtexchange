package io.curity.plugins.procedure.jwtexchange

import se.curity.identityserver.sdk.config.Configuration
import se.curity.identityserver.sdk.config.annotation.DefaultService
import se.curity.identityserver.sdk.config.annotation.Description
import se.curity.identityserver.sdk.plugin.descriptor.TokenProcedurePluginDescriptor
import se.curity.identityserver.sdk.procedure.token.context.TokenIssuersProvider
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.crypto.AsymmetricSignatureVerificationCryptoStore
import se.curity.identityserver.sdk.service.issuer.AccessTokenIssuer
import se.curity.identityserver.sdk.service.issuer.IdTokenIssuer
import se.curity.identityserver.sdk.service.issuer.NonceIssuer
import se.curity.identityserver.sdk.service.issuer.RefreshTokenIssuer



class JwtExchangeTokenProcedureDescriptor: TokenProcedurePluginDescriptor<JwtExchangeTokenProcedureConfig>
{
    override fun getOAuthTokenEndpointTokenExchangeTokenProcedure() = JwtExchangeTokenExchangeTokenProcedure::class.java

    override fun getPluginImplementationType() = "jwtexchange"

    override fun getConfigurationType() = JwtExchangeTokenProcedureConfig::class.java    
}
