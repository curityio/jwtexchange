package io.curity.plugins.procedure.jwtexchange

import org.jose4j.http.Response
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumer
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.http.HttpResponse
import se.curity.identityserver.sdk.plugin.ManagedObject
import se.curity.identityserver.sdk.service.HttpClient
import java.net.URI

class JwtConsumerManagedObject(private val _config: JwtExchangeTokenProcedureConfig) :
    ManagedObject<JwtExchangeTokenProcedureConfig>(_config)
{
    companion object
    {
        private val _logger: Logger = LoggerFactory.getLogger(JwtConsumerManagedObject::class.java)
    }

    private val _exceptionFactory = _config.getExceptionFactory()

    private var _jwtConsumer: JwtConsumer? = null

    private fun getJwtConsumer(httpClient : HttpClient) : JwtConsumer {
        return if (_config.getSignatureVerificationKey().isPresent)
        {
            JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setVerificationKey(_config.getSignatureVerificationKey().get().publicKey)
                .setExpectedAudience(_config.getAudience())
                .setExpectedIssuer(_config.getIssuer())
                .build()
        } else if (_config.getJwksEndpoint().isPresent)
        {

            val httpsJwks = HttpsJwks(_config.getJwksEndpoint().get())
            httpsJwks.setSimpleHttpGet { location ->
                val response = httpClient.request(URI(location)).get().response()
                Response(
                    response.statusCode(), response.toString(), response.headers().map(),
                    response.body(HttpResponse.asString())
                )
            }
            val httpsJwksKeyResolver = HttpsJwksVerificationKeyResolver(httpsJwks)

            JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .setExpectedAudience(_config.getAudience())
                .setExpectedIssuer(_config.getIssuer())
                .build()
        } else
        {
            throw _exceptionFactory.configurationException("Either signature verification key or JWKS uri must be configured")
        }
    }

    fun validateToClaims(jwt: String, httpClient: HttpClient): JwtClaims?
    {
        if(_jwtConsumer == null) {
            _jwtConsumer = getJwtConsumer(httpClient)
        }
        return try
        {
            _jwtConsumer!!.processToClaims(jwt)
        } catch (e: InvalidJwtException)
        {
            _logger.debug("Invalid JWT! $e")
            null
        }
    }
}