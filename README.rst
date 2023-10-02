JwtExchange Token Procedure Kotlin Plugin
=============================================

A custom Token Procedure plugin for the Curity Identity Server.

Building the Plugin
~~~~~~~~~~~~~~~~~~~

You can build the plugin by issuing the command ``mvn package``. This will produce a JAR file in the ``target`` directory,
which can be installed.

Installing the Plugin
~~~~~~~~~~~~~~~~~~~~~

To install the plugin, copy the compiled JAR (and all of its dependencies) into the :file:`${IDSVR_HOME}/usr/share/plugins/JwtExchange`
on each node, including the admin node. For more information about installing plugins, refer to the `curity.io/plugins`_.

Required Dependencies
"""""""""""""""""""""

For a list of the dependencies and their versions, run ``mvn dependency:list``. Ensure that all of these are installed in
the plugin group; otherwise, they will not be accessible to this plug-in and run-time errors will result.

Configuring the Plugin
"""""""""""""""""""""

`Access Token Issuer`: The issuer to use when issuing the response token
`Signature Verification Key`: A configured signature verification key to be used when validating the received JWT (If JWKS Endpoint is not used)
`Audience`: The allowed value in the `aud` claim of the received JWT
`Issuer`: The allowed value in the `iss` claim of the received JWT
`JWKS Endpoint`: The JWKS Endpoint if used for JWT validation

1. Configure the Token Exchange Flow on a new `token` endpoint (ex. `/jwt-exchange`) and set it to use the Plugin.
2. Configure a client with the `Client Credentials` and `Token Exchange` capabilities.
3. Obtain a token using the previously configured client using the Client Credentials Flow.
4. Run a POST Request to the new token endpoint (`/jwt-exchange`). See example below where the `token` value is the token obtain in step 3. The client_id and client_secret is the configured client in step 2. The `subject_token` is the JWT that is to be exchanged.

Example Request
"""""""""""""""""""""

`
curl -Ss -X POST \
https://iggbom-curity.ngrok.io/jwt-exchange \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=https://curity.se/grant/accesstoken' \
--data-urlencode 'client_id=oauth-tools' \
--data-urlencode 'scope=email' \
--data-urlencode 'token=_0XBPWQQ_ac25d03b-f195-4710-8447-57fa4b9a217d' \
--data-urlencode 'client_secret=Pa$$w0rd1!' \
--data-urlencode 'subject_token=eyJhbGciOiJSUzI1NiJ9.eyJodHRw...leiEN5_Qz8c'
`

More Information
~~~~~~~~~~~~~~~~

Please visit `curity.io`_ for more information about the Curity Identity Server.

.. _curity.io/plugins: https://curity.io/docs/idsvr/latest/developer-guide/plugins/index.html#plugin-installation
.. _curity.io: https://curity.io/
