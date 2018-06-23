/*
Copyright 2018 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
*/

const {Command} = require('@oclif/command')
const Config = require('@adobe/aio-cli-plugin-config')
const {validateToken, getPayload, validateConfigData} = require('../../jwt-auth-helpers')

const jwt = require('jwt-simple')
const rp = require('request-promise-native')

async function getAccessToken() {
  const configStr = await Config.get('jwt-auth')
  if (!configStr) {
    return Promise.reject(new Error('missing config data: jwt-auth'))
  }

  // this is temporary, the way we used to import data resulted in stringified objects being stored
  // the better way is to store the actual object, but it requires changes elsewhere and
  // it should all be done at once.
  let configData = configStr
  if (typeof configStr === 'string') {
    configData = JSON.parse(configStr)
  }

  const validateConfigResults = validateConfigData(configData)
  if (validateConfigResults.length > 0) {
    return Promise.reject(new Error(`missing config data: ${validateConfigResults.join(', ')}`))
  }

  // the private key was saved line by line in an array
  const privateKey = configData.jwt_private_key.join('\n')

  // if we already have the token, validate it and return it
  const token = configData.access_token
  if (token) {
    if (validateToken(token, privateKey)) {
      return Promise.resolve(token)
    }
  }

  const payload = getPayload(configData) // re-set the expiry to 24 hours from now
  const jwtToken = jwt.encode(payload, privateKey, 'RS256', null)

  const options = {
    uri: configData.token_exchange_url,
    method: 'POST',
    form: {
      client_id: configData.client_id,
      client_secret: configData.client_secret,
      jwt_token: jwtToken,
    },
    json: true,
  }

  return rp(options)
  .then(async authTokenResult => {
    // store our new token in config
    configData.access_token = authTokenResult.access_token
    await Config.set('jwt-auth', JSON.stringify(configData))
    return authTokenResult.access_token
  })
}

class AccessTokenCommand extends Command {
  async run() {
    let token
    try {
      token = await this.accessToken()
    } catch (e) {
      this.error(e.message)
    }
    this.log(token)
    return token
  }

  async accessToken() {
    return getAccessToken()
  }
}

AccessTokenCommand.description = `get the access token for the Adobe I/O Console
You must have a 'jwt-auth' key in your config, that has all your config data in .json format:
    aio config:set jwt-auth path/to/your/config.json --file --mime-type=application/json
`

AccessTokenCommand.examples = [
  `
jwt_auth:
{
  "client_id": "...",
  "client_secret": "...",
  "token_exchange_url": "...",
  "jwt_payload": {
    "iss": "...",
    "sub": "...",
    "...": true,
    "aud": "..."
  },
  "jwt_private_key": [
    "-----BEGIN RSA PRIVATE KEY-----",
    "...",
    "...",
    "...==",
    "-----END RSA PRIVATE KEY-----"
  ],
  "console_get_orgs_url":"...",
  "console_get_namespaces_url":"..."
}
  `,
]

module.exports = AccessTokenCommand
