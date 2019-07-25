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

const { Command, flags } = require('@oclif/command')
const config = require('@adobe/aio-cna-core-config')
const { validateToken, createJwtAuthConfig, validateConfigData } = require('../../jwt-auth-helpers')
const { cli } = require('cli-ux')
const auth = require('@adobe/jwt-auth')
const debug = require('debug')('aio-cli-plugin-jwt-auth')
let crypto = require('crypto')

async function getToken (jwtConfig) {
  const body = await auth(jwtConfig)

  let expires = (new Date(Date.now() + body.expires_in)).toString()
  config.set('jwt-auth.access_token', body.access_token)
  config.set('jwt-auth.access_token_expiry', expires)

  // whenever we get a token, we store a checksum of the private key we used
  // to create it, so we can detect tokens invalidated by changing the private key.
  let genCheckSum = crypto.createHash('md5')
    .update(jwtConfig.privateKey)
    .digest('hex')
  config.set('jwt-auth.pk_checksum', genCheckSum)

  return { expires, token: body.access_token }
}

async function getAccessToken (passphrase = '', force, prompt) {
  const configData = config.get('jwt-auth')

  if (!configData) {
    return Promise.reject(new Error('missing config data: jwt-auth'))
  }

  const validateConfigResults = validateConfigData(configData)
  if (validateConfigResults.length > 0) {
    return Promise.reject(new Error(`missing config data: ${validateConfigResults.join(', ')}`))
  }

  let token = configData.access_token
  let expires = configData.access_token_expiry
  let jwtConfig = createJwtAuthConfig(configData, passphrase)

  if (!force && token) {
    // first verify that checksum matches the privateKey
    // if not we need to request a new token
    let lastchecksum = configData.pk_checksum
    let newchecksum = crypto.createHash('md5')
      .update(jwtConfig.privateKey)
      .digest('hex')

    if (validateToken(token)) {
      if (newchecksum === lastchecksum) {
        debug('checksum for private key matches')
        return Promise.resolve({ expires, token })
      } else {
        debug('checksum for private key mis-match')
      }
    } else {
      debug('token is expired')
    }
  }

  debug('getting a new token')

  try {
    return await getToken(jwtConfig)
  } catch (obj) {
    // three types of errors:
    // 1. Error object for incorrect passphrase
    // 2. JSON returned from the JWT exchange (for a non 200 status code response)
    // 3. Generic Error object

    if (obj.message === 'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt') {
      if (!prompt) {
        throw new Error('Passphrase is incorrect.')
      }
      try {
        jwtConfig.privateKey.passphrase = await cli.prompt('Private key passphrase', { type: 'hide' })
        return await getToken(jwtConfig)
      } catch (e) {
        throw new Error('Passphrase is incorrect.')
      }
    }

    throw obj
  }
}

class AccessTokenCommand extends Command {
  async run () {
    const { flags } = this.parse(AccessTokenCommand)
    let data
    try {
      data = await getAccessToken(flags.passphrase, flags.force, !flags['no-prompt'] || flags.passphrase)
    } catch (error) {
      debug(error)
      this.error(error)
    }
    if (flags.bare) {
      this.log(data.token)
    } else {
      let expiryRange = ((new Date(data.expires) - Date.now()) / 1000 / 60 / 60).toFixed(2)
      this.log(`Access Token: ${data.token}`)
      this.log(`Expiry: ${data.expires} (${expiryRange} hrs)`)
    }
    return data.token
  }

  async accessToken (passphrase, force, prompt = false) {
    return getAccessToken(passphrase, force, prompt)
      .then(data => data.token)
  }
}

AccessTokenCommand.flags = {
  passphrase: flags.string({ char: 'p', env: 'PASSPHRASE', description: 'the passphrase for the private-key' }),
  force: flags.boolean({ char: 'f', description: 'get a new access token' }),
  bare: flags.boolean({ char: 'b', description: 'print access token only' }),
  'no-prompt': flags.boolean({ description: 'do not prompt for passphrase' })
}

AccessTokenCommand.description = `get the access token for the Adobe I/O Console
You must have a 'jwt-auth' key in your config, that has all your config data in .json format:
    aio config set jwt-auth --json --file path/to/your/config.json
`

AccessTokenCommand.examples = [
  `
jwt_auth:
{
  "client_id": "...",
  "client_secret": "..."
  "jwt_payload": {
    "iss": "...",
    "sub": "...",
    "...": true,
    "aud": "..."
  },
  "jwt_private_key": "/path/to/cert"
}
  `
]

module.exports = AccessTokenCommand
