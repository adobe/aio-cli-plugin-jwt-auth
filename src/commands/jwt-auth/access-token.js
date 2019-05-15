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
const config = require('@adobe/aio-cli-config')
const { validateToken, getPayload, validateConfigData } = require('../../jwt-auth-helpers')
const debug = require('debug')('aio-cli-plugin-jwt-auth')
const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')
const { cli } = require('cli-ux')
const fs = require('fs')
const { URLSearchParams } = require('url')

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

  if (!force && token) {
    if (validateToken(token)) {
      return Promise.resolve({ expires, token })
    }
  }

  let privateKey = configData.jwt_private_key
  if (privateKey.constructor === Array) {
    privateKey = configData.jwt_private_key.join('\n')
  } else if (typeof privateKey === 'string' && !privateKey.match(/^----/)) {
    try {
      privateKey = fs.readFileSync(configData.jwt_private_key, 'utf-8')
    } catch (e) {
      debug(e)
      throw new Error(`Cannot load private key: ${configData.jwt_private_key}`)
    }
  }

  let keyParam = {
    key: privateKey,
    passphrase
  }

  const payload = getPayload(configData) // re-set the expiry to 24 hours from now

  let jwtToken
  try {
    jwtToken = getToken(payload, keyParam)
  } catch (e) {
    if (!prompt) {
      throw new Error('Passphrase is incorrect.')
    }
    keyParam.passphrase = await cli.prompt('Private key passphrase', { type: 'hide' })
    try {
      jwtToken = getToken(payload, keyParam)
    } catch (e) {
      throw new Error('Passphrase is incorrect.')
    }
  }

  const uri = configData.token_exchange_url || 'https://ims-na1.adobelogin.com/ims/exchange/jwt/'
  const body = new URLSearchParams()
  body.append('client_id', configData.client_id)
  body.append('client_secret', configData.client_secret)
  body.append('jwt_token', jwtToken)

  debug(`fetch: ${uri}`)
  return fetch(uri, { method: 'POST', body })
    .then(async res => {
      if (res.ok) return res.json()
      else throw new Error(`Cannot get token from ${uri} (${res.status} ${res.statusText})`)
    })
    .then(body => {
      let expires = (new Date(Date.now() + body.expires_in)).toString()
      config.set('jwt-auth.access_token', body.access_token)
      config.set('jwt-auth.access_token_expiry', expires)
      return { expires, token: body.access_token }
    })
}

const getToken = (payload, keyParam) => {
  try {
    return jwt.sign(payload, keyParam, { algorithm: 'RS256' }, null)
  } catch (error) {
    debug(error)
    throw error
  }
}

class AccessTokenCommand extends Command {
  async run () {
    const { flags } = this.parse(AccessTokenCommand)
    let data
    try {
      data = await getAccessToken(flags.passphrase, flags.force, !flags['no-prompt'] || flags.passphrase)
    } catch (error) {
      this.error(error.message)
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
  'no-prompt': flags.boolean({ description: 'do not promp for passphrase' })
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
