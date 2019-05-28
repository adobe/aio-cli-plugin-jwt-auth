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

const jwt = require('jsonwebtoken')
const debug = require('debug')('aio-cli-plugin-jwt-auth')
const fs = require('fs')
const { URL } = require('url')

const defaultTokenExchangeUrl = 'https://ims-na1.adobelogin.com/ims/exchange/jwt/'

function createJwtAuthConfig (configData, passphrase) {
  const payload = configData.jwt_payload
  if (!payload) {
    return
  }

  let config = {
    orgId: payload.iss,
    technicalAccountId: payload.sub,
    clientId: configData.client_id,
    clientSecret: configData.client_secret
  }

  const tokenUrl = new URL(configData.token_exchange_url || defaultTokenExchangeUrl)
  config.ims = `${tokenUrl.protocol}//${tokenUrl.host}`

  // add metascopes
  config.metaScopes = Object.keys(payload).filter(key => key.startsWith('http') && payload[key] === true)

  // add private key
  config.privateKey = configData.jwt_private_key
  if (config.privateKey.constructor === Array) {
    config.privateKey = {
      key: configData.jwt_private_key.join('\n'),
      passphrase
    }
  } else if (typeof config.privateKey === 'string' && !config.privateKey.match(/^----/)) {
    try {
      config.privateKey = {
        key: fs.readFileSync(configData.jwt_private_key, 'utf-8'),
        passphrase
      }
    } catch (e) {
      debug(e)
      throw new Error(`Cannot load private key: ${configData.jwt_private_key}`)
    }
  }

  debug('JWT Config:', config)
  return config
}

function validateToken (token) {
  let isExpired = true

  try {
    const decodedJWT = jwt.decode(token, { complete: true }).payload
    const createdAt = parseInt(decodedJWT.created_at, 10) // ms
    const expiresIn = parseInt(decodedJWT.expires_in, 10) // ms
    const expiresAt = createdAt + expiresIn
    isExpired = expiresAt < Date.now()
  } catch (error) {
    isExpired = true
  }
  return !isExpired
}

function validateConfigData (configData) {
  if (!configData) {
    return null
  }

  const result = []
  const keys = ['jwt_private_key', 'jwt_payload', 'client_id', 'client_secret']

  keys.forEach(key => {
    if (!configData[key]) {
      result.push(key)
    }
  })

  return result
}

module.exports = {
  validateToken,
  createJwtAuthConfig,
  validateConfigData
}
