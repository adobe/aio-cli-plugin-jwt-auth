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

function getPayload(configData) {
  const payload = configData.jwt_payload
  if (payload) {
    // always set to expire 24 hours in the future
    payload.exp = Math.round((Date.now() / 1000) + (60 * 60 * 12))
  }
  return payload
}

function validateToken(token) {
  let isExpired = true

  try {
    const decodedJWT = jwt.decode(token, {complete: true}).payload
    const createdAt = parseInt(decodedJWT.created_at, 10)
    const expiresIn = parseInt(decodedJWT.expires_in, 10)
    const expiresAt = createdAt + expiresIn
    isExpired = expiresAt < (Date.now() / 1000)
  } catch (e) {
    isExpired = true
  }
  return !isExpired
}

function validateConfigData(configData) {
  if (!configData) {
    return null
  }

  const result = []
  const keys = ['jwt_private_key', 'jwt_payload', 'client_id', 'client_secret', 'token_exchange_url']

  keys.forEach(key => {
    if (!configData[key]) {
      result.push(key)
    }
  })

  return result
}

module.exports = {
  validateToken,
  getPayload,
  validateConfigData,
}
