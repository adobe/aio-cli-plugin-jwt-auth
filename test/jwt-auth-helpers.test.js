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

const jwtAuthHelpers = require('../src/jwt-auth-helpers')
const tempConfigData = require('./fixtures/config/config-sample.json')

jest.mock('jsonwebtoken', () => {
  return {
    decode: jest.fn(token => {
      if (token === 'some_gibberish_token') {
        throw new Error('invalid token')
      } else if (token === 'some_expired_token') {
        return {
          payload: {
            created_at: String(Date.now() - 1000), // ms, in the past
            expires_in: String(1), // 1 ms from created_at
          },
        }
      } else {
        return {
          payload: {
            created_at: String(Date.now()), // ms
            expires_in: String(1000 * 60), // will not expire for the test (60s)
          },
        }
      }
    }),
  }
})

test('exports', () => {
  expect(typeof jwtAuthHelpers.validateToken).toEqual('function')
  expect(typeof jwtAuthHelpers.validateConfigData).toEqual('function')
  expect(typeof jwtAuthHelpers.getPayload).toEqual('function')
})

test('validateToken', () => {
  let isExpired

  isExpired = jwtAuthHelpers.validateToken('some_gibberish_token')
  expect(isExpired).toBeFalsy()

  isExpired = jwtAuthHelpers.validateToken('some_expired_token')
  expect(isExpired).toBeFalsy()

  isExpired = jwtAuthHelpers.validateToken('some_valid_token')
  expect(isExpired).toBeTruthy()
})

test('validateConfigData', () => {
  let configData
  let invalidKeys

  configData = Object.assign({}, tempConfigData)
  invalidKeys = jwtAuthHelpers.validateConfigData(configData)
  expect(invalidKeys.length).toEqual(0)

  delete configData.token_exchange_url
  invalidKeys = jwtAuthHelpers.validateConfigData(configData)
  expect(invalidKeys.length).toEqual(1)
  expect(invalidKeys[0]).toEqual('token_exchange_url')

  configData = null
  invalidKeys = jwtAuthHelpers.validateConfigData(configData)
  expect(invalidKeys).toBeFalsy()
})

test('getPayload', () => {
  let configData
  let payload

  configData = Object.assign({}, tempConfigData)
  payload = jwtAuthHelpers.getPayload(configData)
  expect(payload).toBeDefined()
  expect(payload.exp).toBeLessThanOrEqual(Math.round((Date.now() / 1000) + (60 * 60 * 12)))

  configData = {}
  payload = jwtAuthHelpers.getPayload(configData)
  expect(payload).toBeUndefined()
})
