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

const mockAccessToken = 'asdasdasd'
jest.mock('request-promise-native', () => {
  return function () {
    return Promise.resolve({access_token: mockAccessToken})
  }
})

const Config = require('@adobe/aio-cli-plugin-config')
const AccessTokenCommand = require('../../../src/commands/jwt-auth/access-token')
const mockConfigData = require('../../fixtures/config/config-sample.json')
const mockConfigDataWithPassphrase = require('../../fixtures/config/config-sample-passphrase.json')
const configDataPassphrase = 'password'
const jwt = require('jsonwebtoken')
const {stdout} = require('stdout-stderr')

beforeAll(() => stdout.start())
afterAll(() => stdout.stop())

/**
 * Test: when we have a valid cached access-token we should just use it.
 * Expects: returned token to match the fake one we are mocking
*/
test('valid cached token', async () => {
  let privateKey = mockConfigData.jwt_private_key.join('\n')
  let payload = mockConfigData.jwt_payload
  // always set to expire 24 hours in the future
  payload.created_at = Math.round(Date.now())
  payload.expires_in = 1000000 // hurry!

  const jwtToken = jwt.sign(payload, privateKey, {algorithm: 'RS256'}, null)

  let configSpy1 = jest.spyOn(Config, 'get')
  .mockImplementation(prop => {
    if (prop === 'jwt-auth') {
      let tempConfig = Object.assign({}, mockConfigData)
      tempConfig.access_token = jwtToken
      return JSON.stringify(tempConfig)
    }
  })

  // don't let config write our bunk data
  let configSpy2 = jest.spyOn(Config, 'set')
  .mockImplementation(() => {})

  let runResult = AccessTokenCommand.run([])
  expect.assertions(4)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(jwtToken)
    expect(configSpy1).toHaveBeenCalled()
    expect(configSpy2).not.toHaveBeenCalled()
  })
})

test('invalid cached token', async () => {
  let spy1 = jest.spyOn(Config, 'get')
  .mockImplementation(() => {
    let tempConfig = Object.assign({}, mockConfigData)
    tempConfig.access_token = 'not valid'
    return JSON.stringify(tempConfig)
  })

  // don't let config write our bunk data
  let spy2 = jest.spyOn(Config, 'set')
  .mockImplementation(() => {})

  let runResult = AccessTokenCommand.run([])
  expect.assertions(4)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(mockAccessToken)
    expect(spy1).toHaveBeenCalled()
    expect(spy2).toHaveBeenCalled()
  })
})

test('generated valid cached token', async () => {
  let privateKey = mockConfigData.jwt_private_key.join('\n')
  let payload = mockConfigData.jwt_payload
  // always set to expire 24 hours in the future
  payload.created_at = Math.round(Date.now())
  payload.expires_in = 1000000 // hurry!

  const jwtToken = jwt.sign(payload, privateKey, {algorithm: 'RS256'}, null)

  let fsSpy1 = jest.spyOn(Config, 'get')
  .mockImplementation(prop => {
    if (prop === 'jwt-auth') {
      let tempConfig = Object.assign({}, mockConfigData)
      tempConfig.access_token = jwtToken
      return JSON.stringify(tempConfig)
    }
  })

  // don't let config write our bunk data
  jest.spyOn(Config, 'set')

  let runResult = AccessTokenCommand.run([])
  expect.assertions(3)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(jwtToken)
    expect(fsSpy1).toHaveBeenCalled()
  })
})

test('config missing jwt-auth key', async () => {
  jest.spyOn(Config, 'get').mockImplementation(() => {
    return undefined
  })

  let runResult = AccessTokenCommand.run([])
  return expect(runResult).rejects.toEqual(new Error('missing config data: jwt-auth'))
})

test('config missing key in jwt-auth key', async () => {
  jest.spyOn(Config, 'get').mockImplementation(() => {
    return {
      'jwt-auth': {
      },
    }
  })

  let runResult = AccessTokenCommand.run([])
  return expect(runResult).rejects.toEqual(
    new Error('missing config data: jwt_private_key, jwt_payload, client_id, client_secret, token_exchange_url'))
})

test('config missing key in jwt-auth key', async () => {
  jest.spyOn(Config, 'get').mockImplementation(() => {
    return {
      'jwt-auth': {
      },
    }
  })

  let runResult = AccessTokenCommand.run([])
  return expect(runResult).rejects.toEqual(
    new Error('missing config data: jwt_private_key, jwt_payload, client_id, client_secret, token_exchange_url'))
})

test('no cached access_token', async () => {
  let spy1 = jest.spyOn(Config, 'get')
  .mockImplementation(() => {
    let tempConfig = Object.assign({}, mockConfigData)
    return JSON.stringify(tempConfig)
  })

  // don't let config write our bunk data
  let spy2 = jest.spyOn(Config, 'set')
  .mockImplementation(() => {})

  expect(spy1).toHaveBeenCalled()
  expect(spy2).toHaveBeenCalled()

  let runResult = AccessTokenCommand.run([])
  return expect(runResult).resolves.toEqual(mockAccessToken)
})

test('private-key has passphrase - passphrase not set', async () => {
  let spy1 = jest.spyOn(Config, 'get')
  .mockImplementation(() => {
    let tempConfig = Object.assign({}, mockConfigDataWithPassphrase)
    return JSON.stringify(tempConfig)
  })

  // don't let config write our bunk data
  let spy2 = jest.spyOn(Config, 'set')
  .mockImplementation(() => {})

  expect(spy1).toHaveBeenCalled()
  expect(spy2).toHaveBeenCalled()

  let runResult = AccessTokenCommand.run([])
  return expect(runResult).rejects.toEqual(new Error('A passphrase is needed for your private-key. Use the --passphrase flag to specify one.'))
})

test('private-key has passphrase - passphrase set', async () => {
  let spy1 = jest.spyOn(Config, 'get')
  .mockImplementation(() => {
    let tempConfig = Object.assign({}, mockConfigDataWithPassphrase)
    return JSON.stringify(tempConfig)
  })

  // don't let config write our bunk data
  let spy2 = jest.spyOn(Config, 'set')
  .mockImplementation(() => {})

  expect(spy1).toHaveBeenCalled()
  expect(spy2).toHaveBeenCalled()

  let runResult = AccessTokenCommand.run([`--passphrase=${configDataPassphrase}`])
  return expect(runResult).resolves.toEqual(mockAccessToken)
})
