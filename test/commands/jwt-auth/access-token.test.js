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

let mockResult = Promise.resolve({
  ok: true,
  json: () => Promise.resolve(
    { access_token: mockAccessToken, expires_in: Date.now() }
  ) })
jest.mock('node-fetch', () => jest.fn().mockImplementation(() => mockResult))

const { cli } = require('cli-ux')
jest.mock('cli-ux')
cli.prompt = jest.fn()

const fetch = require('node-fetch')
const fs = require('fs')
const config = require('@adobe/aio-lib-core-config')
const AccessTokenCommand = require('../../../src/commands/jwt-auth/access-token')
const mockConfigData = require('../../__fixtures__/config/config-sample.json')
const mockConfigDataWithPassphrase = require('../../__fixtures__/config/config-sample-passphrase.json')
const configDataPassphrase = 'password'
const jwt = require('jsonwebtoken')

const privateKey = mockConfigData.jwt_private_key.join('\n')
const payload = mockConfigData.jwt_payload
// always set to expire 24 hours in the future
payload.created_at = Math.round(Date.now())
payload.expires_in = 1000000 // hurry!

const jwtToken = jwt.sign(payload, privateKey, { algorithm: 'RS256' }, null)

/**
 * Test: when we have a valid cached access-token we should just use it.
 * Expects: returned token to match the fake one we are mocking
*/

test('valid cached token', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.access_token = jwtToken
    tempConfig.pk_checksum = '70cc9abdc947cbb3b86c771cdf082c83'
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])
  expect.assertions(4)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(jwtToken)
    expect(config.get).toHaveBeenCalled()
    expect(config.set).not.toHaveBeenCalled()
  })
})

test('valid cached token with bad checksum', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.access_token = jwtToken
    tempConfig.pk_checksum = 'asd'
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])
  expect.assertions(4)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(mockAccessToken)
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
  })
})

test('invalid cached token', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.access_token = 'not valid'
    tempConfig.pk_checksum = 'asd'
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])
  expect.assertions(4)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(mockAccessToken)
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
  })
})

test('use bare', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.access_token = mockAccessToken
    return tempConfig
  })

  const runResult = AccessTokenCommand.run(['-b'])
  expect.assertions(4)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(mockAccessToken)
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
  })
})

test('call function directly', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.access_token = mockAccessToken
    return tempConfig
  })

  const runResult = (new AccessTokenCommand()).accessToken()
  expect.assertions(2)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(mockAccessToken)
  })
})

test('uses key filepath', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.jwt_private_key = 'test/__fixtures__/fake_cert'
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(mockAccessToken)
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
  })
})

test('uses key raw test', async () => {
  config.get.mockImplementation(key => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.jwt_private_key = fs.readFileSync('./test/__fixtures__/fake_cert', 'utf-8')
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(mockAccessToken)
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
  })
})

test('uses key raw test - cert not found', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(key => {
      const tempConfig = Object.assign({}, mockConfigData)
      tempConfig.jwt_private_key = './test/__fixtures__/non_existent_cert'
      return tempConfig
    })

    const runResult = AccessTokenCommand.run([])

    expect(runResult instanceof Promise).toBeTruthy()
    return runResult
      .then(reject)
      .catch(res => {
        expect(res).toEqual(new Error('Cannot load private key: ./test/__fixtures__/non_existent_cert'))
        expect(config.get).toHaveBeenCalled()
        resolve()
      })
  })
})

test('general @adobe/jwt-auth error', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(() => {
      const tempConfig = Object.assign({}, mockConfigData)
      tempConfig.jwt_private_key = tempConfig.jwt_private_key + 'gibberish'
      return tempConfig
    })

    const runResult = AccessTokenCommand.run([])
    expect(runResult instanceof Promise).toBeTruthy()
    return runResult.then(reject).catch(err => {
      expect(err).toBeDefined()
      resolve()
    })
  })
})

test('uses key filepath but no file', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(() => {
      const tempConfig = Object.assign({}, mockConfigData)
      tempConfig.jwt_private_key = '/doesntexist'
      return tempConfig
    })

    const runResult = AccessTokenCommand.run([])
    expect(runResult instanceof Promise).toBeTruthy()
    return runResult.then(reject).catch(err => {
      expect(err).toEqual(new Error('Cannot load private key: /doesntexist'))
      resolve()
    })
  })
})

test('generated valid cached token', async () => {
  const privateKey = mockConfigData.jwt_private_key.join('\n')
  const payload = mockConfigData.jwt_payload
  // always set to expire 24 hours in the future
  payload.created_at = Math.round(Date.now())
  payload.expires_in = 1000000 // hurry!

  const jwtToken = jwt.sign(payload, privateKey, { algorithm: 'RS256' }, null)

  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    tempConfig.access_token = jwtToken
    tempConfig.pk_checksum = '70cc9abdc947cbb3b86c771cdf082c83'
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])
  expect.assertions(3)

  expect(runResult instanceof Promise).toBeTruthy()
  return runResult.then(res => {
    expect(res).toEqual(jwtToken)
    expect(config.get).toHaveBeenCalled()
  })
})

test('config missing jwt-auth key', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(() => {
      return undefined
    })

    const runResult = AccessTokenCommand.run([])
    return runResult.then(reject).catch(err => {
      expect(err).toEqual(new Error('missing config data: jwt-auth'))
      resolve()
    })
  })
})

test('config missing key in jwt-auth key', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(() => {
      return { 'jwt-auth': {} }
    })

    const runResult = AccessTokenCommand.run([])
    return runResult.then(reject).catch(err => {
      expect(config.get).toHaveBeenCalled()
      expect(err).toEqual(new Error('missing config data: jwt_private_key, jwt_payload, client_id, client_secret'))
      resolve()
    })
  })
})

test('no cached access_token', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])
  return runResult.then(data => {
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
    expect(data).toEqual(mockAccessToken)
  })
})

test('should default to https://ims-na1.adobelogin.com/ims/exchange/jwt/', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigData)
    delete tempConfig.token_exchange_url
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([])
  return runResult.then(data => {
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
    expect(fetch).toHaveBeenLastCalledWith('https://ims-na1.adobelogin.com/ims/exchange/jwt/', expect.any(Object))
    expect(data).toEqual(mockAccessToken)
  })
})

test('private-key has passphrase - passphrase not set, should prompt', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(() => {
      const tempConfig = Object.assign({}, mockConfigDataWithPassphrase)
      return tempConfig
    })

    const runResult = AccessTokenCommand.run([])
    return runResult
      .then(reject)
      .catch(data => {
        expect(config.get).toHaveBeenCalled()
        expect(cli.prompt).toHaveBeenCalled()
        resolve()
      })
  })
})

test('private-key has passphrase - passphrase set, shouldnt prompt if --no-prompt', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(() => {
      const tempConfig = Object.assign({}, mockConfigDataWithPassphrase)
      return tempConfig
    })

    const runResult = AccessTokenCommand.run([`--no-prompt`])
    return runResult
      .then(reject)
      .catch(data => {
        expect(config.get).toHaveBeenCalled()
        expect(cli.prompt).not.toHaveBeenCalled()
        resolve()
      })
  })
})

test('private-key has passphrase - passphrase set', async () => {
  config.get.mockImplementation(() => {
    const tempConfig = Object.assign({}, mockConfigDataWithPassphrase)
    return tempConfig
  })

  const runResult = AccessTokenCommand.run([`--passphrase=${configDataPassphrase}`])
  return runResult.then(data => {
    expect(config.get).toHaveBeenCalled()
    expect(config.set).toHaveBeenCalled()
    expect(data).toEqual(mockAccessToken)
  })
})

test('fetch failure', async () => {
  await new Promise((resolve, reject) => {
    config.get.mockImplementation(() => {
      const tempConfig = Object.assign({}, mockConfigDataWithPassphrase)
      return tempConfig
    })

    const obj = {
      ok: false,
      status: 404,
      statusText: 'Not Found'
    }

    const response = {
      ...obj,
      json: () => obj
    }
    mockResult = resolve(response)

    const runResult = AccessTokenCommand.run([`--passphrase=${configDataPassphrase}`])
    return runResult.then(reject).catch(err => {
      expect(err.message).toEqual(`An unknown error occurred while swapping jwt. The response is as follows: ${JSON.stringify(obj)}`)
      resolve()
    })
  })
})
