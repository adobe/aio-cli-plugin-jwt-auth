
jest.mock('../../src/commands/jwt-auth/access-token', () => {
  return jest.fn().mockImplementation(() => {
    return { accessToken: () => Promise.resolve('1234') }
  })
})
const index = require('../../src')

describe('index', () => {
  afterAll(() => {
    jest.unMock('../src/commands/jwt-auth/access-token')
  })

  test('exports', () => {
    expect(typeof index.accessToken).toEqual('function')
  })

  test('return accessToken', () => {
    expect(index.accessToken()).resolves.toBe('1234')
  })
})
