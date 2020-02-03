/*
Copyright 2019 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
*/

const execa = require('execa')
const chalk = require('chalk')
const { stdout } = require('stdout-stderr')

stdout.print = true 

test('sdk init test', async () => {

  const name = 'aio-cli-plugin-jwt-auth'
  console.log(chalk.blue(`> e2e tests for ${chalk.bold(name)}`))

  console.log(chalk.dim(`    - create jwt-auth config...`))
  const homedir = require('os').homedir()
  execa.sync('node', [homedir+'/.npm-global/bin/aio', 'config', 'set', 'jwt-auth', '--json', '--file', 'e2e/jwt_auth_config.json'], { stderr: 'inherit' })

  console.log(chalk.dim(`    - Generate jwt-auth access token..`))
  execa.sync('./bin/run', ['jwt-auth:access-token'], { stderr: 'inherit' })

  console.log(chalk.green(`    - done for ${chalk.bold(name)}`))
});
4084663469