<!--
Copyright 2018 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
-->

[![oclif](https://img.shields.io/badge/cli-oclif-brightgreen.svg)](https://oclif.io)
[![Version](https://img.shields.io/npm/v/@adobe/aio-cli-plugin-jwt-auth.svg)](https://npmjs.org/package/@adobe/aio-cli-plugin-jwt-auth)
[![Downloads/week](https://img.shields.io/npm/dw/@adobe/aio-cli-plugin-jwt-auth.svg)](https://npmjs.org/package/@adobe/aio-cli-plugin-jwt-auth)
[![Build Status](https://travis-ci.com/adobe/aio-cli-plugin-jwt-auth.svg?branch=master)](https://travis-ci.com/adobe/aio-cli-plugin-jwt-auth) 
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Greenkeeper badge](https://badges.greenkeeper.io/adobe/aio-cli-plugin-jwt-auth.svg)](https://greenkeeper.io/)
[![Codecov Coverage](https://img.shields.io/codecov/c/github/adobe/aio-cli-plugin-jwt-auth/master.svg?style=flat-square)](https://codecov.io/gh/adobe/aio-cli-plugin-jwt-auth/)

aio-cli-plugin-jwt-auth
=======================

JWT Auth Plugin for the Adobe I/O CLI

<!-- toc -->
* [Usage](#usage)
* [Commands](#commands)
<!-- tocstop -->
# Usage
<!-- usage -->
```sh-session
$ npm install -g @adobe/aio-cli-plugin-jwt-auth
$ ./bin/run COMMAND
running command...
$ ./bin/run (-v|--version|version)
@adobe/aio-cli-plugin-jwt-auth/2.0.4 darwin-x64 node-v10.18.1
$ ./bin/run --help [COMMAND]
USAGE
  $ ./bin/run COMMAND
...
```
<!-- usagestop -->
# Commands
<!-- commands -->
* [`./bin/run jwt-auth:access-token`](#binrun-jwt-authaccess-token)

## `./bin/run jwt-auth:access-token`

get the access token for the Adobe I/O Console

```
USAGE
  $ ./bin/run jwt-auth:access-token

OPTIONS
  -b, --bare                   print access token only
  -f, --force                  get a new access token
  -p, --passphrase=passphrase  the passphrase for the private-key
  --no-prompt                  do not prompt for passphrase

DESCRIPTION
  You must have a 'jwt-auth' key in your config, that has all your config data in .json format:
       aio config set jwt-auth --json --file path/to/your/config.json

EXAMPLE

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
```

_See code: [src/commands/jwt-auth/access-token.js](https://github.com/adobe/aio-cli-plugin-jwt-auth/blob/2.0.4/src/commands/jwt-auth/access-token.js)_
<!-- commandsstop -->
