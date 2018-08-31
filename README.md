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
[![Build Status](https://travis-ci.org/adobe/aio-cli-plugin-jwt-auth.svg?branch=master)](https://travis-ci.org/adobe/aio-cli-plugin-jwt-auth)
[![Build status](https://ci.appveyor.com/api/projects/status/d6m0d43csd8t13vu?svg=true)](https://ci.appveyor.com/project/shazron/aio-cli-plugin-jwt-auth)

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
@adobe/aio-cli-plugin-jwt-auth/1.0.6 darwin-x64 node-v8.11.4
$ ./bin/run --help [COMMAND]
USAGE
  $ ./bin/run COMMAND
...
```
<!-- usagestop -->
# Commands
<!-- commands -->
* [`./bin/run jwt-auth:access-token`](#bin-run-jwt-authaccess-token)

## `./bin/run jwt-auth:access-token`

get the access token for the Adobe I/O Console

```
USAGE
  $ ./bin/run jwt-auth:access-token

DESCRIPTION
  You must have a 'jwt-auth' key in your config, that has all your config data in .json format:
       aio config:set jwt-auth path/to/your/config.json --file --mime-type=application/json

EXAMPLE

  jwt_auth:
  {
     "client_id": "...",
     "client_secret": "...",
     "token_exchange_url": "...",
     "jwt_payload": {
       "iss": "...",
       "sub": "...",
       "...": true,
       "aud": "..."
     },
     "jwt_private_key": [
       "-----BEGIN RSA PRIVATE KEY-----",
       "...",
       "...",
       "...==",
       "-----END RSA PRIVATE KEY-----"
     ],
     "console_get_orgs_url":"...",
     "console_get_namespaces_url":"..."
  }
```

_See code: [src/commands/jwt-auth/access-token.js](https://github.com/adobe/aio-cli-plugin-jwt-auth/blob/v1.0.6/src/commands/jwt-auth/access-token.js)_
<!-- commandsstop -->
