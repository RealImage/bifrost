/* 
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

import { Elm } from './src/Main.elm';
import { createKeyAndCSR } from './src/crypto';

const app = Elm.Main.init();

app.ports.generate.subscribe(async (req) => {
  let res
  try {
    res = await createKeyAndCSR(req);
  } catch ({ message }) {
    res = { error: message };
  }
  app.ports.receive.send(res);
});