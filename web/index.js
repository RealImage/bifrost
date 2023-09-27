/* 
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

import { Elm } from './src/Main.elm';
import { createCsr } from './src/csr';
import "@peculiar/certificates-viewer";

const app = Elm.Main.init();

app.ports.generate.subscribe(async (req) => {
  console.count('generate');
  let res;
  try {
    res = await createCsr(req);
  } catch (e) {
    console.error(e);
    res = { error: e.message };
  }
  app.ports.receive.send(res);
});