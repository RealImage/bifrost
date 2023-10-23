/* 
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

import "@peculiar/certificates-viewer";
import { defineCustomElements } from "@peculiar/certificates-viewer/loader";
import "htmx.org";

import { generateKey } from "./csr";
import "./css/main.css";

defineCustomElements();

document.getElementById("generate-key").addEventListener("click", async () => {
  let { keyPair, keyPem } = await generateKey();
  console.log(keyPem);
});
