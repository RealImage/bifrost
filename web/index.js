/* 
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

import { createCsr } from './src/csr';
import "@peculiar/certificates-viewer";
import { defineCustomElements } from '@peculiar/certificates-viewer/loader';
import './css/main.css';
import 'htmx.org';

defineCustomElements();