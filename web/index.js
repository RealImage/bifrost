import "@peculiar/certificates-viewer";
import { defineCustomElements } from "@peculiar/certificates-viewer/loader";

import { KeyViewer } from "./key-viewer";
import { getNamespace } from "./bifrost";
import { Elm } from "./src/Main.elm";

defineCustomElements();
customElements.define("key-viewer", KeyViewer);

const app = Elm.Main.init();
