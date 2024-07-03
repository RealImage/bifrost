import "@peculiar/certificates-viewer";
import { defineCustomElements } from "@peculiar/certificates-viewer/loader";

import { KeyViewer } from "./key-viewer";
import { getNamespace } from "./bifrost";

defineCustomElements();
customElements.define("key-viewer", KeyViewer);

document.addEventListener("DOMContentLoaded", async () => {
  const namespace = await getNamespace();
  document.getElementById("namespace").textContent = namespace;

  const ids = document.getElementById("identities");

  document.getElementById("generate-key").addEventListener("click", async () => {
    const viewer = document.createElement("key-viewer");
    viewer.namespace = namespace;
    ids.appendChild(viewer);
  });

  document.getElementById("forget-keys").addEventListener("click", () => {
    ids.innerHTML = "";
  });
});
