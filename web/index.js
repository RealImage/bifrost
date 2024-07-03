import "@peculiar/certificates-viewer";
import { defineCustomElements } from "@peculiar/certificates-viewer/loader";

import { KeyViewer } from "./key-viewer";
import { getNamespace } from "./bifrost";

defineCustomElements();
customElements.define("key-viewer", KeyViewer);

document.addEventListener("DOMContentLoaded", async () => {
  const caUrl = "http://localhost:8008";

  const namespace = await getNamespace(caUrl);
  document.getElementById("namespace").textContent = namespace;

  const ids = document.getElementById("identities");

  document.getElementById("generate-key").addEventListener("click", async () => {
    const viewer = document.createElement("key-viewer");
    viewer.caUrl = caUrl;
    ids.appendChild(viewer);
  });

  document.getElementById("forget-keys").addEventListener("click", () => {
    ids.innerHTML = "";
  });
});
