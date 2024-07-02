import "@peculiar/certificates-viewer";
import { defineCustomElements } from "@peculiar/certificates-viewer/loader";

import { KeyViewer } from "./key-viewer";

defineCustomElements();
customElements.define("key-viewer", KeyViewer);

document.addEventListener("DOMContentLoaded", async () => {
  const ids = document.getElementById("identities");

  document.getElementById("generate-key").addEventListener("click", async () => {
    const viewer = document.createElement("key-viewer");
    viewer.setAttribute("class", "col");
    ids.appendChild(viewer);
  });

  document.getElementById("forget-keys").addEventListener("click", () => {
    ids.innerHTML = "";
  });
});
