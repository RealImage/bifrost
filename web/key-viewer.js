import { generateKey, bifrostId, createCsr } from "./bifrost";

export class KeyViewer extends HTMLElement {
  static observedAttributes = ["id", "certificate"];

  #privateKey;

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    generateKey().then((key) => {
      this.#privateKey = key;
      import("./namespace.js").then((ns) => {
        bifrostId(ns.default, key.publicKey).then((id) => {
          this.setAttribute("id", id);
        });
      });
    });
  }


  get certificate() {
    return this.getAttribute("certificate");
  }

  set certificate(value) {
    this.setAttribute("certificate", value);
  }

  async connectedCallback() {
    this.render();
    this.shadowRoot.addEventListener("click", async (event) => {
      if (event.target.id !== "request") {
        return;
      }

      const ns = await import("./namespace.js");
      const csr = await createCsr(ns.default, this.#privateKey);
      const response = await fetch("/issue", {
        method: "POST",
        headers: {
          "Content-Type": "text/plain",
        },
        body: csr,
      });
      this.certificate = await response.text();
    });
  }

  disconnectedCallback() {
    this.shadowRoot.getElementById("request").removeEventListener("click");
  }

  attributeChangedCallback(_, __, ___) {
    this.render();
  }

  render() {
    this.shadowRoot.innerHTML = `
      <link rel="stylesheet" href="/index.css">
      <div class="card">
        <header>
          <h4>Key</h4>
        </header>
        <p><strong>ID:</strong> ${this.id}</p>
        <button id="request" class="button primary">Request Certificate</button>
        ${this.certificate ? `
          <peculiar-certificate-viewer certificate="${this.certificate}">
          </peculiar-certificate-viewer>
        ` : ""}
      </div>
    `;
  }
}
