import { getNamespace, generateKey, bifrostId, createCsr, exportPublicKey, exportPrivateKey } from "./bifrost";

export class KeyViewer extends HTMLElement {
  static observedAttributes = ["ca-url"];

  /**
   * @returns {string}
   * @public
   */
  get caUrl() {
    return this.getAttribute("ca-url");
  }

  /**
   * @param {string} value
   * @public
   */
  set caUrl(value) {
    this.setAttribute("ca-url", value);
  }

  /**
   * @property {string} namespace
   * @private
   */
  #namespace;

  /**
   * @property {CryptoKey} privateKey
   * @private
   */
  #keyPair;

  /**
   * @property {string} id
   * @private
   */
  #id;

  /**
   * @typedef {Object} Certificate
   * @property {string} value
   * @property {string?} name
   * @property {Object} tests
   * @property {string?} tests.valid
   * @property {string?} tests.revoked
   * @property {string?} tests.expired
   *
   * @property {Certificate[]} #certificates
   */
  #certificates = [];

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
  }

  async refresh() {
    if (!this.#keyPair) {
      this.#keyPair = await generateKey();
    }

    if (this.caUrl) {
      this.#namespace = await getNamespace(this.caUrl);
      this.#id = await bifrostId(this.#namespace, this.#keyPair.publicKey);
    } else {
      this.#namespace = null;
      this.#id = null;
    }

    this.#certificates = [];

    await this.render();
  }

  async connectedCallback() {
    await this.refresh();

    this.shadowRoot.addEventListener("click", async (event) => {
      if (event.target.id !== "request") {
        return;
      }

      const csr = await createCsr(this.#namespace, this.#keyPair);
      const response = await fetch(this.caUrl + "/issue", {
        method: "POST",
        headers: {
          "Content-Type": "text/plain",
        },
        body: csr,
      });

      this.#certificates = [...this.#certificates, { value: await response.text() }];

      await this.render();
    });
  }

  disconnectedCallback() {
    this.shadowRoot.getElementById("request").removeEventListener("click");
  }

  async attributeChangedCallback(name, oldValue, newValue) {
    if (name === "ca-url" && oldValue !== newValue) {
      await this.refresh();
    }
  }

  async downloadKeyUrl(format) {
    const type = format === "pem" ? "application/x-pem-file" : "application/octet-stream";
    const blob = new Blob([await exportPrivateKey(this.#keyPair.privateKey, format)], {
      type: type,
    });
    return URL.createObjectURL(blob);
  }

  async render() {
    if (!this.#keyPair) {
      this.shadowRoot.innerHTML = "Loading...";
      return;
    }

    this.shadowRoot.innerHTML = `
      <link rel="stylesheet" href="/index.css">
      <div id="key-viewer" class="card">
        <header>
          <h4>Key ${await exportPublicKey(this.#keyPair.publicKey)} </h4>
          ${this.caUrl ? `
          <p><strong>ID</strong> ${this.#id}</p>
        </header>

        <footer class="is-right">
          <button id="request" class="button primary">Request Certificate</button>
          <a class="button outline primary"
            download="${this.#id}.pem"
            href="${await this.downloadKeyUrl("pem")}"
          >Download PEM</a>
          <a class="button outline dark"
            download="${this.#id}.der"
            href="${await this.downloadKeyUrl("der")}"
          >Download DER</a>
        </footer>
        ` : ""}
      </div>
    `;

    if (this.#certificates.length > 0) {
      const kv = this.shadowRoot.getElementById("key-viewer");

      const forgetCertsBtn = document.createElement("button");
      forgetCertsBtn.classList.add("button", "error");
      forgetCertsBtn.textContent = "Forget Certificates";
      forgetCertsBtn.addEventListener("click", async () => {
        this.#certificates = [];
        await this.render();
      });

      kv.appendChild(forgetCertsBtn);

      const certsContainer = document.createElement("div");
      certsContainer.classList.add("card");
      certsContainer.innerHTML = `
        <header>
          <h4>Certificates</h4>
        </header>
      `;
      const certsViewer = document.createElement("peculiar-certificates-viewer");
      certsViewer.certificates = this.#certificates;
      certsContainer.appendChild(certsViewer);
      kv.appendChild(certsContainer);
    }
  }
}
