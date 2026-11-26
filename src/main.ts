import "./styles/theme.css";
import { vaultClient, type VaultEntry } from "./vaultClient";

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing UI element: ${id}`);
  return element as T;
};

const lockScreen = byId<HTMLElement>("lock-screen");
const vaultScreen = byId<HTMLElement>("vault-screen");
const lockMessage = byId<HTMLElement>("lock-message");
const vaultMessage = byId<HTMLElement>("vault-message");
const list = byId<HTMLUListElement>("entry-list");
const search = byId<HTMLInputElement>("search-input");
const frame = byId<HTMLIFrameElement>("preview-frame");
const previewTitle = byId<HTMLElement>("preview-title");
const deleteButton = byId<HTMLButtonElement>("delete-button");
let entries: VaultEntry[] = [];
let selectedName = "";

function showVault(nextEntries: VaultEntry[]): void {
  entries = nextEntries;
  selectedName = "";
  previewTitle.textContent = "Choose a file";
  frame.srcdoc = "";
  deleteButton.classList.add("hidden");
  lockScreen.classList.add("hidden");
  vaultScreen.classList.remove("hidden");
  vaultMessage.textContent = "";
  renderEntries();
}

function showLock(): void {
  vaultScreen.classList.add("hidden");
  lockScreen.classList.remove("hidden");
  previewTitle.textContent = "Choose a file";
  frame.srcdoc = "";
  selectedName = "";
  deleteButton.classList.add("hidden");
}

function renderEntries(): void {
  list.replaceChildren();
  const query = search.value.trim().toLowerCase();
  type Folder = { files: VaultEntry[]; children: Map<string, Folder> };
  const root: Folder = { files: [], children: new Map() };
  for (const entry of entries.filter((item) => item.name.toLowerCase().includes(query))) {
    const parts = entry.name.split("/");
    let folder = root;
    for (const part of parts.slice(0, -1)) {
      if (!folder.children.has(part)) {
        folder.children.set(part, { files: [], children: new Map() });
      }
      folder = folder.children.get(part)!;
    }
    folder.files.push(entry);
  }

  const appendFolder = (target: HTMLUListElement, folder: Folder): void => {
    for (const [name, child] of folder.children) {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.className = "folder-label";
      label.textContent = name;
      item.append(label);
      const nested = document.createElement("ul");
      nested.className = "folder-list";
      appendFolder(nested, child);
      item.append(nested);
      target.append(item);
    }
    for (const entry of folder.files) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.className = "entry-button";
      button.type = "button";
      button.textContent = entry.name.split("/").at(-1) ?? entry.name;
      button.title = entry.name;
      button.addEventListener("click", () => void preview(entry.name));
      item.append(button);
      target.append(item);
    }
  };
  appendFolder(list, root);
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (character) => {
    const replacements: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return replacements[character] ?? character;
  });
}

function renderMarkdown(markdown: string): string {
  return markdown
    .split(/\r?\n/)
    .map((line) => {
      const heading = /^(#{1,6})\s+(.+)$/.exec(line);
      if (heading) {
        const level = heading[1]?.length ?? 1;
        return `<h${level}>${escapeHtml(heading[2] ?? "")}</h${level}>`;
      }
      if (!line.trim()) return "";
      const escaped = escapeHtml(line)
        .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
        .replace(/`([^`]+)`/g, "<code>$1</code>");
      return `<p>${escaped}</p>`;
    })
    .join("\n");
}

function previewDocument(content: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'"><style>body{font:16px/1.6 system-ui,sans-serif;color:#e8eaf0;background:#171a21;padding:1.5rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{color:#b4a1ff}a{color:#a7b5ff}</style></head><body>${content}</body></html>`;
}

async function preview(name: string): Promise<void> {
  try {
    const content = await vaultClient.read(name);
    const extension = name.split(".").pop()?.toLowerCase();
    const rendered =
      extension === "html" || extension === "htm"
        ? content
        : extension === "md" || extension === "markdown"
          ? renderMarkdown(content)
          : `<pre>${escapeHtml(content)}</pre>`;
    selectedName = name;
    previewTitle.textContent = name;
    frame.srcdoc = previewDocument(rendered);
    deleteButton.classList.remove("hidden");
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not read the file.";
  }
}

byId<HTMLFormElement>("open-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  lockMessage.textContent = "";
  try {
    const result = await vaultClient.open(
      byId<HTMLInputElement>("vault-path").value,
      byId<HTMLInputElement>("open-password").value,
    );
    byId<HTMLInputElement>("open-password").value = "";
    showVault(result);
  } catch (error) {
    lockMessage.textContent = error instanceof Error ? error.message : "Could not open the vault.";
  }
});

byId<HTMLFormElement>("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  lockMessage.textContent = "";
  try {
    const burnPassword = byId<HTMLInputElement>("burn-password").value || null;
    const result = await vaultClient.create(
      byId<HTMLInputElement>("vault-path").value,
      byId<HTMLInputElement>("create-password").value,
      burnPassword,
      byId<HTMLSelectElement>("disguise-mode").value,
    );
    byId<HTMLInputElement>("create-password").value = "";
    byId<HTMLInputElement>("burn-password").value = "";
    showVault(result);
  } catch (error) {
    lockMessage.textContent = error instanceof Error ? error.message : "Could not create the vault.";
  }
});

byId<HTMLFormElement>("add-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    entries = await vaultClient.add(
      byId<HTMLInputElement>("entry-name").value,
      byId<HTMLTextAreaElement>("entry-content").value,
    );
    byId<HTMLInputElement>("entry-name").value = "";
    byId<HTMLTextAreaElement>("entry-content").value = "";
    renderEntries();
    vaultMessage.textContent = "File added.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not add the file.";
  }
});

search.addEventListener("input", renderEntries);

deleteButton.addEventListener("click", async () => {
  if (!selectedName) return;
  try {
    entries = await vaultClient.remove(selectedName);
    selectedName = "";
    previewTitle.textContent = "Choose a file";
    frame.srcdoc = "";
    deleteButton.classList.add("hidden");
    renderEntries();
    vaultMessage.textContent = "File deleted.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not delete the file.";
  }
});

byId<HTMLButtonElement>("compact-button").addEventListener("click", async () => {
  try {
    await vaultClient.compact();
    vaultMessage.textContent = "Vault compacted.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not compact the vault.";
  }
});

byId<HTMLButtonElement>("lock-button").addEventListener("click", async () => {
  await vaultClient.lock();
  showLock();
});
