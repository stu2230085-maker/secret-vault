import "./styles/theme.css";
import { vaultClient, type VaultEntry } from "./vaultClient";

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing UI element: ${id}`);
  return element as T;
};

const lockScreen = byId<HTMLElement>("lock-screen");
const vaultScreen = byId<HTMLElement>("vault-screen");
const envBadge = byId<HTMLElement>("env-badge");
const lockMessage = byId<HTMLElement>("lock-message");
const vaultMessage = byId<HTMLElement>("vault-message");
const vaultStatsPill = byId<HTMLElement>("vault-stats-pill");
const autolockPill = byId<HTMLElement>("autolock-pill");
const sidebar = byId<HTMLElement>("sidebar");
const list = byId<HTMLUListElement>("entry-list");
const search = byId<HTMLInputElement>("search-input");
const frame = byId<HTMLIFrameElement>("preview-frame");
const editorTextarea = byId<HTMLTextAreaElement>("editor-textarea");
const previewTitle = byId<HTMLElement>("preview-title");
const editButton = byId<HTMLButtonElement>("edit-button");
const saveEditButton = byId<HTMLButtonElement>("save-edit-button");
const cancelEditButton = byId<HTMLButtonElement>("cancel-edit-button");
const renameButton = byId<HTMLButtonElement>("rename-button");
const copyButton = byId<HTMLButtonElement>("copy-button");
const exportButton = byId<HTMLButtonElement>("export-button");
const deleteButton = byId<HTMLButtonElement>("delete-button");
const importInput = byId<HTMLInputElement>("import-input");
const settingsDialog = byId<HTMLDialogElement>("settings-dialog");
const settingsMessage = byId<HTMLElement>("settings-message");
const statEntries = byId<HTMLElement>("stat-entries");
const statSize = byId<HTMLElement>("stat-size");
const statReclaimable = byId<HTMLElement>("stat-reclaimable");
const autolockSelect = byId<HTMLSelectElement>("autolock-select");
const themeSelect = byId<HTMLSelectElement>("theme-select");

const textDecoder = new TextDecoder("utf-8", { fatal: true });

let entries: VaultEntry[] = [];
let selectedName = "";
let selectedText: string | null = null;
let selectedBytes: Uint8Array | null = null;
let isEditing = false;
let autoLockSeconds = 300;
let autoLockTimer: number | undefined;
let clipboardClearTimer: number | undefined;

if (!vaultClient.isTauriEnvironment()) {
  envBadge.classList.remove("hidden");
  envBadge.title = "Browser preview mode: password 'test' opens demo vault, 'burn' triggers self-destruct";
}

function applyTheme(theme: string): void {
  if (theme === "dark") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", theme);
  }
  themeSelect.value = theme;
}

const savedTheme = localStorage.getItem("secret-vault-theme");
if (savedTheme === "midnight" || savedTheme === "light" || savedTheme === "dark") {
  applyTheme(savedTheme);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function updateAutoLockLabel(): void {
  if (autoLockSeconds === 0) {
    autolockPill.textContent = "Auto-lock: Off";
  } else if (autoLockSeconds < 60) {
    autolockPill.textContent = `Auto-lock: ${autoLockSeconds}s`;
  } else {
    autolockPill.textContent = `Auto-lock: ${Math.round(autoLockSeconds / 60)}m`;
  }
}

function resetAutoLockTimer(): void {
  if (autoLockTimer !== undefined) {
    window.clearTimeout(autoLockTimer);
    autoLockTimer = undefined;
  }
  if (autoLockSeconds <= 0 || vaultScreen.classList.contains("hidden")) {
    return;
  }
  autoLockTimer = window.setTimeout(() => {
    void lockNow("Vault auto-locked due to inactivity.");
  }, autoLockSeconds * 1000);
}

async function lockNow(reason?: string): Promise<void> {
  if (autoLockTimer !== undefined) {
    window.clearTimeout(autoLockTimer);
    autoLockTimer = undefined;
  }
  await vaultClient.lock();
  showLock(reason);
}

for (const eventName of ["pointerdown", "keydown", "input"] as const) {
  document.addEventListener(eventName, resetAutoLockTimer, { passive: true });
}

function clearSelection(): void {
  selectedName = "";
  selectedText = null;
  selectedBytes = null;
  isEditing = false;
  previewTitle.textContent = "Choose a file";
  frame.srcdoc = "";
  frame.classList.remove("hidden");
  editorTextarea.value = "";
  editorTextarea.classList.add("hidden");
  editButton.classList.add("hidden");
  saveEditButton.classList.add("hidden");
  cancelEditButton.classList.add("hidden");
  renameButton.classList.add("hidden");
  copyButton.classList.add("hidden");
  exportButton.classList.add("hidden");
  deleteButton.classList.add("hidden");
}

async function refreshStatsPill(): Promise<void> {
  try {
    const stats = await vaultClient.stats();
    if (stats.decoy) {
      vaultStatsPill.textContent = "0 files";
      return;
    }
    const reclaimNote =
      stats.reclaimable_bytes > 0 ? ` · ${formatBytes(stats.reclaimable_bytes)} reclaimable` : "";
    vaultStatsPill.textContent = `${stats.entry_count} files (${formatBytes(stats.file_size)}${reclaimNote})`;
    statEntries.textContent = String(stats.entry_count);
    statSize.textContent = formatBytes(stats.file_size);
    statReclaimable.textContent = formatBytes(stats.reclaimable_bytes);
  } catch {
    vaultStatsPill.textContent = `${entries.length} files`;
  }
}

function showVault(nextEntries: VaultEntry[]): void {
  entries = nextEntries;
  clearSelection();
  lockScreen.classList.add("hidden");
  vaultScreen.classList.remove("hidden");
  vaultMessage.textContent = "";
  updateAutoLockLabel();
  resetAutoLockTimer();
  renderEntries();
  void refreshStatsPill();
}

function showLock(message?: string): void {
  if (settingsDialog.open) settingsDialog.close();
  entries = [];
  clearSelection();
  vaultScreen.classList.add("hidden");
  lockScreen.classList.remove("hidden");
  lockMessage.textContent = message ?? "";
}

function renderEntries(): void {
  list.replaceChildren();
  const query = search.value.trim().toLowerCase();
  type Folder = { files: VaultEntry[]; children: Map<string, Folder> };
  const root: Folder = { files: [], children: new Map() };
  const filtered = entries
    .filter((item) => item.name.toLowerCase().includes(query))
    .sort((a, b) => a.name.localeCompare(b.name));

  for (const entry of filtered) {
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
      const details = document.createElement("details");
      details.className = "folder-details";
      details.open = true;
      const summary = document.createElement("summary");
      summary.textContent = name;
      const nested = document.createElement("ul");
      nested.className = "folder-list";
      appendFolder(nested, child);
      details.append(summary, nested);
      item.append(details);
      target.append(item);
    }
    for (const entry of folder.files) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.className = "entry-button";
      if (entry.name === selectedName) button.classList.add("active");
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

function formatInlineMarkdown(escapedLine: string): string {
  return escapedLine
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
}

function renderMarkdown(markdown: string): string {
  const lines = markdown.split(/\r?\n/);
  const output: string[] = [];
  let inCodeBlock = false;

  for (const line of lines) {
    if (line.trimStart().startsWith("```")) {
      if (inCodeBlock) {
        output.push("</code></pre>");
        inCodeBlock = false;
      } else {
        output.push("<pre><code>");
        inCodeBlock = true;
      }
      continue;
    }
    if (inCodeBlock) {
      output.push(`${escapeHtml(line)}\n`);
      continue;
    }
    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    if (heading) {
      const level = heading[1]?.length ?? 1;
      output.push(`<h${level}>${formatInlineMarkdown(escapeHtml(heading[2] ?? ""))}</h${level}>`);
      continue;
    }
    if (/^---+$/.test(line.trim())) {
      output.push("<hr>");
      continue;
    }
    if (line.startsWith("> ")) {
      output.push(`<blockquote>${formatInlineMarkdown(escapeHtml(line.slice(2)))}</blockquote>`);
      continue;
    }
    const listItem = /^[-*]\s+(.+)$/.exec(line);
    if (listItem) {
      output.push(`<li>${formatInlineMarkdown(escapeHtml(listItem[1] ?? ""))}</li>`);
      continue;
    }
    if (!line.trim()) continue;
    output.push(`<p>${formatInlineMarkdown(escapeHtml(line))}</p>`);
  }
  if (inCodeBlock) output.push("</code></pre>");
  return output.join("\n");
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function imageMimeType(extension: string | undefined): string | null {
  switch (extension) {
    case "png":
      return "image/png";
    case "jpg":
    case "jpeg":
      return "image/jpeg";
    case "gif":
      return "image/gif";
    case "webp":
      return "image/webp";
    case "svg":
      return "image/svg+xml";
    case "bmp":
      return "image/bmp";
    default:
      return null;
  }
}

function previewDocument(content: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'"><style>body{font:16px/1.6 system-ui,sans-serif;color:#e8eaf0;background:#171a21;padding:1.5rem;margin:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101218;padding:0.9rem;border-radius:0.45rem}code{color:#b4a1ff;font-family:ui-monospace,monospace}blockquote{border-left:3px solid #788cff;margin:0.8rem 0;padding-left:1rem;color:#9da4b4}hr{border:0;border-top:1px solid #303543;margin:1rem 0}img{max-width:100%;height:auto;border-radius:0.45rem}a{color:#a7b5ff}</style></head><body>${content}</body></html>`;
}

function setEditMode(editing: boolean): void {
  isEditing = editing;
  if (editing && selectedText !== null) {
    editorTextarea.value = selectedText;
    frame.classList.add("hidden");
    editorTextarea.classList.remove("hidden");
    editButton.classList.add("hidden");
    saveEditButton.classList.remove("hidden");
    cancelEditButton.classList.remove("hidden");
  } else {
    editorTextarea.classList.add("hidden");
    frame.classList.remove("hidden");
    saveEditButton.classList.add("hidden");
    cancelEditButton.classList.add("hidden");
    if (selectedText !== null) {
      editButton.classList.remove("hidden");
    }
  }
}

async function preview(name: string): Promise<void> {
  try {
    const bytes = await vaultClient.readBytes(name);
    const extension = name.split(".").pop()?.toLowerCase();
    const mime = imageMimeType(extension);

    selectedName = name;
    selectedBytes = bytes;
    selectedText = null;
    isEditing = false;

    let rendered: string;
    if (mime) {
      const dataUrl = `data:${mime};base64,${encodeBase64(bytes)}`;
      rendered = `<img src="${dataUrl}" alt="${escapeHtml(name)}" />`;
    } else {
      try {
        const text = textDecoder.decode(bytes);
        selectedText = text;
        rendered =
          extension === "html" || extension === "htm"
            ? text
            : extension === "md" || extension === "markdown"
              ? renderMarkdown(text)
              : `<pre>${escapeHtml(text)}</pre>`;
      } catch {
        rendered = `<p>Binary file (${formatBytes(bytes.byteLength)}). Use <strong>Export</strong> to save a copy.</p>`;
      }
    }

    previewTitle.textContent = name;
    frame.srcdoc = previewDocument(rendered);
    setEditMode(false);
    editButton.classList.toggle("hidden", selectedText === null);
    copyButton.classList.toggle("hidden", selectedText === null);
    renameButton.classList.remove("hidden");
    exportButton.classList.remove("hidden");
    deleteButton.classList.remove("hidden");
    renderEntries();
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not read the file.";
  }
}

async function importFileList(files: FileList): Promise<void> {
  if (!files.length) return;
  let imported = 0;
  try {
    for (const file of files) {
      const buffer = new Uint8Array(await file.arrayBuffer());
      entries = await vaultClient.addBytes(file.name, buffer);
      imported += 1;
    }
    renderEntries();
    void refreshStatsPill();
    vaultMessage.textContent = `Imported ${imported} file${imported === 1 ? "" : "s"}.`;
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not import files.";
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
    const name = byId<HTMLInputElement>("entry-name").value;
    entries = await vaultClient.add(name, byId<HTMLTextAreaElement>("entry-content").value);
    byId<HTMLInputElement>("entry-name").value = "";
    byId<HTMLTextAreaElement>("entry-content").value = "";
    renderEntries();
    void refreshStatsPill();
    vaultMessage.textContent = "File added.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not add the file.";
  }
});

search.addEventListener("input", renderEntries);

byId<HTMLButtonElement>("import-button").addEventListener("click", () => {
  importInput.click();
});

importInput.addEventListener("change", () => {
  if (importInput.files) {
    void importFileList(importInput.files);
    importInput.value = "";
  }
});

sidebar.addEventListener("dragover", (event) => {
  event.preventDefault();
  sidebar.classList.add("drag-over");
});

sidebar.addEventListener("dragleave", () => {
  sidebar.classList.remove("drag-over");
});

sidebar.addEventListener("drop", (event) => {
  event.preventDefault();
  sidebar.classList.remove("drag-over");
  if (event.dataTransfer?.files.length) {
    void importFileList(event.dataTransfer.files);
  }
});

editButton.addEventListener("click", () => {
  setEditMode(true);
});

cancelEditButton.addEventListener("click", () => {
  setEditMode(false);
});

saveEditButton.addEventListener("click", async () => {
  if (!selectedName || !isEditing) return;
  try {
    entries = await vaultClient.add(selectedName, editorTextarea.value);
    await preview(selectedName);
    void refreshStatsPill();
    vaultMessage.textContent = "Changes saved.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not save changes.";
  }
});

renameButton.addEventListener("click", async () => {
  if (!selectedName) return;
  const nextName = window.prompt("New file path:", selectedName);
  if (!nextName || nextName.trim() === selectedName) return;
  try {
    entries = await vaultClient.rename(selectedName, nextName.trim());
    await preview(nextName.trim());
    void refreshStatsPill();
    vaultMessage.textContent = "File renamed.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not rename the file.";
  }
});

copyButton.addEventListener("click", async () => {
  if (selectedText === null) return;
  try {
    await navigator.clipboard.writeText(selectedText);
    if (clipboardClearTimer !== undefined) {
      window.clearTimeout(clipboardClearTimer);
    }
    clipboardClearTimer = window.setTimeout(() => {
      void navigator.clipboard.writeText("").catch(() => undefined);
    }, 30_000);
    vaultMessage.textContent = "Copied to clipboard (auto-clears in 30s).";
  } catch {
    vaultMessage.textContent = "Clipboard access was denied.";
  }
});

exportButton.addEventListener("click", () => {
  if (!selectedName || !selectedBytes) return;
  const copy = new Uint8Array(selectedBytes);
  const blob = new Blob([copy], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = selectedName.split("/").at(-1) ?? "export.bin";
  anchor.click();
  URL.revokeObjectURL(url);
  vaultMessage.textContent = "File exported.";
});

deleteButton.addEventListener("click", async () => {
  if (!selectedName) return;
  try {
    entries = await vaultClient.remove(selectedName);
    clearSelection();
    renderEntries();
    void refreshStatsPill();
    vaultMessage.textContent = "File deleted.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not delete the file.";
  }
});

byId<HTMLButtonElement>("compact-button").addEventListener("click", async () => {
  try {
    await vaultClient.compact();
    void refreshStatsPill();
    vaultMessage.textContent = "Vault compacted.";
  } catch (error) {
    vaultMessage.textContent = error instanceof Error ? error.message : "Could not compact the vault.";
  }
});

byId<HTMLButtonElement>("lock-button").addEventListener("click", () => {
  void lockNow();
});

byId<HTMLButtonElement>("settings-button").addEventListener("click", () => {
  settingsMessage.textContent = "";
  void refreshStatsPill();
  settingsDialog.showModal();
});

byId<HTMLButtonElement>("close-settings-button").addEventListener("click", () => {
  settingsDialog.close();
});

autolockSelect.addEventListener("change", () => {
  autoLockSeconds = Number(autolockSelect.value) || 0;
  updateAutoLockLabel();
  resetAutoLockTimer();
});

themeSelect.addEventListener("change", () => {
  const theme = themeSelect.value;
  applyTheme(theme);
  localStorage.setItem("secret-vault-theme", theme);
});

byId<HTMLFormElement>("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  settingsMessage.textContent = "";
  const currentInput = byId<HTMLInputElement>("current-password");
  const newInput = byId<HTMLInputElement>("new-password");
  const burnInput = byId<HTMLInputElement>("new-burn-password");
  const disguiseSelect = byId<HTMLSelectElement>("new-disguise-mode");

  const currentPassword = currentInput.value;
  const newPassword = newInput.value;
  const burnPassword = burnInput.value || null;
  currentInput.value = "";
  newInput.value = "";
  burnInput.value = "";

  try {
    await vaultClient.changePasswords(
      currentPassword,
      newPassword,
      burnPassword,
      disguiseSelect.value,
    );
    settingsMessage.textContent = "Passwords updated.";
  } catch (error) {
    settingsMessage.textContent =
      error instanceof Error ? error.message : "Could not update passwords.";
  }
});
