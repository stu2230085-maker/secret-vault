import { invoke } from "@tauri-apps/api/core";

export interface VaultEntry {
  name: string;
  offset: number;
  len: number;
}

export interface VaultStats {
  entry_count: number;
  file_size: number;
  live_data_bytes: number;
  reclaimable_bytes: number;
  decoy: boolean;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function encodeDemoEntries(): Map<string, Uint8Array> {
  return new Map<string, Uint8Array>([
    [
      "Welcome.md",
      encoder.encode(
        "# Your private vault\n\nThis **Markdown** preview is rendered in a `sandbox=\"\"` isolated frame.\n\n- Drag & drop files onto the sidebar to encrypt and import\n- Click **Edit** to update text notes in memory\n- Open **Settings** to rotate passwords or configure auto-lock",
      ),
    ],
    [
      "Example.html",
      encoder.encode(
        "<h1>Isolated HTML preview</h1><p>Scripts, forms, objects, and external network requests are blocked.</p><script>window.alert('blocked')</script>",
      ),
    ],
    [
      "notes/security.txt",
      encoder.encode(
        "AES-256-GCM per-entry encryption + Argon2id key wrapping + zeroize + CSPRNG crypto-shredding.",
      ),
    ],
  ]);
}

let mockFiles = encodeDemoEntries();
let mockPassword = "test";
let mockBurnPassword: string | null = "burn";
let mockDisguise = "error";
let mockIsOpen = false;
let mockDecoy = false;
let mockHasCustomVault = false;
let mockReclaimableBytes = 0;

function normalizeEntryName(name: string): string {
  const normalized = name.trim().replaceAll("\\", "/");
  if (
    !normalized ||
    normalized.startsWith("/") ||
    normalized.includes(":") ||
    normalized.split("/").some((part) => !part || part === "." || part === "..")
  ) {
    throw new Error("invalid entry name");
  }
  return normalized;
}

function mockEntries(): VaultEntry[] {
  return [...mockFiles.entries()].map(([name, bytes], offset) => ({
    name,
    offset: 320 + offset * 64,
    len: 28 + bytes.byteLength,
  }));
}

function passwordsAreSimilar(normal: string, burn: string): boolean {
  const left = [...normal.trim().toLowerCase()];
  const right = [...burn.trim().toLowerCase()];
  if (!left.length || !right.length) return true;
  if (Math.abs(left.length - right.length) > 1) return false;
  let previous = right.map((_, index) => index + 1);
  previous.unshift(0);
  for (const [index, character] of left.entries()) {
    const current = [index + 1];
    for (const [rightIndex, other] of right.entries()) {
      current.push(
        Math.min(
          (previous[rightIndex + 1] ?? 0) + 1,
          (current[rightIndex] ?? 0) + 1,
          (previous[rightIndex] ?? 0) + Number(character !== other),
        ),
      );
    }
    previous = current;
  }
  return previous[right.length] <= 1;
}

async function delayRateLimit(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 500));
}

async function mockOpen(password: string): Promise<VaultEntry[]> {
  if (mockBurnPassword && password === mockBurnPassword) {
    mockFiles.clear();
    mockReclaimableBytes = 0;
    mockIsOpen = false;
    if (mockDisguise === "decoy") {
      mockIsOpen = true;
      mockDecoy = true;
      return [];
    }
    await delayRateLimit();
    throw new Error("invalid password");
  }
  if (password !== mockPassword && !(password === "test" && !mockHasCustomVault)) {
    await delayRateLimit();
    throw new Error("invalid password");
  }
  if (!mockIsOpen && password === "test" && !mockHasCustomVault && mockFiles.size === 0) {
    mockFiles = encodeDemoEntries();
  }
  mockIsOpen = true;
  mockDecoy = false;
  return mockEntries();
}

export const vaultClient = {
  isTauriEnvironment(): boolean {
    return isTauri;
  },

  async open(path: string, password: string): Promise<VaultEntry[]> {
    if (!isTauri) return mockOpen(password);
    return invoke<VaultEntry[]>("open_vault", { path, password });
  },

  async create(
    path: string,
    password: string,
    burnPassword: string | null,
    disguise: string,
  ): Promise<VaultEntry[]> {
    if (isTauri) {
      return invoke<VaultEntry[]>("create_vault", {
        path,
        password,
        burnPassword,
        disguise,
      });
    }
    if (!password) throw new Error("invalid password");
    if (burnPassword && passwordsAreSimilar(password, burnPassword)) {
      throw new Error("burn password is too similar to the main password");
    }
    mockFiles = new Map();
    mockPassword = password;
    mockBurnPassword = burnPassword;
    mockDisguise = disguise;
    mockIsOpen = true;
    mockDecoy = false;
    mockHasCustomVault = true;
    mockReclaimableBytes = 0;
    return [];
  },

  async entries(): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("list_entries");
    if (!mockIsOpen) throw new Error("no vault is open");
    return mockEntries();
  },

  async add(name: string, content: string): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("add_entry", { name, content });
    return this.addBytes(name, encoder.encode(content));
  },

  async addBytes(name: string, bytes: Uint8Array): Promise<VaultEntry[]> {
    if (isTauri) {
      return invoke<VaultEntry[]>("add_entry_bytes", {
        name,
        content: Array.from(bytes),
      });
    }
    if (!mockIsOpen) throw new Error("no vault is open");
    if (mockDecoy) throw new Error("this decoy vault is read-only");
    const normalized = normalizeEntryName(name);
    const previous = mockFiles.get(normalized);
    if (previous) {
      mockReclaimableBytes += 28 + previous.byteLength;
    }
    mockFiles.set(normalized, new Uint8Array(bytes));
    return mockEntries();
  },

  async read(name: string): Promise<string> {
    if (isTauri) return invoke<string>("read_entry", { name });
    const bytes = await this.readBytes(name);
    try {
      return decoder.decode(bytes);
    } catch {
      throw new Error("file is not UTF-8 text");
    }
  },

  async readBytes(name: string): Promise<Uint8Array> {
    if (isTauri) {
      const data = await invoke<number[]>("read_entry_bytes", { name });
      return new Uint8Array(data);
    }
    if (!mockIsOpen) throw new Error("no vault is open");
    const content = mockFiles.get(name);
    if (content === undefined) throw new Error("vault entry not found");
    return new Uint8Array(content);
  },

  async rename(oldName: string, newName: string): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("rename_entry", { oldName, newName });
    if (!mockIsOpen) throw new Error("no vault is open");
    if (mockDecoy) throw new Error("this decoy vault is read-only");
    const normalized = normalizeEntryName(newName);
    if (oldName === normalized) return mockEntries();
    if (mockFiles.has(normalized)) throw new Error("vault entry already exists");
    const existing = mockFiles.get(oldName);
    if (existing === undefined) throw new Error("vault entry not found");
    mockFiles.delete(oldName);
    mockFiles.set(normalized, existing);
    return mockEntries();
  },

  async renameFolder(oldPrefix: string, newPrefix: string): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("rename_folder", { oldPrefix, newPrefix });
    if (!mockIsOpen) throw new Error("no vault is open");
    if (mockDecoy) throw new Error("this decoy vault is read-only");
    const from = `${normalizeEntryName(oldPrefix)}/`;
    const to = `${normalizeEntryName(newPrefix)}/`;
    const updates: Array<[string, string, Uint8Array]> = [];
    for (const [key, value] of mockFiles.entries()) {
      if (key.startsWith(from)) {
        const target = normalizeEntryName(`${to}${key.slice(from.length)}`);
        updates.push([key, target, value]);
      }
    }
    if (!updates.length) throw new Error("vault entry not found");
    for (const [, target] of updates) {
      if (mockFiles.has(target)) throw new Error("vault entry already exists");
    }
    for (const [oldKey, target, value] of updates) {
      mockFiles.delete(oldKey);
      mockFiles.set(target, value);
    }
    return mockEntries();
  },

  async remove(name: string): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("delete_entry", { name });
    if (!mockIsOpen) throw new Error("no vault is open");
    if (mockDecoy) throw new Error("this decoy vault is read-only");
    const existing = mockFiles.get(name);
    if (!existing) throw new Error("vault entry not found");
    mockReclaimableBytes += 28 + existing.byteLength;
    mockFiles.delete(name);
    return mockEntries();
  },

  async changePasswords(
    currentPassword: string,
    newPassword: string,
    burnPassword: string | null,
    disguise: string,
  ): Promise<void> {
    if (isTauri) {
      await invoke<void>("change_passwords", {
        currentPassword,
        newPassword,
        burnPassword,
        disguise,
      });
      return;
    }
    if (!mockIsOpen) throw new Error("no vault is open");
    if (mockDecoy) throw new Error("this decoy vault is read-only");
    if (!newPassword) throw new Error("invalid password");
    if (burnPassword && passwordsAreSimilar(newPassword, burnPassword)) {
      throw new Error("burn password is too similar to the main password");
    }
    if (currentPassword !== mockPassword) {
      await delayRateLimit();
      throw new Error("invalid password");
    }
    mockPassword = newPassword;
    mockBurnPassword = burnPassword;
    mockDisguise = disguise;
    mockHasCustomVault = true;
  },

  async stats(): Promise<VaultStats> {
    if (isTauri) return invoke<VaultStats>("vault_stats");
    if (!mockIsOpen) throw new Error("no vault is open");
    if (mockDecoy) {
      return {
        entry_count: 0,
        file_size: 0,
        live_data_bytes: 0,
        reclaimable_bytes: 0,
        decoy: true,
      };
    }
    const live = [...mockFiles.values()].reduce((sum, item) => sum + 28 + item.byteLength, 0);
    const indexSize = 64 + mockFiles.size * 48;
    return {
      entry_count: mockFiles.size,
      file_size: 320 + live + mockReclaimableBytes + indexSize + 20,
      live_data_bytes: live,
      reclaimable_bytes: mockReclaimableBytes,
      decoy: false,
    };
  },

  async compact(): Promise<void> {
    if (isTauri) {
      await invoke<void>("compact_vault");
      return;
    }
    if (!mockIsOpen) throw new Error("no vault is open");
    if (mockDecoy) throw new Error("this decoy vault is read-only");
    mockReclaimableBytes = 0;
  },

  async lock(): Promise<void> {
    if (isTauri) await invoke("lock_vault");
    mockIsOpen = false;
    mockDecoy = false;
  },
};
