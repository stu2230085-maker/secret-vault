import { invoke } from "@tauri-apps/api/core";

export interface VaultEntry {
  name: string;
  offset: number;
  len: number;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const demoFiles = new Map<string, string>([
  ["Welcome.md", "# Your private vault\n\nThis **Markdown** preview is rendered in a sandboxed frame."],
  [
    "Example.html",
    "<h1>Isolated HTML preview</h1><p>Scripts and external resources are blocked.</p>",
  ],
]);

let mockFiles = new Map(demoFiles);
let mockPassword = "test";
let mockBurnPassword = "burn";
let mockDisguise = "error";
let mockIsOpen = false;
let mockHasCustomVault = false;

function mockEntries(): VaultEntry[] {
  return [...mockFiles.keys()].map((name, offset) => ({
    name,
    offset,
    len: mockFiles.get(name)?.length ?? 0,
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

async function mockOpen(password: string): Promise<VaultEntry[]> {
  if (password === mockBurnPassword) {
    mockFiles.clear();
    mockIsOpen = false;
    if (mockDisguise === "decoy") {
      mockIsOpen = true;
      return [];
    }
    throw new Error("invalid password");
  }
  if (password !== mockPassword && !(password === "test" && !mockHasCustomVault)) {
    throw new Error("invalid password");
  }
  if (!mockIsOpen && password === "test" && !mockHasCustomVault && mockFiles.size === 0) {
    mockFiles = new Map(demoFiles);
  }
  mockIsOpen = true;
  return mockEntries();
}

export const vaultClient = {
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
    if (burnPassword && passwordsAreSimilar(password, burnPassword)) {
      throw new Error("burn password is too similar to the main password");
    }
    mockFiles = new Map();
    mockPassword = password;
    mockBurnPassword = burnPassword || "burn";
    mockDisguise = disguise;
    mockIsOpen = true;
    mockHasCustomVault = true;
    return [];
  },

  async entries(): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("list_entries");
    if (!mockIsOpen) throw new Error("no vault is open");
    return mockEntries();
  },

  async add(name: string, content: string): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("add_entry", { name, content });
    if (!mockIsOpen) throw new Error("no vault is open");
    mockFiles.set(name.replaceAll("\\", "/"), content);
    return mockEntries();
  },

  async read(name: string): Promise<string> {
    if (isTauri) return invoke<string>("read_entry", { name });
    if (!mockIsOpen) throw new Error("no vault is open");
    const content = mockFiles.get(name);
    if (content === undefined) throw new Error("vault entry not found");
    return content;
  },

  async remove(name: string): Promise<VaultEntry[]> {
    if (isTauri) return invoke<VaultEntry[]>("delete_entry", { name });
    if (!mockIsOpen) throw new Error("no vault is open");
    mockFiles.delete(name);
    return mockEntries();
  },

  async compact(): Promise<void> {
    if (isTauri) await invoke<void>("compact_vault");
  },

  async lock(): Promise<void> {
    if (isTauri) await invoke("lock_vault");
    mockIsOpen = false;
  },
};
