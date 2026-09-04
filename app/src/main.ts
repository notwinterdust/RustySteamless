import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";

interface LogEvent {
  level: "debug" | "info" | "success" | "error";
  message: string;
}

interface UnpackReport {
  success: boolean;
  message: string;
  used_variant: string | null;
}

interface Options {
  verbose_output: boolean;
  keep_bind_section: boolean;
  dump_payload_to_disk: boolean;
  dump_steam_drmp_to_disk: boolean;
  use_experimental_features: boolean;
  realign_sections: boolean;
  zero_dos_stub_data: boolean;
  recalculate_file_checksum: boolean;
}

const pathEl = document.getElementById("path") as HTMLSpanElement;
const pickEl = document.getElementById("pick") as HTMLButtonElement;
const unpackEl = document.getElementById("unpack") as HTMLButtonElement;
const dispatchEl = document.getElementById("dispatch") as HTMLSpanElement;
const statusEl = document.getElementById("status") as HTMLSpanElement;
const consoleEl = document.getElementById("console") as HTMLPreElement;
const logCard = document.getElementById("log-card") as HTMLElement;

let selectedPath: string | null = null;
let unlisten: UnlistenFn | null = null;
let dispatch = "";

function setStatus(text: string) {
  statusEl.textContent = text;
}

function appendLog(level: string, message: string) {
  const line = document.createElement("div");
  line.className = `log-${level}`;
  line.textContent = `[${level.toUpperCase()}] ${message}`;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function currentOptions(): Options {
  const checked = (id: string) => (document.getElementById(id) as HTMLInputElement).checked;
  return {
    verbose_output: checked("opt-verbose"),
    keep_bind_section: checked("opt-keepbind"),
    dump_payload_to_disk: checked("opt-dumppayload"),
    dump_steam_drmp_to_disk: checked("opt-dumpdrmp"),
    use_experimental_features: checked("opt-exp"),
    realign_sections: checked("opt-realign"),
    zero_dos_stub_data: !checked("opt-keepstub"),
    recalculate_file_checksum: checked("opt-checksum"),
  };
}

async function selectFile() {
  const file = await open({
    multiple: false,
    directory: false,
    title: "Select a packed executable",
  });
  if (typeof file === "string") {
    selectedPath = file;
    pathEl.textContent = file;
    unpackEl.disabled = false;
    setStatus("");
  }
}

function handleDrop(event: DragEvent) {
  event.preventDefault();
  logCard.classList.remove("dragover");
  const file = event.dataTransfer?.files[0];
  if (file) {
    const dropped = file as File & { path?: string };
    selectedPath = dropped.path ?? null;
    if (selectedPath) {
      pathEl.textContent = selectedPath;
      unpackEl.disabled = false;
      setStatus("");
    } else {
      appendLog("error", "dropped file has no usable path; use the file picker instead");
    }
  }
}

async function unpack() {
  if (!selectedPath) {
    return;
  }
  unpackEl.disabled = true;
  consoleEl.replaceChildren();
  appendLog("info", `Unpacking: ${selectedPath}`);
  setStatus("Working…");

  unlisten = await listen<LogEvent>("log", (event) => {
    appendLog(event.payload.level, event.payload.message);
  });

  try {
    const report = await invoke<UnpackReport>("unpack", {
      path: selectedPath,
      options: currentOptions(),
    });
    dispatch = report.used_variant ?? dispatch;
    dispatchEl.textContent = dispatch ? `via ${dispatch}` : "";
    if (report.success) {
      setStatus("Done");
    } else {
      setStatus("Failed");
      appendLog("error", report.message);
    }
  } catch (error) {
    setStatus("Failed");
    appendLog("error", String(error));
  } finally {
    unlisten?.();
    unpackEl.disabled = false;
  }
}

pickEl.addEventListener("click", selectFile);
unpackEl.addEventListener("click", unpack);
logCard.addEventListener("dragover", (event) => {
  event.preventDefault();
  logCard.classList.add("dragover");
});
logCard.addEventListener("dragleave", () => logCard.classList.remove("dragover"));
logCard.addEventListener("drop", handleDrop);

async function init() {
  try {
    dispatch = (await invoke<string[]>("list_variants")).join(", ");
    dispatchEl.textContent = dispatch;
  } catch (error) {
    appendLog("error", `failed to list variants: ${String(error)}`);
  }
}

void init();