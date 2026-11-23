import { createSalt, deriveKey, openVault, sealVault } from "./crypto.js";
import { MAX_ENVELOPE_BYTES, validateEnvelope } from "./vault-format.js";

const elements = Object.fromEntries(
  [...document.querySelectorAll("[id]")].map((element) => [element.id, element])
);
const dateFormatter = new Intl.DateTimeFormat("zh-CN", { month: "short", day: "numeric" });
const canUseClient = isSecureContext && !!crypto.subtle;
let mode = "access";
let connection = null;
let encryptedVault = null;
let session = null;
let selectedId = null;
let dirty = false;
let conflict = false;
let operation = null;
let idleTimer;
let needsSignIn = false;

class UserError extends Error {}
class ExpiredSession extends UserError {}

async function request(path, signal, options) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)]);
  let response;
  try {
    response = await fetch(path, {
      cache: "no-store",
      credentials: "omit",
      mode: "same-origin",
      redirect: "error",
      referrerPolicy: "same-origin",
      signal: deadline,
      ...options,
    });
  } catch {
    signal.throwIfAborted();
    throw new UserError("连接失败。请检查网络后重试。");
  }
  signal.throwIfAborted();
  return response;
}

async function responseJson(response, maxBytes) {
  const reader = response.body?.getReader();
  if (!reader) throw new UserError("同步服务返回了空响应。");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let text = "";
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new UserError("同步响应超过大小上限。");
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } finally {
    reader.releaseLock();
  }
}

async function authenticate(password, signal) {
  const pending = request("/api/session", signal, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  password = "";
  const response = await pending;
  if (response.status === 401) throw new UserError("门禁密码不正确。");
  if (response.status === 429) throw new UserError("尝试次数过多，请稍后重试。");
  if (response.status === 503) throw new UserError("Worker 尚未配置门禁密码。");
  if (!response.ok) throw new UserError("无法登录门禁。");
  const data = await responseJson(response, 1024);
  signal.throwIfAborted();
  if (typeof data?.token !== "string" || !/^v1\.\d{1,12}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(data.token)) {
    throw new UserError("同步服务未返回有效会话。");
  }
  return data.token;
}

async function vaultRequest(access, signal, options) {
  const response = await request("/api/vault", signal, {
    ...options,
    headers: { ...options?.headers, Authorization: `Bearer ${access.token}` },
  });
  if (response.status === 401) throw new ExpiredSession("门禁会话已过期，请重新连接。");
  return response;
}

async function readVault(access, signal) {
  const response = await vaultRequest(access, signal);
  if (response.status === 404) return null;
  if (!response.ok) throw new UserError("暂时无法读取保险库，请稍后重试。");

  const envelope = await responseJson(response, MAX_ENVELOPE_BYTES);
  signal.throwIfAborted();
  const tag = response.headers.get("ETag");
  const revision = tag && /^"[1-9][0-9]*"$/.test(tag) ? Number(tag.slice(1, -1)) : NaN;
  if (!Number.isSafeInteger(revision) || !validateEnvelope(envelope)) {
    throw new UserError("保险库格式无效，或者需要更新客户端。");
  }
  return { envelope, revision };
}

async function writeVault(envelope, revision, signal) {
  const body = JSON.stringify(envelope);
  if (body.length > MAX_ENVELOPE_BYTES) {
    throw new UserError("保险库已达到 1 MB 的同步上限。请缩短或删除部分笔记后重试。");
  }
  const precondition = revision === null ? { "If-None-Match": "*" } : { "If-Match": `"${revision}"` };
  signal.throwIfAborted();
  const response = await vaultRequest(connection, signal, {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...precondition },
    body,
  });
  if (response.status === 412) return null;
  if (!response.ok) throw new UserError("保存失败。请稍后重试。");
  const result = await responseJson(response, 1024);
  signal.throwIfAborted();
  if (result?.revision !== (revision ?? 0) + 1) {
    throw new UserError("保存结果无法确认。请检查云端版本。");
  }
  return result.revision;
}

function setNotice(element, message = "") {
  element.textContent = message;
  element.hidden = !message;
}

function renderControls() {
  const status = elements["sync-status"];
  const selected = currentNote();
  const setup = mode === "setup";
  const busy = operation !== null;
  status.dataset.state = dirty || conflict ? "changed" : session && !busy ? "ok" : "quiet";
  if (busy) status.textContent = "处理中";
  else if (conflict) status.textContent = "同步冲突";
  else if (dirty) status.textContent = "未保存";
  else if (session) status.textContent = "已同步";
  else status.textContent = "已锁定";

  elements.gate.hidden = session !== null;
  elements.workspace.hidden = session === null;
  elements.lock.hidden = !connection && !busy;
  elements["access-fields"].hidden = mode !== "access";
  elements["unlock-fields"].hidden = mode !== "setup" && mode !== "unlock";
  elements["renew-fields"].hidden = !session || !needsSignIn;
  elements["confirm-field"].hidden = !setup;
  elements.connect.disabled = busy || !canUseClient;
  elements.renew.disabled = busy;
  elements.unlock.disabled = busy;
  elements.unlock.textContent = setup ? "创建保险库" : "解锁";
  elements["gate-title"].textContent = setup ? "创建保险库" : mode === "unlock" ? "解锁保险库" : "登录门禁";
  elements["gate-copy"].textContent = setup
    ? "请用独立的随机长口令。忘记主密码将无法解密。"
    : mode === "unlock" ? "主密码只在此设备的内存中使用。"
      : "输入门禁密码后，再用独立的加密主密码解锁笔记。";

  elements["new-note"].disabled = busy;
  elements["first-note"].disabled = busy;
  elements.refresh.disabled = busy || needsSignIn;
  elements.save.disabled = busy || needsSignIn || !dirty || conflict;
  elements["delete-note"].hidden = !selected;
  elements["delete-note"].disabled = busy;
  for (const id of ["access-password", "renew-password", "password", "confirm-password", "note-title", "note-tags", "note-body"]) {
    elements[id].readOnly = busy;
  }
}

async function run(action) {
  if (operation || !canUseClient || document.hidden) return;
  const controller = new AbortController();
  const { signal } = controller;
  operation = controller;
  setNotice(session ? elements["editor-notice"] : elements["gate-notice"]);
  renderControls();
  try {
    await action(signal);
  } catch (error) {
    if (!signal.aborted) {
      let message = error instanceof UserError ? error.message : "操作未完成。请稍后重试。";
      if (error instanceof ExpiredSession) {
        if (session) {
          needsSignIn = true;
          connection.token = "";
          message = "门禁会话已过期。重新输入门禁密码后可继续保存。";
        } else {
          lock();
        }
      }
      setNotice(session ? elements["editor-notice"] : elements["gate-notice"], message);
    }
  } finally {
    if (operation === controller) {
      operation = null;
      renderControls();
    }
  }
}

function takeInput(id) {
  const input = elements[id];
  const value = input.value;
  input.value = "";
  const fresh = input.cloneNode(false);
  fresh.value = "";
  input.replaceWith(fresh);
  elements[id] = fresh;
  return value;
}

async function connect() {
  await run(async (signal) => {
    let password = takeInput("access-password");
    const signingIn = authenticate(password, signal);
    password = "";
    const access = { token: await signingIn };
    const remote = await readVault(access, signal);
    signal.throwIfAborted();
    connection = access;
    encryptedVault = remote;
    mode = remote ? "unlock" : "setup";
  });
  if (connection && !session) elements.password.focus();
}

async function renew() {
  await run(async (signal) => {
    let password = takeInput("renew-password");
    const signingIn = authenticate(password, signal);
    password = "";
    const token = await signingIn;
    signal.throwIfAborted();
    connection.token = token;
    needsSignIn = false;
  });
}

async function decryptNotes(key, envelope) {
  try {
    return await openVault(key, envelope);
  } catch {
    throw new UserError("无法解密保险库。请检查主密码，或确认云端数据是否已损坏。");
  }
}

async function unlock() {
  if (!connection || session) return;
  await run(async (signal) => {
    let passphrase = takeInput("password");
    const matches = passphrase === takeInput("confirm-password");
    const remote = encryptedVault;
    if (!passphrase) throw new UserError("请输入加密主密码。");
    if (!remote && [...passphrase].length < 24) throw new UserError("新主密码至少需要 24 个字符。");
    if (!remote && !matches) throw new UserError("两次输入的主密码不同。");

    const salt = remote?.envelope.salt ?? createSalt();
    const deriving = deriveKey(passphrase, salt);
    passphrase = "";
    const key = await deriving;
    signal.throwIfAborted();
    if (!remote) {
      const revision = await writeVault(await sealVault(key, salt, []), null, signal);
      if (revision === null) {
        const created = await readVault(connection, signal);
        signal.throwIfAborted();
        encryptedVault = created;
        mode = created ? "unlock" : "setup";
        throw new UserError("保险库状态已变化。请重新解锁或连接。");
      }
      showWorkspace({ key, salt, revision, notes: [] });
      return;
    }

    const { envelope, revision } = remote;
    const notes = await decryptNotes(key, envelope);
    signal.throwIfAborted();
    showWorkspace({ key, salt, revision, notes });
  });
  if (!session && connection) elements.password.focus();
  if (session) elements["new-note"].focus();
}

function showWorkspace(vault) {
  session = vault;
  encryptedVault = null;
  selectedId = sortedNotes(vault.notes)[0]?.id ?? null;
  dirty = false;
  conflict = false;
  renderEditor();
}

function currentNote() {
  return session?.notes.find(({ id }) => id === selectedId);
}

function sortedNotes(notes) {
  return [...notes].sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
}

function renderList() {
  const notes = session?.notes ?? [];
  const query = elements.search.value.trim().toLocaleLowerCase();
  const matches = sortedNotes(notes).filter((note) =>
    [note.title, note.body, ...note.tags].some((text) => text.toLocaleLowerCase().includes(query))
  );
  const rows = matches.map((note) => {
    const row = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.id = note.id;
    if (note.id === selectedId) button.setAttribute("aria-current", "true");
    const title = document.createElement("strong");
    title.textContent = note.title.trim() || "无标题";
    const summary = document.createElement("span");
    summary.textContent = note.tags.join(" · ") || dateFormatter.format(Date.parse(note.updatedAt));
    button.append(title, summary);
    row.append(button);
    return row;
  });
  elements["note-list"].replaceChildren(...rows);
  setNotice(elements["list-empty"], matches.length ? "" : query ? "没有匹配的笔记" : "还没有笔记");
}

function renderEditor() {
  const note = currentNote();
  elements.editor.hidden = !note;
  elements["empty-editor"].hidden = !!note;
  elements["note-title"].value = note?.title ?? "";
  elements["note-tags"].value = note?.tags.join(", ") ?? "";
  elements["note-body"].value = note?.body ?? "";
  renderList();
  renderControls();
}

function addNote() {
  if (operation || !session) return;
  const note = { id: crypto.randomUUID(), title: "", body: "", tags: [], updatedAt: new Date().toISOString() };
  session.notes.push(note);
  selectedId = note.id;
  dirty = true;
  elements.search.value = "";
  renderEditor();
  elements["note-title"].focus();
}

function editNote() {
  const note = currentNote();
  if (!note || operation) return;
  note.title = elements["note-title"].value;
  note.body = elements["note-body"].value;
  note.tags = elements["note-tags"].value.split(/[,，]/).map((tag) => tag.trim()).filter(Boolean);
  note.updatedAt = new Date().toISOString();
  dirty = true;
  renderList();
  renderControls();
}

function deleteNote() {
  if (operation || !currentNote()) return;
  ask("删除这条笔记？加密保存后会同步到云端。", () => {
    session.notes = session.notes.filter(({ id }) => id !== selectedId);
    selectedId = sortedNotes(session.notes)[0]?.id ?? null;
    dirty = true;
    renderEditor();
  });
}

async function save() {
  if (!session || !dirty || conflict || needsSignIn) return;
  await run(async (signal) => {
    const { key, salt, notes, revision } = session;
    let envelope;
    try {
      envelope = await sealVault(key, salt, notes);
    } catch (error) {
      if (error instanceof RangeError) throw new UserError("保险库已达到同步上限，请缩短或删除部分笔记。");
      throw error;
    }
    const next = await writeVault(envelope, revision, signal);
    signal.throwIfAborted();
    if (next === null) {
      conflict = true;
      throw new UserError("云端已有新版本。当前草稿仅保留在内存中，载入云端会替换它。");
    }
    session.revision = next;
    dirty = false;
  });
}

async function refresh() {
  if (operation || !session || needsSignIn) return;
  await run(async (signal) => {
    const remote = await readVault(connection, signal);
    signal.throwIfAborted();
    if (!remote || remote.envelope.salt !== session.salt) {
      throw new UserError("云端保险库已变化。请确认同步地址和数据后重新连接。");
    }
    if (remote.revision < session.revision) throw new UserError("云端返回了较早的版本，已保留当前内容。");
    const notes = await decryptNotes(session.key, remote.envelope);
    signal.throwIfAborted();
    session.notes = notes;
    session.revision = remote.revision;
    if (!currentNote()) selectedId = sortedNotes(notes)[0]?.id ?? null;
    dirty = false;
    conflict = false;
    renderEditor();
  });
}

let confirmationAction = null;

function ask(message, action) {
  elements["dialog-message"].textContent = message;
  confirmationAction = action;
  elements.confirmation.showModal();
}

function lock() {
  operation?.abort();
  operation = null;
  clearTimeout(idleTimer);
  confirmationAction = null;
  if (elements.confirmation.open) elements.confirmation.close();
  mode = "access";
  if (connection) connection.token = "";
  if (session) {
    session.notes.length = 0;
    session.key = null;
  }
  connection = null;
  encryptedVault = null;
  session = null;
  selectedId = null;
  dirty = false;
  conflict = false;
  needsSignIn = false;
  for (const id of ["access-password", "password", "confirm-password", "renew-password",
    "search", "note-title", "note-tags", "note-body"]) takeInput(id);
  setNotice(elements["gate-notice"]);
  setNotice(elements["editor-notice"]);
  renderEditor();
}

function noteActivity() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, 60_000);
}

elements.connect.addEventListener("click", connect);
elements.unlock.addEventListener("click", unlock);
elements.renew.addEventListener("click", renew);
elements.lock.addEventListener("click", lock);
elements["new-note"].addEventListener("click", addNote);
elements["first-note"].addEventListener("click", addNote);
elements["delete-note"].addEventListener("click", deleteNote);
elements["note-list"].addEventListener("click", (event) => {
  const button = event.target.closest("button[data-id]");
  if (operation || !session || !button) return;
  selectedId = button.dataset.id;
  renderEditor();
  elements["note-title"].focus();
});
document.addEventListener("input", (event) => {
  noteActivity();
  const id = event.target.id;
  if (id === "search") renderList();
  else if (["note-title", "note-tags", "note-body"].includes(id)) editNote();
});
elements.save.addEventListener("click", save);
elements.refresh.addEventListener("click", () => {
  if (dirty) ask("载入云端会丢弃当前未保存的更改。继续吗？", refresh);
  else void refresh();
});
elements["dialog-cancel"].addEventListener("click", () => elements.confirmation.close());
elements["dialog-confirm"].addEventListener("click", () => {
  const action = confirmationAction;
  confirmationAction = null;
  elements.confirmation.close();
  action?.();
});
elements.confirmation.addEventListener("close", () => { confirmationAction = null; });
document.addEventListener("pointerdown", noteActivity);
document.addEventListener("wheel", noteActivity, { passive: true });
document.addEventListener("touchmove", noteActivity, { passive: true });
document.addEventListener("keydown", (event) => {
  noteActivity();
  if (event.isComposing) return;
  if (event.key === "Enter") {
    const id = event.target.id;
    if (id === "access-password") void connect();
    if (id === "password" || id === "confirm-password") void unlock();
    if (id === "renew-password") void renew();
  }
  if (session && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
    event.preventDefault();
    void save();
  }
});
window.addEventListener("blur", lock);
window.addEventListener("pagehide", lock);
document.addEventListener("visibilitychange", () => { if (document.hidden) lock(); });
renderControls();
if (!canUseClient) setNotice(elements["gate-notice"], "请使用 HTTPS 访问密记。");
