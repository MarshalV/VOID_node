// Minimal vanilla JS front-end for the bootstrap node UI.

const $ = (sel) => document.querySelector(sel);

async function api(path, opts) {
    const res = await fetch(path, Object.assign({ headers: { "content-type": "application/json" } }, opts || {}));
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

function fmtUptime(sec) {
    sec = Math.max(0, sec | 0);
    const d = Math.floor(sec / 86400); sec -= d * 86400;
    const h = Math.floor(sec / 3600); sec -= h * 3600;
    const m = Math.floor(sec / 60); sec -= m * 60;
    const parts = [];
    if (d) parts.push(d + "д");
    if (h || d) parts.push(h + "ч");
    parts.push(m + "м");
    parts.push(sec + "с");
    return parts.join(" ");
}

function fmtAgo(ts, now) {
    if (!ts) return "никогда";
    const d = Math.max(0, now - ts);
    if (d < 60) return d + " сек. назад";
    if (d < 3600) return Math.floor(d / 60) + " мин. назад";
    if (d < 86400) return Math.floor(d / 3600) + " ч. назад";
    return Math.floor(d / 86400) + " д. назад";
}

function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString();
}

let currentStatus = null;

async function refreshStatus() {
    const s = await api("/api/status");
    currentStatus = s;
    $("#peer_id").textContent = s.peer_id_b58;
    $("#libp2p_port").textContent = s.libp2p_port;
    $("#seed_port").textContent = s.seed_port;
    $("#known_nodes").textContent = s.known_nodes;
    $("#uptime").textContent = fmtUptime(s.now - s.started_at);
    const ph = $("#public_host");
    if (document.activeElement !== ph) ph.value = s.public_host || "";
    const host = s.public_host || "<ВАШ_ПУБЛИЧНЫЙ_IP>";
    $("#bootstrap_line").textContent =
        `/ip4/${host}/tcp/${s.libp2p_port}/p2p/${s.peer_id_b58}`;
}

async function refreshNodes() {
    const r = await api("/api/nodes");
    const tb = $("#nodes_tbl tbody");
    tb.innerHTML = "";
    $("#nodes_count").textContent = r.nodes.length;
    $("#nodes_empty").hidden = r.nodes.length > 0;
    const now = currentStatus ? currentStatus.now : Math.floor(Date.now() / 1000);
    for (const n of r.nodes) {
        const tr = document.createElement("tr");
        tr.innerHTML =
            `<td class="mono break">${escapeHtml(n.host)}</td>` +
            `<td class="mono">${n.seed_port || "-"}</td>` +
            `<td class="mono">${n.libp2p_port || "-"}</td>` +
            `<td class="mono break">${escapeHtml(n.peer_id_b58)}</td>` +
            `<td>${fmtAgo(n.last_seen, now)}</td>` +
            `<td><button class="btn-del" data-pid="${escapeAttr(n.peer_id_b58)}">удалить</button></td>`;
        tb.appendChild(tr);
    }
    tb.querySelectorAll(".btn-del").forEach((b) => {
        b.addEventListener("click", async () => {
            const pid = b.getAttribute("data-pid");
            if (!confirm(`Забыть ноду ${pid}?`)) return;
            await api(`/api/nodes/${encodeURIComponent(pid)}`, { method: "DELETE" });
            refresh();
        });
    });
}

async function refreshActivity() {
    const r = await api("/api/activity");
    const ul = $("#activity");
    ul.innerHTML = "";
    for (const it of r.items) {
        const li = document.createElement("li");
        li.innerHTML =
            `<span class="ts">${fmtTime(it.timestamp)}</span>` +
            `<span class="kind" data-kind="${escapeAttr(it.kind)}">${escapeHtml(it.kind)}</span>` +
            `<span>${escapeHtml(it.message)}</span>`;
        ul.appendChild(li);
    }
}

function escapeHtml(s) {
    return String(s || "").replace(/[&<>"']/g, (c) =>
        ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function escapeAttr(s) { return escapeHtml(s); }

async function refresh() {
    try { await Promise.all([refreshStatus(), refreshNodes(), refreshActivity()]); }
    catch (e) { console.error(e); }
}

async function onConnect() {
    const host = $("#connect_host").value.trim();
    if (!host) return;
    const res = $("#connect_result");
    res.className = "";
    res.style.display = "block";
    res.textContent = "Подключаемся и выполняем handshake ...";
    try {
        const r = await api("/api/connect", {
            method: "POST",
            body: JSON.stringify({ host }),
        });
        if (r.ok) {
            res.classList.add("ok");
            res.innerHTML =
                `<strong>Успех.</strong> Удалённый узел прошёл проверку VOID.<br>` +
                `<span class="k">PeerId:</span> <code>${escapeHtml(r.peer_id_b58)}</code><br>` +
                `<span class="k">Agent:</span> <code>${escapeHtml(r.agent || "")}</code><br>` +
                `<span class="k">Передано ему:</span> ${r.sent}, ` +
                `<span class="k">получено:</span> ${r.received}, ` +
                `<span class="k">новых добавлено:</span> ${r.added}.`;
        } else {
            res.classList.add("err");
            res.innerHTML =
                `<strong>Отказ.</strong> ${escapeHtml(r.error || "не удалось проверить удалённый узел")}.`;
        }
    } catch (e) {
        res.classList.add("err");
        res.textContent = "Ошибка: " + e.message;
    }
    refresh();
}

async function onSavePublicHost() {
    const host = $("#public_host").value.trim();
    await api("/api/public_host", {
        method: "POST",
        body: JSON.stringify({ host }),
    });
    refresh();
}

document.addEventListener("DOMContentLoaded", () => {
    $("#connect_btn").addEventListener("click", onConnect);
    $("#connect_host").addEventListener("keydown", (e) => {
        if (e.key === "Enter") onConnect();
    });
    $("#save_public_host").addEventListener("click", onSavePublicHost);
    $("#public_host").addEventListener("keydown", (e) => {
        if (e.key === "Enter") onSavePublicHost();
    });
    refresh();
    setInterval(refresh, 5000);
});
