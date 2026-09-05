// AI Code Reviewer & Security Auditor Frontend Application

let currentScanResult = null;
let sampleData = {};

document.addEventListener("DOMContentLoaded", () => {
    initEditor();
    initTabs();
    initSettingsModal();
    loadSamples();
    setupEventListeners();
});

// -------------------------------------------------------------
// Editor Initialization & Line Numbers
// -------------------------------------------------------------
function initEditor() {
    const codeInput = document.getElementById("code-input");
    const lineNumbers = document.getElementById("line-numbers");
    const lineCountLabel = document.getElementById("label-line-count");

    function updateLineNumbers() {
        const lines = codeInput.value.split("\n");
        const count = lines.length;
        lineCountLabel.textContent = `${count} ${count === 1 ? 'line' : 'lines'}`;
        
        let numStr = "";
        for (let i = 1; i <= count; i++) {
            numStr += i + "\n";
        }
        lineNumbers.textContent = numStr;
    }

    // Support Tab indentation
    codeInput.addEventListener("keydown", (e) => {
        if (e.key === "Tab") {
            e.preventDefault();
            const start = codeInput.selectionStart;
            const end = codeInput.selectionEnd;
            codeInput.value = codeInput.value.substring(0, start) + "    " + codeInput.value.substring(end);
            codeInput.selectionStart = codeInput.selectionEnd = start + 4;
            updateLineNumbers();
        }
    });

    codeInput.addEventListener("input", updateLineNumbers);
    codeInput.addEventListener("scroll", () => {
        lineNumbers.scrollTop = codeInput.scrollTop;
    });

    // Default code placeholder
    codeInput.value = `# Welcome to AI Code Reviewer & Security Auditor\n# Select a vulnerable sample from the dropdown above or paste code here.\n\nimport os\n\ndef run_query(user_id):\n    # Example: Select "Python: SQL Injection & Secrets" above to test\n    pass\n`;
    updateLineNumbers();
}

// -------------------------------------------------------------
// Tab Switching
// -------------------------------------------------------------
function initTabs() {
    const tabs = [
        { btn: "tab-btn-issues", content: "tab-content-issues" },
        { btn: "tab-btn-diff", content: "tab-content-diff" },
        { btn: "tab-btn-clean", content: "tab-content-clean" },
    ];

    tabs.forEach(({ btn, content }) => {
        const btnEl = document.getElementById(btn);
        btnEl.addEventListener("click", () => {
            tabs.forEach(t => {
                document.getElementById(t.btn).classList.remove("active", "text-cyan-400", "border-cyan-400");
                document.getElementById(t.btn).classList.add("text-gray-400", "border-transparent");
                document.getElementById(t.content).classList.add("hidden");
            });
            btnEl.classList.add("active", "text-cyan-400", "border-cyan-400");
            btnEl.classList.remove("text-gray-400", "border-transparent");
            document.getElementById(content).classList.remove("hidden");
        });
    });
}

// -------------------------------------------------------------
// AI Settings Modal
// -------------------------------------------------------------
function initSettingsModal() {
    const modal = document.getElementById("api-modal");
    const openBtn = document.getElementById("btn-toggle-api");
    const closeBtn = document.getElementById("btn-close-modal");
    const providerSelect = document.getElementById("setting-provider");
    const apiKeyGroup = document.getElementById("api-key-group");
    const apiKeyInput = document.getElementById("setting-api-key");
    const saveBtn = document.getElementById("btn-save-settings");

    // Load saved settings
    const savedProvider = localStorage.getItem("ai_provider") || "offline";
    const savedKey = localStorage.getItem("ai_key") || "";
    providerSelect.value = savedProvider;
    apiKeyInput.value = savedKey;

    if (savedProvider !== "offline") {
        apiKeyGroup.classList.remove("hidden");
    }

    openBtn.addEventListener("click", () => modal.classList.remove("hidden"));
    closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
    modal.addEventListener("click", (e) => {
        if (e.target === modal) modal.classList.add("hidden");
    });

    providerSelect.addEventListener("change", () => {
        if (providerSelect.value === "offline") {
            apiKeyGroup.classList.add("hidden");
        } else {
            apiKeyGroup.classList.remove("hidden");
        }
    });

    saveBtn.addEventListener("click", () => {
        localStorage.setItem("ai_provider", providerSelect.value);
        localStorage.setItem("ai_key", apiKeyInput.value);
        modal.classList.add("hidden");
    });
}

// -------------------------------------------------------------
// Sample Code Loading
// -------------------------------------------------------------
async function loadSamples() {
    try {
        const res = await fetch("/api/samples");
        sampleData = await res.json();
    } catch (err) {
        console.warn("Could not fetch preloaded samples:", err);
    }
}

// -------------------------------------------------------------
// Event Listeners & Actions
// -------------------------------------------------------------
function setupEventListeners() {
    const sampleSelect = document.getElementById("select-sample");
    const langSelect = document.getElementById("select-lang");
    const codeInput = document.getElementById("code-input");
    const scanBtn = document.getElementById("btn-scan");
    const clearBtn = document.getElementById("btn-clear-code");
    const applyFixBtn = document.getElementById("btn-apply-fix");
    const exportMdBtn = document.getElementById("btn-export-md");
    const exportJsonBtn = document.getElementById("btn-export-json");
    const copyCleanBtn = document.getElementById("btn-copy-clean");
    const fileUpload = document.getElementById("file-upload");
    const triggerUploadBtn = document.getElementById("btn-trigger-upload");

    sampleSelect.addEventListener("change", () => {
        const val = sampleSelect.value;
        if (val && sampleData[val]) {
            codeInput.value = sampleData[val].code;
            document.getElementById("label-filename").textContent = sampleData[val].filename;
            if (val.includes("python")) langSelect.value = "python";
            else if (val.includes("node")) langSelect.value = "javascript";
            else if (val.includes("java")) langSelect.value = "java";
            
            // Dispatch input event to refresh line numbers
            codeInput.dispatchEvent(new Event("input"));
            // Auto scan on sample load
            scanCode();
        }
    });

    clearBtn.addEventListener("click", () => {
        codeInput.value = "";
        document.getElementById("label-filename").textContent = "snippet";
        codeInput.dispatchEvent(new Event("input"));
        resetResults();
    });

    scanBtn.addEventListener("click", scanCode);

    applyFixBtn.addEventListener("click", () => {
        if (currentScanResult && currentScanResult.clean_code) {
            codeInput.value = currentScanResult.clean_code;
            codeInput.dispatchEvent(new Event("input"));
            scanCode(); // Re-scan clean code to show updated A+ score
        }
    });

    copyCleanBtn.addEventListener("click", () => {
        if (currentScanResult && currentScanResult.clean_code) {
            navigator.clipboard.writeText(currentScanResult.clean_code);
            copyCleanBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
            setTimeout(() => {
                copyCleanBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
            }, 2000);
        }
    });

    exportMdBtn.addEventListener("click", exportMarkdown);
    exportJsonBtn.addEventListener("click", exportJSON);

    triggerUploadBtn.addEventListener("click", () => fileUpload.click());
    fileUpload.addEventListener("change", handleFileUpload);
}

// -------------------------------------------------------------
// Scan Execution
// -------------------------------------------------------------
async function scanCode() {
    const code = document.getElementById("code-input").value;
    if (!code.trim()) {
        alert("Please paste some code to review.");
        return;
    }

    const scanBtn = document.getElementById("btn-scan");
    const statusText = document.getElementById("scan-status-text");
    const lang = document.getElementById("select-lang").value;
    const provider = localStorage.getItem("ai_provider") || "offline";
    const apiKey = localStorage.getItem("ai_key") || "";

    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-base"></i><span>Analyzing Code...</span>';
    statusText.textContent = "Running security checks...";

    try {
        const payload = {
            code: code,
            language: lang,
            filename: document.getElementById("label-filename").textContent || "snippet",
            use_llm: provider !== "offline" && !!apiKey,
            api_key: apiKey || null,
            provider: provider,
        };

        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Scan request failed");
        }

        const data = await res.json();
        currentScanResult = data;
        renderResults(data);
    } catch (err) {
        alert(`Scan failed: ${err.message}`);
        statusText.textContent = "Scan encountered an error.";
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart text-base"></i><span>Audit & Review Code</span>';
    }
}

// -------------------------------------------------------------
// Render Audit Findings & Score
// -------------------------------------------------------------
function renderResults(data) {
    const scoreVal = document.getElementById("score-val");
    const scoreGrade = document.getElementById("score-grade");
    const scoreCircle = document.getElementById("score-circle");
    const scanDuration = document.getElementById("scan-duration");
    const statusText = document.getElementById("scan-status-text");

    // Badges
    document.getElementById("badge-critical").textContent = data.counts_by_severity.CRITICAL || 0;
    document.getElementById("badge-high").textContent = data.counts_by_severity.HIGH || 0;
    document.getElementById("badge-medium").textContent = data.counts_by_severity.MEDIUM || 0;
    document.getElementById("badge-low").textContent = (data.counts_by_severity.LOW || 0) + (data.counts_by_severity.INFO || 0);

    // Score & Grade
    scoreVal.textContent = data.security_score;
    scoreGrade.textContent = data.health_grade;
    scanDuration.textContent = `${data.scan_duration_ms} ms`;
    statusText.textContent = `Completed audit: ${data.total_issues} issue(s) detected`;

    // Radial Gauge Color & Offset
    const offset = 100 - data.security_score;
    scoreCircle.setAttribute("stroke-dasharray", `${data.security_score}, 100`);

    if (data.security_score >= 85) {
        scoreCircle.setAttribute("class", "text-emerald-500 transition-all duration-1000 ease-out");
        scoreGrade.className = "text-[10px] font-bold text-emerald-400 px-1.5 py-0.2 bg-emerald-950/60 rounded";
    } else if (data.security_score >= 70) {
        scoreCircle.setAttribute("class", "text-yellow-500 transition-all duration-1000 ease-out");
        scoreGrade.className = "text-[10px] font-bold text-yellow-400 px-1.5 py-0.2 bg-yellow-950/60 rounded";
    } else {
        scoreCircle.setAttribute("class", "text-rose-500 transition-all duration-1000 ease-out");
        scoreGrade.className = "text-[10px] font-bold text-rose-400 px-1.5 py-0.2 bg-rose-950/60 rounded";
    }

    // Enable action buttons
    document.getElementById("btn-apply-fix").disabled = !data.clean_code || data.total_issues === 0;
    document.getElementById("btn-export-md").disabled = false;
    document.getElementById("btn-export-json").disabled = false;

    // Render Issues List
    document.getElementById("tab-issues-count").textContent = data.total_issues;
    const emptyMsg = document.getElementById("empty-issues-msg");
    const container = document.getElementById("issues-container");
    container.innerHTML = "";

    if (data.issues.length === 0) {
        emptyMsg.classList.remove("hidden");
        emptyMsg.querySelector("p").textContent = "Clean Code! No vulnerabilities found.";
    } else {
        emptyMsg.classList.add("hidden");
        data.issues.forEach((issue) => {
            container.appendChild(createIssueCard(issue));
        });
    }

    // Render Diff
    const diffContainer = document.getElementById("diff-container");
    if (data.diff) {
        diffContainer.innerHTML = formatDiff(data.diff);
    } else {
        diffContainer.textContent = "// No modifications required. Code is secure!";
    }

    // Render Clean Code
    const cleanContainer = document.getElementById("clean-code-container");
    cleanContainer.textContent = data.clean_code || "// Remediated code is identical to original.";
}

function createIssueCard(issue) {
    const card = document.createElement("div");
    card.className = "issue-card bg-[#161F30] border border-gray-800 rounded-xl p-3.5 space-y-2.5 text-xs";

    let severityClass = "bg-rose-950 text-rose-400 border-rose-800";
    if (issue.severity === "HIGH") severityClass = "bg-amber-950 text-amber-400 border-amber-800";
    else if (issue.severity === "MEDIUM") severityClass = "bg-yellow-950 text-yellow-400 border-yellow-800";
    else if (issue.severity === "LOW" || issue.severity === "INFO") severityClass = "bg-blue-950 text-blue-400 border-blue-800";

    card.innerHTML = `
        <div class="flex items-start justify-between gap-2">
            <div class="flex items-center gap-2 flex-wrap">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${severityClass}">${issue.severity}</span>
                <span class="font-semibold text-gray-100 text-xs">${issue.title}</span>
            </div>
            <span class="text-gray-500 font-mono text-[11px] whitespace-nowrap">Line ${issue.line_number}</span>
        </div>
        <p class="text-gray-400 text-xs leading-relaxed">${issue.description}</p>
        <div class="bg-[#0B0F19] rounded-lg p-2 font-mono text-[11px] text-rose-300 overflow-x-auto border border-gray-800/80">
            ${escapeHtml(issue.snippet)}
        </div>
        <div class="pt-1 flex items-center justify-between text-[11px] text-gray-500 border-t border-gray-800/60">
            <span class="text-cyan-400/80"><i class="fa-solid fa-tag mr-1"></i>${issue.cwe.split(':')[0]}</span>
            <span class="text-emerald-400/90 flex items-center gap-1">
                <i class="fa-solid fa-lightbulb"></i> Fix: ${issue.remediation.slice(0, 60)}...
            </span>
        </div>
    `;

    return card;
}

function formatDiff(diffText) {
    const lines = diffText.split("\n");
    let html = "";
    lines.forEach(line => {
        if (line.startsWith("+") && !line.startsWith("+++")) {
            html += `<span class="diff-add">${escapeHtml(line)}</span>\n`;
        } else if (line.startsWith("-") && !line.startsWith("---")) {
            html += `<span class="diff-del">${escapeHtml(line)}</span>\n`;
        } else if (line.startsWith("@@")) {
            html += `<span class="diff-chunk">${escapeHtml(line)}</span>\n`;
        } else {
            html += `<span>${escapeHtml(line)}</span>\n`;
        }
    });
    return html;
}

function resetResults() {
    currentScanResult = null;
    document.getElementById("score-val").textContent = "100";
    document.getElementById("score-grade").textContent = "A+";
    document.getElementById("score-circle").setAttribute("stroke-dasharray", "100, 100");
    document.getElementById("badge-critical").textContent = "0";
    document.getElementById("badge-high").textContent = "0";
    document.getElementById("badge-medium").textContent = "0";
    document.getElementById("badge-low").textContent = "0";
    document.getElementById("scan-status-text").textContent = "Ready for scan";
    document.getElementById("issues-container").innerHTML = "";
    document.getElementById("empty-issues-msg").classList.remove("hidden");
    document.getElementById("diff-container").textContent = "// No diff generated yet.";
    document.getElementById("clean-code-container").textContent = "// Remediated code will appear here after scanning.";
    document.getElementById("btn-apply-fix").disabled = true;
    document.getElementById("btn-export-md").disabled = true;
    document.getElementById("btn-export-json").disabled = true;
}

// -------------------------------------------------------------
// Export & File Upload Handling
// -------------------------------------------------------------
async function exportMarkdown() {
    if (!currentScanResult) return;
    try {
        const res = await fetch("/api/export/markdown", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(currentScanResult),
        });
        const text = await res.text();
        downloadBlob(text, `security-audit-${currentScanResult.filename}.md`, "text/markdown");
    } catch (err) {
        alert("Export failed: " + err.message);
    }
}

function exportJSON() {
    if (!currentScanResult) return;
    const jsonStr = JSON.stringify(currentScanResult, null, 2);
    downloadBlob(jsonStr, `security-audit-${currentScanResult.filename}.json`, "application/json");
}

function downloadBlob(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    const scanBtn = document.getElementById("btn-scan");
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-base"></i><span>Uploading & Scanning...</span>';

    try {
        const res = await fetch("/api/scan/file", {
            method: "POST",
            body: formData,
        });
        if (!res.ok) throw new Error("File scan failed");
        const data = await res.json();
        currentScanResult = data;

        // Read and populate editor
        const reader = new FileReader();
        reader.onload = (evt) => {
            const codeInput = document.getElementById("code-input");
            codeInput.value = evt.target.result;
            document.getElementById("label-filename").textContent = file.name;
            codeInput.dispatchEvent(new Event("input"));
            renderResults(data);
        };
        reader.readAsText(file);
    } catch (err) {
        alert("File scan failed: " + err.message);
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart text-base"></i><span>Audit & Review Code</span>';
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
