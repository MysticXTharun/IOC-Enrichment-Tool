// ================================
// IOC Enrichment Tool
// Part 1 - Initialization, Dashboard & History
// ================================

document.addEventListener("DOMContentLoaded", () => {
    loadDashboard();
    loadHistory();

    document
        .getElementById("searchBtn")
        .addEventListener("click", enrichIOC);
});

// -------------------------------
// Dashboard
// -------------------------------

async function loadDashboard() {

    try {

        const response = await fetch("/dashboard");

        if (!response.ok)
            throw new Error("Unable to load dashboard");

        const data = await response.json();

        document.getElementById("totalIOCs").textContent =
            data.total_iocs;

        document.getElementById("ipCount").textContent =
            data.ioc_types.ip;

        document.getElementById("urlCount").textContent =
            data.ioc_types.url;

        document.getElementById("hashCount").textContent =
            data.ioc_types.hash;

    }

    catch (err) {

        console.error("Dashboard Error:", err);

    }

}

// -------------------------------
// History
// -------------------------------

async function loadHistory() {

    try {

        const response = await fetch("/history");

        if (!response.ok)
            throw new Error("Unable to load history");

        const history = await response.json();

        const table = document.getElementById("historyTable");

        if (!table)
            return;

        table.innerHTML = "";

        history.forEach(item => {

            table.innerHTML += `
<tr>
    <td>${item.ioc}</td>
    <td>${item.type}</td>
    <td>${item.source}</td>
    <td>${new Date(item.created_at).toLocaleString()}</td>
</tr>
`;

        });

    }

    catch (err) {

        console.error("History Error:", err);

    }

}

// ================================
// Part 2 - IOC Enrichment
// ================================

async function enrichIOC() {

    const ioc = document.getElementById("iocInput").value.trim();

    if (!ioc) {

        alert("Please enter an IOC");

        return;

    }

    const result = document.getElementById("result");

    result.innerHTML = `
<div class="alert alert-info">
    Enriching IOC...
</div>
`;

    try {

        const response = await fetch("/enrich", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                ioc: ioc
            })

        });

        if (!response.ok)
            throw new Error("Enrichment failed");

        const data = await response.json();

        renderResult(data);

        loadHistory();

        loadDashboard();

    }

    catch (err) {

        result.innerHTML = `
<div class="alert alert-danger">
    ${err}
</div>
`;

    }

}

// -------------------------------
// Result Renderer
// -------------------------------

function renderResult(data) {

    const result = document.getElementById("result");

    const summary = data.response.summary || {};

    const score = data.response.score || {};

    result.innerHTML = `

<div class="card bg-dark text-white">

<div class="card-body">

<h3>${data.ioc}</h3>

<hr>

<div class="row">

<div class="col-md-4">

<h6>IOC Type</h6>

<h4>${data.type}</h4>

</div>

<div class="col-md-4">

<h6>Risk Verdict</h6>

<h4>${score.verdict ?? "Unknown"}</h4>

</div>

<div class="col-md-4">

<h6>Risk Score</h6>

<h4>${score.risk_score ?? "-"}</h4>

</div>

</div>

<hr>

<div class="row">

<div class="col-md-3">

<h6>Risk</h6>

<p>${summary.risk ?? "-"}</p>

</div>

<div class="col-md-3">

<h6>Abuse Score</h6>

<p>${summary.abuse_confidence ?? "-"}</p>

</div>

<div class="col-md-3">

<h6>VT Malicious</h6>

<p>${summary.malicious_engines ?? "-"}</p>

</div>

<div class="col-md-3">

<h6>OTX Pulses</h6>

<p>${summary.otx_pulses ?? "-"}</p>

</div>

</div>

<hr>

<details>

<summary class="mb-3">

Raw Intelligence

</summary>

<pre style="max-height:500px;overflow:auto;">
${JSON.stringify(data.response, null, 4)}
</pre>

</details>

</div>

</div>

`;

}

// ================================
// Part 3 - Helper Functions
// ================================

// Press Enter to search

const iocInput = document.getElementById("iocInput");

if (iocInput) {

    iocInput.addEventListener("keypress", function (event) {

        if (event.key === "Enter") {

            enrichIOC();

        }

    });

}

// -------------------------------
// Utility
// -------------------------------

function showAlert(message, type = "info") {

    const result = document.getElementById("result");

    result.innerHTML = `
<div class="alert alert-${type}">
    ${message}
</div>
`;

}

// -------------------------------
// Console Banner
// -------------------------------

console.log(
    "%cIOC Enrichment Tool Loaded",
    "color:lime;font-size:14px;font-weight:bold;"
);
