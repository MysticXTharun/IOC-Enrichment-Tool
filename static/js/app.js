document.addEventListener("DOMContentLoaded", () => {
    document
        .getElementById("searchBtn")
        .addEventListener("click", enrichIOC);

    loadHistory();
});

async function loadHistory() {

    try {

        const response = await fetch("/history");
        const history = await response.json();

        const table = document.getElementById("historyTable");

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

    catch(err){

        console.error("History Error:", err);

    }

}

function riskBadge(risk){

    switch(risk){

        case "High":
            return "danger";

        case "Medium":
            return "warning";

        case "Low":
            return "info";

        case "Clean":
            return "success";

        default:
            return "secondary";

    }

}

function safe(value){

    if(value === undefined || value === null){

        return "N/A";

    }

    return value;

}

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

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Enrichment failed");
        }

        const summary = data.response.summary || {};

        const score = data.response.score || {
            verdict: "N/A",
            risk_score: 0,
            confidence: "N/A"
        };

        result.innerHTML = renderResult(data, summary, score);

        loadHistory();

    }

    catch (err) {

        result.innerHTML = `
            <div class="alert alert-danger">
                ${err.message}
            </div>
        `;

    }

}

function renderResult(data, summary, score) {

    return `
    <div class="card border-success shadow">

        <div class="card-header bg-success text-white">
            <h4>${data.ioc}</h4>
        </div>

        <div class="card-body">

            <div class="row mb-4">

                <div class="col-md-4">
                    <div class="card bg-dark text-white">
                        <div class="card-body">
                            <h6>IOC Type</h6>
                            <h4>${data.type}</h4>
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card bg-dark text-white">
                        <div class="card-body">
                            <h6>Risk</h6>
                            <h4>
                                <span class="badge bg-${riskBadge(summary.risk)}">
                                    ${safe(summary.risk)}
                                </span>
                            </h4>
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card bg-dark text-white">
                        <div class="card-body">
                            <h6>Verdict</h6>
                            <h4>${safe(score.verdict)}</h4>
                        </div>
                    </div>
                </div>

            </div>

            <div class="row mb-4">

                <div class="col-md-3">
                    <strong>Risk Score</strong>
                    <p>${safe(score.risk_score)}</p>
                </div>

                <div class="col-md-3">
                    <strong>Confidence</strong>
                    <p>${safe(score.confidence)}</p>
                </div>

                <div class="col-md-3">
                    <strong>Abuse Confidence</strong>
                    <p>${safe(summary.abuse_confidence)}</p>
                </div>

                <div class="col-md-3">
                    <strong>OTX Pulses</strong>
                    <p>${safe(summary.otx_pulses)}</p>
                </div>

            </div>

            <div class="row mb-4">

                <div class="col-md-6">
                    <strong>VirusTotal Malicious</strong>
                    <p>${safe(summary.malicious_engines)}</p>
                </div>

                <div class="col-md-6">
                    <strong>VirusTotal Suspicious</strong>
                    <p>${safe(summary.suspicious_engines)}</p>
                </div>

            </div>

            <hr>

            <details>

                <summary class="mb-3">
                    Raw Intelligence
                </summary>

                <pre style="max-height:500px;overflow:auto;">${JSON.stringify(data.response, null, 4)}</pre>

            </details>

        </div>

    </div>
    `;

}
