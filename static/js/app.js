document.getElementById("searchBtn").addEventListener("click", enrichIOC);

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

        const summary = data.response.summary;
        const score = data.response.score;

        let badge = "secondary";

        if (score.verdict === "Clean")
            badge = "success";

        if (score.verdict === "Low")
            badge = "info";

        if (score.verdict === "Suspicious")
            badge = "warning";

        if (score.verdict === "Malicious")
            badge = "danger";

        result.innerHTML = `

<div class="card shadow bg-secondary border-0">

<div class="card-body">

<h2 class="mb-4">${data.ioc}</h2>

<span class="badge bg-${badge} fs-5">
${score.verdict}
</span>

<hr>

<h5>Risk Score</h5>

<div class="progress mb-3" style="height:30px;">

<div
class="progress-bar bg-${badge}"
style="width:${score.risk_score}%">

${score.risk_score}/100

</div>

</div>

<div class="row">

<div class="col-md-4">

<div class="card bg-dark">

<div class="card-body">

<h6>Confidence</h6>

<h4>${score.confidence}</h4>

</div>

</div>

</div>

<div class="col-md-4">

<div class="card bg-dark">

<div class="card-body">

<h6>Risk</h6>

<h4>${summary.risk}</h4>

</div>

</div>

</div>

<div class="col-md-4">

<div class="card bg-dark">

<div class="card-body">

<h6>IOC Type</h6>

<h4>${data.type}</h4>

</div>

</div>

</div>

</div>

<hr>

<div class="row">

<div class="col-md-4">

<h6>Abuse Confidence</h6>

<p>${summary.abuse_confidence}</p>

</div>

<div class="col-md-4">

<h6>VirusTotal</h6>

<p>${summary.malicious_engines} malicious</p>

</div>

<div class="col-md-4">

<h6>OTX Pulses</h6>

<p>${summary.otx_pulses}</p>

</div>

</div>

<hr>

<details>

<summary class="mb-3">

Raw Intelligence

</summary>

<pre style="max-height:500px;overflow:auto;">

${JSON.stringify(data.response,null,4)}

</pre>

</details>

</div>

</div>

`;

    }

    catch(err){

        result.innerHTML = `
            <div class="alert alert-danger">
                ${err}
            </div>
        `;

    }

}
