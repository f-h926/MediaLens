import { useState } from "react";
import "./App.css";


function App() {

  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // submit the URL to the backend for analysis and risk assessment

  async function handleSubmit(event) {

    event.preventDefault();

    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {

      const response = await fetch(
        "http://127.0.0.1:5000/api/scan",
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json"
          },

          body: JSON.stringify({
            url: url.trim()
          })
        }
      );


      const data = await response.json();

      console.log("Flask response:", data);


      if (!response.ok) {

        throw new Error(
          data.error || "Unable to analyse URL."
        );

      }


      if (!data.analysis || !data.risk) {

        throw new Error(
          "MediaLens received an incomplete response."
        );

      }


      setResult(data);

    }

    catch (error) {

      console.error(error);

      setError(error.message);

    }

    finally {

      setLoading(false);

    }
  }

  // page layout and structure, including the masthead, URL scanner form, and results display.

  return (

    <main className="page">

      {/* Masthead */}

      <header className="masthead">

        <p className="edition">
          DIGITAL SECURITY • MEDIA INTELLIGENCE
        </p>

        <h1>MediaLens</h1>

        <p className="tagline">
          Cyber Safety for All Things Media
        </p>

      </header>

      {/* URL Scanner */}

      <section className="scanner">

        <p className="kicker">Check the Link Before the Click</p>

        <form
          className="scan-form"
          onSubmit={handleSubmit}
        >

          <input
            type="text"
            placeholder="Enter a URL..."
            value={url}
            onChange={(event) =>
              setUrl(event.target.value)
            }
          />

          <button
            type="submit"
            disabled={loading}
          >

            {loading
              ? "Scanning..."
              : "Scan"}

          </button>

        </form>

        {error && (

          <p className="error">
            {error}
          </p>

        )}

      </section>

      {/* Results Display */}

      {result &&
        result.analysis &&
        result.risk && (

        <section className="results">

          {/* Risk Assessment */}

          <section className="risk-hero">

            <div>

              <p className="section-label">
                Risk Assessment
              </p>

              <div className="risk-score">
                <span>
                  {result.risk.score ?? 0}
                </span>
                <small>
                  / 100
                </small>
              </div>

              <p className="risk-level">
                {result.risk.level ?? "Unknown"}
              </p>

            </div>

            <div className="risk-meta">

              <p>
                <strong>Local URL Score</strong>
                <span>
                  {result.local_risk?.score ?? 0}
                  {" / 100"}
                </span>
              </p>

              <p>
                <strong>Threat Intelligence</strong>
                <span>
                  {result.risk
                    .threat_intelligence_used
                    ? "Included"
                    : "Not Available"}
                </span>
              </p>

              <p>
                <strong>Analysed Host</strong>
                <span>
                  {result.analysis.hostname}
                </span>
              </p>

            </div>

          </section>

          {/* Risk Breakdown */}

          <section className="report-section">

            <p className="section-label">
              Analysis
            </p>

            <h2>Risk Breakdown</h2>

            {(result.risk.reasons ?? [])
              .length > 0 ? (

              result.risk.reasons.map(
                (reason, index) => (

                <p key={index}>
                  <strong>
                    +{reason.score}
                  </strong>

                  {" — "}

                  {reason.reason}

                </p>

              ))

            ) : (

              <p>No URL-based risk indicators contributed to the current score.</p>

            )}

          </section>



          {/* Local Analysis */}  

          <section className="report-section">

            <p className="section-label">
              Local Analysis
            </p>

            <h2>
              Security Findings
            </h2>

            {(result.analysis.findings ?? [])
              .map((finding, index) => (

              <article
                className={
                  `finding finding-${finding.severity}`
                }
                key={index}
              >

                <h3>
                  {finding.severity
                    ?.toUpperCase()}

                  {" / "}
                  {finding.title}
                </h3>

                <p>
                  {finding.description}
                </p>

              </article>

            ))}

          </section>

          {/* External Intelligence */}

          <section className="report-section">

            <p className="section-label">
              External Intelligence
            </p>

            <h2>
              Threat Intelligence
            </h2>

            {/* VirusTotal */}

            <article className="intelligence-source">

              <h3>
                VirusTotal
              </h3>

              {!result
                .threat_intelligence
                ?.virustotal
                ?.available ? (

                <p>
                  VirusTotal unavailable:{" "}
                  {result
                    .threat_intelligence
                    ?.virustotal
                    ?.error
                    ?? "Unknown error"}
                </p>

              ) : !result
                .threat_intelligence
                .virustotal
                .found ? (

                <p>No existing VirusTotal report was found for this URL.</p>

              ) : (

                <div className="intelligence-data">

                  <p>
                    <strong>Malicious</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .virustotal
                        .stats
                        ?.malicious ?? 0}
                    </span>
                  </p>

                  <p>
                    <strong>Suspicious</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .virustotal
                        .stats
                        ?.suspicious ?? 0}
                    </span>
                  </p>

                  <p>
                    <strong>Harmless</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .virustotal
                        .stats
                        ?.harmless ?? 0}
                    </span>
                  </p>

                  <p>
                    <strong>Undetected</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .virustotal
                        .stats
                        ?.undetected ?? 0}
                    </span>
                  </p>

                  <p>
                    <strong>Reputation</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .virustotal
                        .reputation ?? 0}
                    </span>
                  </p>

                </div>

              )}

            </article>

            {/* URLhaus */}

            <article className="intelligence-source">

              <h3>
                URLhaus
              </h3>

              {!result
                .threat_intelligence
                ?.urlhaus
                ?.available ? (

                <p>
                  URLhaus unavailable:{" "}
                  {result
                    .threat_intelligence
                    ?.urlhaus
                    ?.error
                    ?? "Unknown error"}
                </p>

              ) : !result
                .threat_intelligence
                .urlhaus
                .found ? (

                <p>No URLhaus malware record was found for this URL.</p>

              ) : (

                <div className="intelligence-data">

                  <p>
                    <strong>Database Match</strong>
                    <span>
                      Yes
                    </span>
                  </p>

                  <p>
                    <strong>Status</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .urlhaus
                        .url_status
                        ?? "Unknown"}
                    </span>
                  </p>

                  <p>
                    <strong>Threat</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .urlhaus
                        .threat
                        ?? "Unknown"}
                    </span>
                  </p>

                  <p>
                    <strong>Tags</strong>
                    <span>
                      {(result
                        .threat_intelligence
                        .urlhaus
                        .tags ?? [])
                        .join(", ")
                        || "None"}
                    </span>
                  </p>

                  <p>
                    <strong>Date Added</strong>
                    <span>
                      {result
                        .threat_intelligence
                        .urlhaus
                        .date_added
                        ?? "Unknown"}
                    </span>
                  </p>

                </div>

              )}

            </article>

          </section>

          {/* Technical Details */}

          <section className="report-section">

            <p className="section-label">URL Examination</p>

            <h2>
              Technical Details
            </h2>

            <div className="technical-data">

              <p>
                <strong>URL</strong>
                <span>
                  {result.analysis.url}
                </span>
              </p>

              <p>
                <strong>Hostname</strong>
                <span>
                  {result.analysis.hostname}
                </span>
              </p>

              <p>
                <strong>Protocol</strong>
                <span>
                  {result.analysis.scheme}
                </span>
              </p>

              <p>
                <strong>HTTPS</strong>
                <span>
                  {result.analysis.uses_https
                    ? "Yes"
                    : "No"}
                </span>
              </p>

              <p>
                <strong>IP Address URL</strong>
                <span>
                  {result.analysis.is_ip_address
                    ? "Yes"
                    : "No"}
                </span>
              </p>

              <p>
                <strong>Private IP</strong>
                <span>
                  {result.analysis.is_private_ip
                    ? "Yes"
                    : "No"}
                </span>
              </p>

              <p>

                <strong>Punycode</strong>
                <span>
                  {result.analysis.uses_punycode
                    ? "Yes"
                    : "No"}
                </span>
              </p>

              <p>
                <strong>@ Symbol</strong>
                <span>
                  {result.analysis
                    .contains_at_symbol
                    ? "Yes"
                    : "No"}
                </span>
              </p>

              <p>
                <strong>Excessive Subdomains</strong>
                <span>
                  {result.analysis
                    .excessive_subdomains
                    ? "Yes"
                    : "No"}
                </span>
              </p>

              <p>
                <strong>URL Length</strong>
                <span>
                  {result.analysis.url_length}
                </span>
              </p>

              <p>
                <strong>Suspicious Keywords</strong>
                <span>
                  {(result.analysis
                    .keyword_matches ?? [])
                    .join(", ")
                    || "None"}
                </span>
              </p>

            </div>

          </section>

          {/* Foot note */}

          <footer className="report-footer">

            <p>
              MediaLens combines URL characteristics
              with external threat intelligence to
              provide a risk score.
              However, the score is not a statistical probability
              that a website is malicious.
            </p>

          </footer>

        </section>

      )}

    </main>

  );

}

export default App;