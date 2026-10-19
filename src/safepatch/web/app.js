const state = {
  scenario: "clean",
  report: null,
  busy: false,
};

const $ = (id) => document.getElementById(id);

function setText(id, value) {
  $(id).textContent = value;
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function clear(element) {
  element.replaceChildren();
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || "The demo server returned an error.");
  return value;
}

function log(message) {
  setText("activity-log", message);
}

function setBusy(busy) {
  state.busy = busy;
  $("scan-button").disabled = busy;
  $("scan-button").textContent = busy ? "Scanning…" : "↗  Run demo scan";
}

function setDecisionStyle(element, decision) {
  element.classList.remove("review", "block");
  if (decision === "review" || decision === "block") element.classList.add(decision);
}

function renderFinding(finding) {
  const item = node("article", "finding");
  const top = node("div", "finding-top");
  top.append(
    node("strong", "finding-rule", finding.rule || finding.category || "Finding"),
    node("span", `severity severity-${finding.severity || "low"}`, (finding.severity || "low").toUpperCase()),
  );
  item.append(top, node("p", "finding-message", finding.message || "No message provided."));
  if (finding.path) {
    const location = finding.line ? `${finding.path}:${finding.line}` : finding.path;
    item.append(node("div", "finding-location", location));
  }
  return item;
}

function renderFindings(report) {
  const list = $("finding-list");
  const empty = $("findings-empty");
  clear(list);
  setText("finding-count", String(report.findings.length));
  if (!report.findings.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  report.findings.forEach((finding) => list.append(renderFinding(finding)));
}

function commandStatus(command) {
  if (command.decision === "block") return "block";
  if (command.decision === "review") return "review";
  return "allow";
}

function renderCommand(command) {
  const row = node("article", `command-row ${commandStatus(command)}`);
  const details = node("div");
  details.append(node("div", "command-id", command.command_id));
  details.append(node("code", "command-code", command.argv.join(" ")));
  if (command.reason) details.append(node("div", "command-reason", command.reason));

  const actions = node("div", "command-actions");
  const badge = node("span", `decision-badge ${commandStatus(command)}`, command.decision.toUpperCase());
  actions.append(badge);

  if (command.decision === "block") {
    actions.append(node("span", "command-reason", "Not executable"));
  } else if (command.execution && command.execution.status) {
    const status = command.execution.status === "confirmed" ? "Completed" : command.execution.status;
    actions.append(node("span", "decision-badge", status.toUpperCase()));
  } else if (command.decision === "review" && command.approval_status !== "approved") {
    const approve = node("button", "mini-button", "Approve");
    approve.type = "button";
    approve.addEventListener("click", () => approveCommand(command.command_id));
    actions.append(approve);
  } else {
    const run = node("button", "mini-button", "Run command");
    run.type = "button";
    run.addEventListener("click", () => runCommand(command.command_id));
    actions.append(run);
  }

  row.append(details, actions);
  return row;
}

function renderCommands(report) {
  const list = $("command-list");
  clear(list);
  if (!report.commands.length) {
    list.append(node("div", "empty-state command-empty", "No commands were found in this plan."));
    return;
  }
  report.commands.forEach((command) => list.append(renderCommand(command)));
}

function updateWorkflow(report) {
  let completed = 1;
  if (report.commands.some((command) => command.approval_status === "approved")) completed = 2;
  if (report.execution_results.length) completed = 3;
  document.querySelectorAll(".workflow-step").forEach((step, index) => {
    step.classList.toggle("active", index <= completed);
  });
}

function renderReport(report) {
  state.report = report;
  const decision = report.decision;
  const decisionValue = $("decision-value");
  setText("decision-value", decision);
  setDecisionStyle(decisionValue, decision);
  setText("decision-caption", decision === "allow" ? "No blocking evidence detected." : decision === "review" ? "Human approval is required." : "A command was stopped by policy.");
  setText("findings-value", String(report.findings_count));
  setText("blocked-value", String(report.blocked_commands));
  setText("integrity-value", report.report_valid ? "VALID" : "INVALID");
  setText("hash-caption", `${report.report_hash.slice(0, 16)}…`);
  setText("command-context", `${report.scenario} plan · ${report.scanned_files} files scanned`);
  setText("report-status", report.report_valid ? "Report integrity valid" : "Report integrity failed");
  $("report-dot").className = `status-dot ${report.report_valid ? "" : "muted"}`;
  $("verify-button").hidden = false;
  renderFindings(report);
  renderCommands(report);
  updateWorkflow(report);
  log(report.output || "Scan complete.");
}

async function scan() {
  if (state.busy) return;
  setBusy(true);
  log(`Scanning the ${state.scenario} plan… SafePatch will not execute commands during this step.`);
  try {
    const report = await request("/api/scans", {
      method: "POST",
      body: JSON.stringify({ scenario: state.scenario }),
    });
    renderReport(report);
  } catch (error) {
    log(`Error: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

async function approveCommand(commandId) {
  if (!state.report) return;
  try {
    const report = await request(`/api/scans/${state.report.scan_id}/approve`, {
      method: "POST",
      body: JSON.stringify({ command_id: commandId }),
    });
    renderReport(report);
    log(`${commandId} approved. The approval is bound to this exact plan and repository snapshot.`);
  } catch (error) {
    log(`Approval error: ${error.message}`);
  }
}

async function runCommand(commandId) {
  if (!state.report) return;
  try {
    const report = await request(`/api/scans/${state.report.scan_id}/run`, {
      method: "POST",
      body: JSON.stringify({ command_id: commandId }),
    });
    renderReport(report);
    const command = report.commands.find((item) => item.command_id === commandId);
    const execution = command && command.execution;
    log(execution ? `${commandId}: ${execution.status.toUpperCase()} (exit code ${execution.exit_code}).` : `${commandId} finished.`);
  } catch (error) {
    log(`Execution error: ${error.message}`);
  }
}

async function verifyReport() {
  if (!state.report) return;
  try {
    const result = await request(`/api/scans/${state.report.scan_id}/verify`);
    setText("report-status", result.valid ? "Report integrity valid" : "Report integrity failed");
    log(result.valid ? "Report hash verified. No tampering detected." : "Report hash verification failed.");
  } catch (error) {
    log(`Verification error: ${error.message}`);
  }
}

document.querySelectorAll(".scenario-card").forEach((card) => {
  card.addEventListener("click", () => {
    state.scenario = card.dataset.scenario;
    document.querySelectorAll(".scenario-card").forEach((item) => item.classList.toggle("selected", item === card));
    log(`${state.scenario} plan selected. Click “Run demo scan” to inspect it.`);
  });
});

$("scan-button").addEventListener("click", scan);
$("verify-button").addEventListener("click", verifyReport);
