import React from 'react';
import { AlertTriangle, Brain, CheckCircle2, CircleOff, Gauge, ShieldCheck } from 'lucide-react';

const text = (value) => (value === null || value === undefined || value === '' ? 'n/a' : String(value));
const percent = (value) => (value === null || value === undefined ? 'n/a' : `${(Number(value) * 100).toFixed(1)}%`);
const number = (value) => (value === null || value === undefined ? 'n/a' : Number(value).toFixed(3));

export function modelStateLabel(model = {}) {
    if (!model.available) return 'Fallback active';
    if (model.state === 'legacy_compatibility') return 'Legacy compatibility';
    if (model.state === 'active_trained') return 'Active governed model';
    return 'Model state unavailable';
}

function MetricList({ metrics = {}, title }) {
    const perClass = metrics.per_class || [];
    return (
        <section className="panel">
            <div className="section-heading"><div><h2>{title}</h2></div><Gauge size={20} /></div>
            <div className="detail-grid">
                <span>Macro F1</span><strong>{number(metrics.macro_f1)}</strong>
                <span>Weighted F1</span><strong>{number(metrics.weighted_f1)}</strong>
                <span>Balanced accuracy</span><strong>{number(metrics.balanced_accuracy)}</strong>
                <span>False positive rate</span><strong>{percent(metrics.false_positive_rate)}</strong>
                <span>Brier score</span><strong>{number(metrics.brier_score)}</strong>
                <span>Calibration error</span><strong>{number(metrics.calibration_error)}</strong>
                <span>Inference latency</span><strong>{metrics.inference_latency_ms === null || metrics.inference_latency_ms === undefined ? 'n/a' : `${Number(metrics.inference_latency_ms).toFixed(2)} ms`}</strong>
            </div>
            {perClass.length > 0 && (
                <div className="table-wrap model-table-wrap">
                    <table className="alerts-table">
                        <thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead>
                        <tbody>{perClass.map((row) => (
                            <tr key={row.class}><td>{row.class}</td><td>{number(row.precision)}</td><td>{number(row.recall)}</td><td>{number(row.f1)}</td><td>{text(row.support)}</td></tr>
                        ))}</tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

function ValidationSummary({ model }) {
    const criteria = model.validation_result?.criteria || [];
    if (!criteria.length) return <div className="state-panel">No registry quality-gate validation is recorded for this model.</div>;
    return (
        <div className="compact-list">
            {criteria.map((criterion) => (
                <span key={criterion.name}>
                    <b>{criterion.passed ? 'Pass' : 'Fail'}: {criterion.name.replace(/_/g, ' ')}</b>
                    <em>{criterion.actual === null || criterion.actual === undefined ? 'n/a' : text(criterion.actual)}</em>
                </span>
            ))}
        </div>
    );
}

function DriftSummary({ drift = {} }) {
    const psi = drift.summary_psi;
    return (
        <section className="panel">
            <div className="section-heading"><div><h2>Production Drift</h2><span className="section-kicker">Population stability index on recent telemetry</span></div><AlertTriangle size={20} /></div>
            <div className="detail-grid">
                <span>State</span><strong>{text(drift.status)}</strong>
                <span>Sample window</span><strong>{text(drift.sample_window)}</strong>
                <span>Summary PSI</span><strong>{number(psi)}</strong>
                <span>Metric</span><strong>{text(drift.metric)}</strong>
            </div>
            {drift.reason && <div className="state-panel">{drift.reason}</div>}
        </section>
    );
}

function ModelMonitoring({ modelStatus }) {
    const model = modelStatus.model || {};
    const governance = modelStatus.governance || {};
    const active = governance.active_model;
    const statusLabel = modelStateLabel(model);
    const checksum = model.model_file_checksum ? `${model.model_file_checksum.slice(0, 12)}...` : 'n/a';
    const activeDetails = active?.metadata || {};

    return (
        <>
            <section className="panel">
                <div className="section-heading"><div><h2>Model Runtime</h2><span className="section-kicker">Serving state and artifact identity</span></div><Brain size={20} /></div>
                <div className="detail-grid">
                    <span>State</span><strong>{statusLabel}</strong>
                    <span>Version</span><strong>{text(model.model_version)}</strong>
                    <span>Mode</span><strong>{text(model.model_mode)}</strong>
                    <span>Checksum</span><strong>{checksum}</strong>
                    <span>Dataset</span><strong>{text(model.dataset_identifier)}</strong>
                    <span>Split</span><strong>{text(model.split_strategy)}</strong>
                    <span>Features</span><strong>{text(model.feature_count)}</strong>
                    <span>Sequence length</span><strong>{text(model.sequence_length)}</strong>
                </div>
                {model.fallback_reason && <div className="state-panel error-message">{model.fallback_reason}</div>}
            </section>

            <section className="panel">
                <div className="section-heading"><div><h2>Registry State</h2><span className="section-kicker">Promotion remains an explicit administrative action</span></div>{active ? <CheckCircle2 size={20} /> : <CircleOff size={20} />}</div>
                {!active && <div className="state-panel">No active registered model is available.</div>}
                {active && <>
                    <div className="detail-grid">
                        <span>Lifecycle</span><strong>{text(active.status)}</strong>
                        <span>Type</span><strong>{text(active.model_type)}</strong>
                        <span>Validated</span><strong>{active.validation_result?.passed ? 'passed' : 'not recorded'}</strong>
                        <span>Activated</span><strong>{text(active.activated_at)}</strong>
                    </div>
                    <ValidationSummary model={active} />
                </>}
            </section>

            <MetricList title="Validation Quality" metrics={model.validation_metrics || activeDetails.validation_metrics || {}} />
            <MetricList title="Held-out Test Quality" metrics={model.test_metrics || activeDetails.test_metrics || {}} />
            <DriftSummary drift={governance.drift || model.drift || {}} />
            <section className="panel">
                <div className="section-heading"><div><h2>Operational Scope</h2><span className="section-kicker">Known limits are carried with the artifact</span></div><ShieldCheck size={20} /></div>
                <div className="compact-list">
                    {(model.known_limitations || activeDetails.known_limitations || []).map((item) => <span key={item}><b>{item}</b></span>)}
                </div>
                {!(model.known_limitations || activeDetails.known_limitations || []).length && <div className="state-panel">No governed artifact limitations are available while the runtime is in fallback or legacy mode.</div>}
            </section>
        </>
    );
}

export default ModelMonitoring;
