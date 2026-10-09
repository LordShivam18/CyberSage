import React, { useEffect, useState } from 'react';
import { simulatePolicy, fetchActionRegistry } from './guardianApi';
import { statusStyle, sharedStyles as s } from './formatters';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];

const SimulatePanel = ({ token, role }) => {
    const [registry, setRegistry] = useState([]);
    const [form, setForm] = useState({
        action_type: 'network',
        action_name: 'block_destination',
        target: '{"destination_ip": "203.0.113.66", "destination_port": 443}',
        risk_score: 75,
        incident_severity: 'high',
        incident_id: '',
        event_ids: '',
        correlation_id: '',
        persist: true,
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [result, setResult] = useState(null);

    useEffect(() => {
        if (!token) return;
        fetchActionRegistry(token).then((data) => setRegistry(data.actions || [])).catch(() => setRegistry([]));
    }, [token]);

    const canSimulate = role === 'administrator' || role === 'security_analyst' || role === 'incident_responder';

    const submit = async (event) => {
        event.preventDefault();
        setError('');
        setResult(null);
        let target;
        try {
            target = form.target.trim() ? JSON.parse(form.target) : {};
            if (typeof target !== 'object' || Array.isArray(target)) throw new Error('target must be a JSON object');
        } catch (err) {
            setError(`Invalid target JSON: ${err.message}`);
            return;
        }
        const payload = {
            action_type: form.action_type.trim(),
            action_name: form.action_name.trim(),
            target,
            risk_score: Number(form.risk_score),
            incident_severity: form.incident_severity,
            incident_id: form.incident_id === '' ? null : Number(form.incident_id),
            event_ids: form.event_ids.split(',').map((v) => v.trim()).filter(Boolean),
            correlation_id: form.correlation_id.trim() || null,
            persist: Boolean(form.persist),
        };
        setLoading(true);
        try {
            const data = await simulatePolicy(token, payload);
            setResult(data);
        } catch (err) {
            setError(err.status === 403 ? 'Your role cannot simulate (HTTP 403). Analyst, responder or administrator required.' : (err.message || 'Simulation failed.'));
        } finally {
            setLoading(false);
        }
    };

    if (!token) return <div style={s.empty}>Sign in to run policy simulations.</div>;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h2 style={s.title}>Policy Simulation (dry-run)</h2>
            <div style={s.error} role="note">
                SIMULATED OUTCOME ONLY — simulation never executes a process, blocks a destination, alters persistence,
                creates an approval, consumes execution quota, or modifies a kill switch. No execution is initiated from this panel.
            </div>
            {!canSimulate && (
                <div style={s.error} role="alert">
                    Your role ({role || 'unknown'}) cannot simulate. Simulation requires security_analyst, incident_responder or administrator.
                    The backend enforces this; the form is disabled.
                </div>
            )}
            {error && <div style={s.error} role="alert">{error}</div>}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
                <form style={{ ...s.panel, display: 'flex', flexDirection: 'column', gap: '10px' }} onSubmit={submit} aria-label="Simulation inputs">
                    <label style={s.label}>Action type
                        <input style={s.input} value={form.action_type} onChange={(e) => setForm({ ...form, action_type: e.target.value })} disabled={!canSimulate} required maxLength={64} list="action-types" />
                        <datalist id="action-types">
                            {registry.map((a) => <option key={`${a.action_type}:${a.action_name}`} value={a.action_type} />)}
                        </datalist>
                    </label>
                    <label style={s.label}>Action name
                        <input style={s.input} value={form.action_name} onChange={(e) => setForm({ ...form, action_name: e.target.value })} disabled={!canSimulate} required maxLength={64} list="action-names" />
                        <datalist id="action-names">
                            {registry.map((a) => <option key={`${a.action_type}:${a.action_name}`} value={a.action_name}>{a.action_type}:{a.action_name}</option>)}
                        </datalist>
                    </label>
                    <label style={s.label}>Target (JSON object)
                        <textarea style={{ ...s.input, fontFamily: 'monospace' }} rows={4} value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} disabled={!canSimulate} aria-describedby="target-help" />
                    </label>
                    <span id="target-help" style={s.muted}>Example: {"{"}"destination_ip": "203.0.113.66", "destination_port": 443{"}"}. Use documentation IPs only.</span>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                        <label style={s.label}>Risk score (0–100)
                            <input style={s.input} type="number" min={0} max={100} step="0.1" value={form.risk_score} onChange={(e) => setForm({ ...form, risk_score: e.target.value })} disabled={!canSimulate} required />
                        </label>
                        <label style={s.label}>Incident severity
                            <select style={s.input} value={form.incident_severity} onChange={(e) => setForm({ ...form, incident_severity: e.target.value })} disabled={!canSimulate}>
                                {SEVERITIES.map((sev) => <option key={sev} value={sev}>{sev}</option>)}
                            </select>
                        </label>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                        <label style={s.label}>Incident id (optional)
                            <input style={s.input} type="number" value={form.incident_id} onChange={(e) => setForm({ ...form, incident_id: e.target.value })} disabled={!canSimulate} />
                        </label>
                        <label style={s.label}>Correlation id (optional)
                            <input style={s.input} value={form.correlation_id} onChange={(e) => setForm({ ...form, correlation_id: e.target.value })} disabled={!canSimulate} maxLength={128} />
                        </label>
                    </div>
                    <label style={s.label}>Event ids (comma-separated, optional)
                        <input style={s.input} value={form.event_ids} onChange={(e) => setForm({ ...form, event_ids: e.target.value })} disabled={!canSimulate} />
                    </label>
                    <label style={{ ...s.muted, display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <input type="checkbox" checked={form.persist} onChange={(e) => setForm({ ...form, persist: e.target.checked })} disabled={!canSimulate} />
                        Persist simulation audit row (default true; uncheck for pure dry-run with no DB write)
                    </label>
                    <button style={{ ...s.btn, ...s.btnPrimary }} type="submit" disabled={loading || !canSimulate} aria-label="Run simulation">
                        {loading ? 'Simulating…' : 'Run simulation (no execution)'}
                    </button>
                </form>

                <section style={s.panel} aria-label="Simulation result" aria-live="polite">
                    <h3 style={s.title}>Result</h3>
                    {!result && <div style={s.empty}>No simulation yet. Submit the form to see the evaluated policy version, applicable rules, outcome and explanation.</div>}
                    {result && (
                        <>
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                                <span style={{ ...s.badge, ...statusStyle(result.decision) }}>SIMULATED: {result.decision}</span>
                                <span style={s.muted}>reason: {result.reason}</span>
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', marginTop: '12px', fontSize: '13px' }}>
                                <span style={s.muted}>Evaluation id</span><strong title={result.evaluation_id}>{result.evaluation_id}{result.existing ? ' (replay of existing audit row)' : ''}</strong>
                                <span style={s.muted}>Matched policy</span><strong>{result.matched_policy_id || 'none'} {result.matched_policy_version ? `v${result.matched_policy_version}` : ''}</strong>
                                <span style={s.muted}>Matched rule</span><strong>{result.matched_rule_id || 'none'}</strong>
                                <span style={s.muted}>Approval mode</span><strong>{result.approval_mode} · requires approval: {String(result.would_require_approval)}</strong>
                                <span style={s.muted}>Would execute</span><strong>{String(result.would_execute)} (always false for simulation)</strong>
                                <span style={s.muted}>Blocked reason</span><strong>{result.blocked_reason || 'n/a'}</strong>
                                <span style={s.muted}>Kill switch active</span><strong>{String(result.kill_switch_active ?? 'unknown')}</strong>
                                <span style={s.muted}>Evaluated policies</span><strong>{result.evaluated_policies} · candidates {result.candidate_rules} · specificity {result.scope_specificity}</strong>
                            </div>
                            <h4 style={{ color: '#E0E6ED', margin: '12px 0 6px 0' }}>Explanation</h4>
                            <p style={{ ...s.muted, color: '#C9D1D9' }}>{result.explanation}</p>
                            <h4 style={{ color: '#E0E6ED', margin: '12px 0 6px 0' }}>Safety checks relevant to the proposed outcome</h4>
                            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                                {(result.safety_checks || []).map((check) => (
                                    <span key={check} style={{ ...s.badge, color: '#8B949E', backgroundColor: 'rgba(139,148,158,0.15)' }}>{check}</span>
                                ))}
                            </div>
                            <div style={{ ...s.muted, marginTop: '10px' }}>
                                This simulated outcome must not be presented as a real execution. Use the evaluation id above only as an identity binding for a separately approved manual execution.
                            </div>
                        </>
                    )}
                </section>
            </div>
        </div>
    );
};

export default SimulatePanel;
