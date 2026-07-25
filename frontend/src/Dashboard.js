import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
    Activity,
    AlertTriangle,
    Bell,
    Brain,
    Database,
    Eye,
    Lock,
    LogIn,
    RefreshCcw,
    Search,
    Server,
    ShieldCheck,
    UserCheck,
    Wifi,
} from 'lucide-react';
import {
    fetchAlertPage,
    fetchEvents,
    fetchIncidents,
    fetchMetrics,
    fetchModelStatus,
    alertWebSocketUrl,
    login,
    updateAlert,
    updateIncident,
} from './apiService';
import AlertsTable from './components/AlertsTable';
import PredictionForm from './components/PredictionForm';
import './Dashboard.css';

const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'alerts', label: 'Alerts', icon: Bell },
    { id: 'incidents', label: 'Incidents', icon: AlertTriangle },
    { id: 'events', label: 'Events', icon: Database },
    { id: 'model', label: 'Model', icon: Brain },
];

const emptyPage = { total: 0, items: [] };

const fmt = (value) => {
    if (value === null || value === undefined || value === '') return 'n/a';
    return value;
};

const pct = (value) => `${(Number(value || 0) * 100).toFixed(1)}%`;

function MetricTile({ icon: Icon, label, value, tone }) {
    return (
        <div className={`metric-tile ${tone || ''}`}>
            <Icon size={18} />
            <span>{label}</span>
            <strong>{value}</strong>
        </div>
    );
}

function SectionHeading({ title, kicker, icon: Icon }) {
    return (
        <div className="section-heading">
            <div>
                <h2>{title}</h2>
                {kicker && <span className="section-kicker">{kicker}</span>}
            </div>
            {Icon && <Icon size={20} />}
        </div>
    );
}

function AuthPanel({ user, onLogin, authError }) {
    const [credentials, setCredentials] = useState({ username: '', password: '' });
    const [busy, setBusy] = useState(false);

    const submit = async (event) => {
        event.preventDefault();
        setBusy(true);
        await onLogin(credentials);
        setBusy(false);
    };

    if (user) {
        return (
            <div className="auth-state">
                <UserCheck size={16} />
                <span>{user.username}</span>
                <small>{user.role}</small>
            </div>
        );
    }

    return (
        <form className="auth-form" onSubmit={submit}>
            <Lock size={16} />
            <input
                aria-label="Username"
                placeholder="Username"
                value={credentials.username}
                onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
            />
            <input
                aria-label="Password"
                placeholder="Password"
                type="password"
                value={credentials.password}
                onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
            />
            <button type="submit" disabled={busy} title="Sign in for analyst actions">
                <LogIn size={16} />
            </button>
            {authError && <span className="inline-error">{authError}</span>}
        </form>
    );
}

function Overview({ metrics, alerts, incidents }) {
    const severityEntries = Object.entries(metrics.alerts_by_severity || {});
    const classEntries = Object.entries(metrics.top_attack_classes || {}).filter(([key]) => key);
    const sourceEntries = Object.entries(metrics.detection_sources || {});
    const maxSeverity = Math.max(...severityEntries.map(([, value]) => value), 1);

    return (
        <div className="view-grid">
            <section className="panel wide">
                <SectionHeading title="SOC Overview" kicker="Live posture from normalized detections" icon={ShieldCheck} />
                <div className="metric-grid">
                    <MetricTile icon={AlertTriangle} label="Active incidents" value={metrics.active_incidents || 0} tone="danger" />
                    <MetricTile icon={Bell} label="Alerts" value={metrics.total_alerts || 0} />
                    <MetricTile icon={Wifi} label="False positive rate" value={pct(metrics.false_positive_rate)} />
                    <MetricTile icon={Brain} label="Avg inference ms" value={Number(metrics.model_monitoring?.inference_latency_ms_latest || 0).toFixed(1)} />
                </div>
            </section>

            <section className="panel">
                <SectionHeading title="Alerts By Severity" />
                <div className="bar-list">
                    {severityEntries.length === 0 && <div className="state-panel">No alerts yet.</div>}
                    {severityEntries.map(([severity, count]) => (
                        <div className="bar-row" key={severity}>
                            <span>{severity}</span>
                            <div><i style={{ width: `${Math.max(8, (count / maxSeverity) * 100)}%` }} /></div>
                            <strong>{count}</strong>
                        </div>
                    ))}
                </div>
            </section>

            <section className="panel">
                <SectionHeading title="Top Attack Classes" />
                <div className="compact-list">
                    {classEntries.length === 0 && <div className="state-panel">No attack classifications yet.</div>}
                    {classEntries.slice(0, 6).map(([name, count]) => (
                        <span key={name}><b>{name}</b><em>{count}</em></span>
                    ))}
                </div>
            </section>

            <section className="panel">
                <SectionHeading title="Detection Mix" />
                <div className="compact-list">
                    {sourceEntries.map(([name, count]) => (
                        <span key={name}><b>{name.replace(/_/g, ' ')}</b><em>{count}</em></span>
                    ))}
                </div>
            </section>

            <section className="panel">
                <SectionHeading title="Recent Incidents" />
                <div className="queue-list">
                    {incidents.slice(0, 5).map(incident => (
                        <article key={incident.id}>
                            <strong>{incident.title}</strong>
                            <span>{incident.status} | {incident.severity}</span>
                        </article>
                    ))}
                    {!incidents.length && <div className="state-panel">No correlated incidents.</div>}
                </div>
            </section>

            <section className="panel wide">
                <SectionHeading title="Detection Volume" kicker="Latest alerts by arrival time" />
                <div className="timeline-strip">
                    {alerts.slice(0, 18).reverse().map(alert => (
                        <span
                            key={alert.id}
                            className={`severity-${alert.severity || 'low'}`}
                            title={`${alert.classification || alert.prediction} ${new Date(alert.timestamp).toLocaleString()}`}
                        />
                    ))}
                    {!alerts.length && <div className="state-panel">No alert volume to show yet.</div>}
                </div>
            </section>
        </div>
    );
}

function AlertDetails({ alert, onAction, permissionError }) {
    if (!alert) return <div className="state-panel">Select an alert to inspect evidence.</div>;
    return (
        <aside className="detail-pane">
            <SectionHeading title="Alert Details" kicker={`Risk score ${alert.risk_score ?? 'n/a'}`} icon={Eye} />
            {permissionError && <div className="state-panel error-message">{permissionError}</div>}
            <div className="detail-grid">
                <span>Classification</span><strong>{alert.classification || alert.prediction}</strong>
                <span>Status</span><strong>{alert.status}</strong>
                <span>Severity</span><strong>{alert.severity}</strong>
                <span>Route</span><strong>{fmt(alert.source_ip)} to {fmt(alert.destination_ip)}</strong>
                <span>Confidence</span><strong>{pct(alert.confidence ?? alert.probability)}</strong>
                <span>Anomaly</span><strong>{alert.anomaly_score !== null ? Number(alert.anomaly_score || 0).toFixed(2) : 'n/a'}</strong>
            </div>
            <h3>Risk Components</h3>
            <div className="component-grid">
                {Object.entries(alert.risk_components || {}).map(([name, value]) => (
                    <span key={name}><b>{name.replace(/_/g, ' ')}</b><em>{value}</em></span>
                ))}
            </div>
            <h3>Triggered Rules</h3>
            <div className="tag-row">
                {(alert.triggered_rules || []).map(rule => <span key={rule.id}>{rule.name}</span>)}
                {!(alert.triggered_rules || []).length && <small>No rule triggers.</small>}
            </div>
            <h3>MITRE ATT&CK</h3>
            <div className="tag-row">
                {(alert.mitre_techniques || []).map(technique => <span key={technique}>{technique}</span>)}
                {!(alert.mitre_techniques || []).length && <small>No mapping available.</small>}
            </div>
            <h3>Investigation Actions</h3>
            <ul className="action-list">
                {(alert.investigation_actions || []).map(action => <li key={action}>{action}</li>)}
            </ul>
            <div className="action-buttons">
                <button onClick={() => onAction(alert.id, { status: 'acknowledged' })}>Acknowledge</button>
                <button onClick={() => onAction(alert.id, { status: 'investigating' })}>Investigate</button>
                <button onClick={() => onAction(alert.id, { status: 'false_positive', resolution_reason: 'Analyst marked as false positive' })}>False Positive</button>
            </div>
        </aside>
    );
}

function IncidentsView({ incidents, selectedIncident, setSelectedIncident, onAction, permissionError }) {
    return (
        <div className="split-view">
            <section className="panel">
                <SectionHeading title="Incident Queue" icon={AlertTriangle} />
                <div className="queue-list selectable">
                    {incidents.map(incident => (
                        <article
                            key={incident.id}
                            className={selectedIncident?.id === incident.id ? 'selected-card' : ''}
                            onClick={() => setSelectedIncident(incident)}
                        >
                            <strong>{incident.title}</strong>
                            <span>{incident.status} | {incident.severity} | {incident.alerts?.length || 0} alerts</span>
                        </article>
                    ))}
                    {!incidents.length && <div className="state-panel">No incidents have been correlated.</div>}
                </div>
            </section>
            <section className="panel">
                <SectionHeading title="Incident Details" />
                {permissionError && <div className="state-panel error-message">{permissionError}</div>}
                {!selectedIncident && <div className="state-panel">Select an incident to triage.</div>}
                {selectedIncident && (
                    <>
                        <div className="detail-grid">
                            <span>Status</span><strong>{selectedIncident.status}</strong>
                            <span>Priority</span><strong>{selectedIncident.priority}</strong>
                            <span>Assignee</span><strong>{fmt(selectedIncident.assignee)}</strong>
                            <span>Attack family</span><strong>{fmt(selectedIncident.attack_family)}</strong>
                            <span>First seen</span><strong>{new Date(selectedIncident.first_seen).toLocaleString()}</strong>
                            <span>Last seen</span><strong>{new Date(selectedIncident.last_seen).toLocaleString()}</strong>
                        </div>
                        <h3>Related Indicators</h3>
                        <div className="tag-row">
                            {(selectedIncident.indicators || []).map(item => <span key={item}>{item}</span>)}
                        </div>
                        <div className="action-buttons">
                            <button onClick={() => onAction(selectedIncident.id, { status: 'triaged' })}>Triage</button>
                            <button onClick={() => onAction(selectedIncident.id, { status: 'investigating' })}>Investigate</button>
                            <button onClick={() => onAction(selectedIncident.id, { status: 'resolved', resolution_reason: 'Resolved by analyst workflow' })}>Resolve</button>
                        </div>
                    </>
                )}
            </section>
        </div>
    );
}

function EventsView({ events, selectedEvent, setSelectedEvent }) {
    return (
        <div className="split-view events-view">
            <section className="panel">
                <SectionHeading title="Event Explorer" icon={Database} />
                <div className="table-wrap">
                    <table className="alerts-table">
                        <thead>
                            <tr>
                                <th>Sensor</th>
                                <th>Protocol</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Bytes</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {events.map(event => (
                                <tr key={event.event_id} onClick={() => setSelectedEvent(event)} className={selectedEvent?.event_id === event.event_id ? 'selected-row' : ''}>
                                    <td>{event.sensor_type}</td>
                                    <td>{fmt(event.protocol)}</td>
                                    <td>{fmt(event.source_ip)}:{fmt(event.source_port)}</td>
                                    <td>{fmt(event.destination_ip)}:{fmt(event.destination_port)}</td>
                                    <td>{Number((event.bytes_sent || 0) + (event.bytes_received || 0)).toLocaleString()}</td>
                                    <td>{new Date(event.timestamp).toLocaleString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {!events.length && <div className="state-panel">No normalized events are stored yet.</div>}
            </section>
            <section className="panel">
                <SectionHeading title="Raw And Normalized" />
                {!selectedEvent && <div className="state-panel">Select an event to inspect.</div>}
                {selectedEvent && <pre className="json-block">{JSON.stringify(selectedEvent.normalized || selectedEvent.raw_event, null, 2)}</pre>}
            </section>
        </div>
    );
}

function ModelView({ modelStatus }) {
    return (
        <div className="view-grid">
            <section className="panel">
                <SectionHeading title="Model Status" icon={Brain} />
                <div className="detail-grid">
                    <span>Transformer</span><strong>{modelStatus.model?.available ? 'available' : 'fallback active'}</strong>
                    <span>Version</span><strong>{fmt(modelStatus.model?.model_version)}</strong>
                    <span>Features</span><strong>{fmt(modelStatus.model?.feature_count)}</strong>
                    <span>Anomaly</span><strong>{modelStatus.anomaly?.available ? 'available' : 'fallback active'}</strong>
                    <span>Rules loaded</span><strong>{fmt(modelStatus.rules?.loaded)}</strong>
                    <span>Drift</span><strong>baseline pending</strong>
                </div>
                {modelStatus.model?.fallback_reason && <div className="state-panel">{modelStatus.model.fallback_reason}</div>}
            </section>
            <section className="panel wide">
                <PredictionForm />
            </section>
        </div>
    );
}

function Dashboard() {
    const [activeTab, setActiveTab] = useState('overview');
    const [alertsPage, setAlertsPage] = useState(emptyPage);
    const [incidentsPage, setIncidentsPage] = useState(emptyPage);
    const [eventsPage, setEventsPage] = useState(emptyPage);
    const [metrics, setMetrics] = useState({});
    const [modelStatus, setModelStatus] = useState({});
    const [selectedAlert, setSelectedAlert] = useState(null);
    const [selectedIncident, setSelectedIncident] = useState(null);
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [filters, setFilters] = useState({ query: '', severity: '', status: '' });
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState('');
    const [permissionError, setPermissionError] = useState('');
    const [user, setUser] = useState(null);
    const [authError, setAuthError] = useState('');
    const [liveState, setLiveState] = useState('connecting');

    const loadData = useCallback(async () => {
        try {
            const [alerts, incidents, events, metricData, status] = await Promise.all([
                fetchAlertPage({ limit: 100 }),
                fetchIncidents({ limit: 100 }),
                fetchEvents({ limit: 100 }),
                fetchMetrics(),
                fetchModelStatus(),
            ]);
            setAlertsPage(alerts);
            setIncidentsPage(incidents);
            setEventsPage(events);
            setMetrics(metricData);
            setModelStatus(status);
            setSelectedAlert(current => current || alerts.items?.[0] || null);
            setSelectedIncident(current => current || incidents.items?.[0] || null);
            setSelectedEvent(current => current || events.items?.[0] || null);
            setError('');
        } catch (err) {
            setError('Could not load SOC data. The API may be offline or still starting.');
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => {
        loadData();
        const timer = setInterval(loadData, 10000);
        return () => clearInterval(timer);
    }, [loadData]);

    useEffect(() => {
        const socket = new WebSocket(alertWebSocketUrl());
        socket.onopen = () => setLiveState('live');
        socket.onerror = () => setLiveState('offline');
        socket.onclose = () => setLiveState('offline');
        socket.onmessage = () => loadData();
        return () => socket.close();
    }, [loadData]);

    const filteredAlerts = useMemo(() => {
        const query = filters.query.toLowerCase();
        return (alertsPage.items || []).filter(alert => {
            const matchesQuery = !query || [
                alert.classification,
                alert.prediction,
                alert.source_ip,
                alert.destination_ip,
                alert.detection_source,
            ].some(value => String(value || '').toLowerCase().includes(query));
            const matchesSeverity = !filters.severity || alert.severity === filters.severity;
            const matchesStatus = !filters.status || alert.status === filters.status;
            return matchesQuery && matchesSeverity && matchesStatus;
        });
    }, [alertsPage, filters]);

    const handleLogin = async (credentials) => {
        setAuthError('');
        try {
            const result = await login(credentials);
            setUser({ username: result.username, role: result.role });
            setPermissionError('');
        } catch (err) {
            setAuthError('Sign-in failed');
        }
    };

    const guarded = async (operation) => {
        if (!user) {
            setPermissionError('Sign in with an analyst or responder role to change workflow state.');
            return;
        }
        try {
            setPermissionError('');
            await operation();
            await loadData();
        } catch (err) {
            setPermissionError(err.response?.status === 403 ? 'Your role cannot perform this action.' : 'Action failed.');
        }
    };

    const handleAlertAction = (alertId, payload) => guarded(async () => {
        const updated = await updateAlert(alertId, payload);
        setSelectedAlert(updated);
    });

    const handleIncidentAction = (incidentId, payload) => guarded(async () => {
        const updated = await updateIncident(incidentId, payload);
        setSelectedIncident(updated);
    });

    return (
        <div className="dashboard-shell">
            <div className="topbar">
                <nav className="tabbar" aria-label="SOC views">
                    {tabs.map(tab => {
                        const Icon = tab.icon;
                        return (
                            <button
                                key={tab.id}
                                className={activeTab === tab.id ? 'active-tab' : ''}
                                onClick={() => setActiveTab(tab.id)}
                            >
                                <Icon size={16} />
                                <span>{tab.label}</span>
                            </button>
                        );
                    })}
                </nav>
                <div className="topbar-tools">
                    <span className={`live-indicator ${liveState}`}>
                        <Wifi size={15} /> {liveState}
                    </span>
                    <button className="icon-button" onClick={loadData} title="Refresh dashboard data">
                        <RefreshCcw size={16} />
                    </button>
                    <AuthPanel user={user} onLogin={handleLogin} authError={authError} />
                </div>
            </div>

            {error && <div className="state-panel error-message">{error}</div>}
            {isLoading && <div className="state-panel">Loading SOC workspace...</div>}

            {!isLoading && activeTab === 'overview' && (
                <Overview metrics={metrics} alerts={alertsPage.items || []} incidents={incidentsPage.items || []} />
            )}

            {!isLoading && activeTab === 'alerts' && (
                <div className="split-view alerts-view">
                    <section className="panel wide">
                        <div className="filterbar">
                            <label>
                                <Search size={15} />
                                <input
                                    placeholder="Search alerts"
                                    value={filters.query}
                                    onChange={(e) => setFilters({ ...filters, query: e.target.value })}
                                />
                            </label>
                            <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
                                <option value="">All severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                                <option value="informational">Informational</option>
                            </select>
                            <select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
                                <option value="">All statuses</option>
                                <option value="new">New</option>
                                <option value="acknowledged">Acknowledged</option>
                                <option value="investigating">Investigating</option>
                                <option value="resolved">Resolved</option>
                                <option value="false_positive">False positive</option>
                            </select>
                        </div>
                        <AlertsTable
                            alerts={filteredAlerts}
                            isLoading={false}
                            error=""
                            selectedAlertId={selectedAlert?.id}
                            onSelect={setSelectedAlert}
                        />
                    </section>
                    <AlertDetails alert={selectedAlert} onAction={handleAlertAction} permissionError={permissionError} />
                </div>
            )}

            {!isLoading && activeTab === 'incidents' && (
                <IncidentsView
                    incidents={incidentsPage.items || []}
                    selectedIncident={selectedIncident}
                    setSelectedIncident={setSelectedIncident}
                    onAction={handleIncidentAction}
                    permissionError={permissionError}
                />
            )}

            {!isLoading && activeTab === 'events' && (
                <EventsView
                    events={eventsPage.items || []}
                    selectedEvent={selectedEvent}
                    setSelectedEvent={setSelectedEvent}
                />
            )}

            {!isLoading && activeTab === 'model' && (
                <ModelView modelStatus={modelStatus} />
            )}

            <footer className="platform-note">
                <Server size={14} />
                Authorized defensive lab use only. External threat-intelligence lookups are disabled unless explicitly configured.
            </footer>
        </div>
    );
}

export default Dashboard;
