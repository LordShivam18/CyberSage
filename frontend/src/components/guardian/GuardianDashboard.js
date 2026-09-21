import React from 'react';
import { useGuardianDashboard, useCollectorHealth } from '../../hooks/useGuardianData';

const GuardianDashboard = ({ token }) => {
    const { data, loading, error } = useGuardianDashboard(token);
    const { collectors } = useCollectorHealth(token);

    if (loading) return <div style={styles.message}>Loading dashboard...</div>;
    if (error) return <div style={styles.error}>Error: {error}</div>;

    const stats = [
        { label: 'Active Incidents', value: data?.active_incidents_count ?? 0, color: '#F85149' },
        { label: 'Pending Approvals', value: data?.pending_approvals_count ?? 0, color: '#D29922' },
        { label: 'Recent Automations', value: data?.recent_automation_runs?.length ?? 0, color: '#2EA043' },
    ];

    return (
        <div style={styles.dashboard}>
            <div style={styles.statsContainer}>
                {stats.map((stat, idx) => (
                    <div key={idx} style={styles.statCard}>
                        <div style={styles.statLabel}>{stat.label}</div>
                        <div style={{ ...styles.statValue, color: stat.color }}>{stat.value}</div>
                    </div>
                ))}
            </div>

            <div style={styles.section}>
                <h3 style={styles.sectionTitle}>Collector Health</h3>
                <div style={styles.tableContainer}>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Agent ID</th>
                                <th style={styles.th}>Collector Type</th>
                                <th style={styles.th}>Health State</th>
                                <th style={styles.th}>Last Event</th>
                                <th style={styles.th}>Events Received</th>
                            </tr>
                        </thead>
                        <tbody>
                            {collectors && collectors.length > 0 ? (
                                collectors.map((c, i) => (
                                    <tr key={i} style={styles.tr}>
                                        <td style={styles.td}>{c.agent_id}</td>
                                        <td style={styles.td}>{c.collector_type}</td>
                                        <td style={styles.td}>
                                            <span style={{
                                                ...styles.badge,
                                                backgroundColor: c.health_state === 'running' ? 'rgba(46,160,67,0.15)' : 'rgba(248,81,73,0.15)',
                                                color: c.health_state === 'running' ? '#3FB950' : '#F85149'
                                            }}>
                                                {c.health_state.toUpperCase()}
                                            </span>
                                        </td>
                                        <td style={styles.td}>{c.last_event_at ? new Date(c.last_event_at).toLocaleString() : 'N/A'}</td>
                                        <td style={styles.td}>{c.events_received ?? 0}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="5" style={styles.empty}>No collectors found</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            <div style={styles.section}>
                <h3 style={styles.sectionTitle}>Recent Automation Runs</h3>
                <div style={styles.tableContainer}>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Run ID</th>
                                <th style={styles.th}>Action Type</th>
                                <th style={styles.th}>Status</th>
                                <th style={styles.th}>Created At</th>
                            </tr>
                        </thead>
                        <tbody>
                            {data?.recent_automation_runs?.map((run, i) => (
                                <tr key={i} style={styles.tr}>
                                    <td style={styles.td}>{run.run_id}</td>
                                    <td style={styles.td}>{run.action_type}</td>
                                    <td style={styles.td}>{run.status}</td>
                                    <td style={styles.td}>{new Date(run.created_at).toLocaleString()}</td>
                                </tr>
                            ))}
                            {!data?.recent_automation_runs?.length && (
                                <tr>
                                    <td colSpan="4" style={styles.empty}>No recent automation runs</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

const styles = {
    dashboard: {
        display: 'flex',
        flexDirection: 'column',
        gap: '32px',
    },
    message: {
        color: '#8B949E',
        fontSize: '16px',
    },
    error: {
        color: '#F85149',
        fontSize: '16px',
    },
    statsContainer: {
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
        gap: '24px',
    },
    statCard: {
        backgroundColor: '#1E232E',
        borderRadius: '8px',
        padding: '24px',
        border: '1px solid #2A303C',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
    },
    statLabel: {
        color: '#8B949E',
        fontSize: '14px',
        fontWeight: '500',
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
    },
    statValue: {
        fontSize: '32px',
        fontWeight: 'bold',
    },
    section: {
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
    },
    sectionTitle: {
        fontSize: '20px',
        fontWeight: '600',
        color: '#E0E6ED',
        margin: 0,
    },
    tableContainer: {
        backgroundColor: '#1E232E',
        borderRadius: '8px',
        border: '1px solid #2A303C',
        overflow: 'hidden',
    },
    table: {
        width: '100%',
        borderCollapse: 'collapse',
    },
    th: {
        padding: '16px',
        textAlign: 'left',
        color: '#8B949E',
        fontSize: '14px',
        fontWeight: '600',
        borderBottom: '1px solid #2A303C',
        backgroundColor: '#161B22',
    },
    tr: {
        borderBottom: '1px solid #2A303C',
    },
    td: {
        padding: '16px',
        fontSize: '14px',
        color: '#C9D1D9',
    },
    empty: {
        padding: '32px',
        textAlign: 'center',
        color: '#8B949E',
        fontStyle: 'italic',
    },
    badge: {
        padding: '4px 8px',
        borderRadius: '12px',
        fontSize: '12px',
        fontWeight: '600',
    },
};

export default GuardianDashboard;
