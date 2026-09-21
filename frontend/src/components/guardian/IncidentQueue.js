import React, { useState, useEffect } from 'react';

const IncidentQueue = ({ token }) => {
    const [incidents, setIncidents] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchIncidents = async () => {
            try {
                const res = await fetch('/api/v1/incidents', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (res.ok) {
                    const data = await res.json();
                    setIncidents(data);
                }
            } catch (err) {
                console.error("Failed to fetch incidents", err);
            } finally {
                setLoading(false);
            }
        };
        fetchIncidents();
    }, [token]);

    return (
        <div>
            <h2 style={styles.title}>Incident Queue</h2>
            <div style={styles.tableContainer}>
                <table style={styles.table}>
                    <thead>
                        <tr>
                            <th style={styles.th}>ID</th>
                            <th style={styles.th}>Title</th>
                            <th style={styles.th}>Severity</th>
                            <th style={styles.th}>Status</th>
                            <th style={styles.th}>Created</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            <tr><td colSpan="5" style={styles.empty}>Loading...</td></tr>
                        ) : incidents.length > 0 ? (
                            incidents.map((inc) => (
                                <tr key={inc.id} style={styles.tr}>
                                    <td style={styles.td}>INC-{inc.id}</td>
                                    <td style={styles.td}>{inc.title}</td>
                                    <td style={styles.td}>
                                        <span style={{...styles.badge, ...getSeverityStyle(inc.severity)}}>
                                            {inc.severity}
                                        </span>
                                    </td>
                                    <td style={styles.td}>{inc.status}</td>
                                    <td style={styles.td}>{new Date(inc.created_at).toLocaleString()}</td>
                                </tr>
                            ))
                        ) : (
                            <tr><td colSpan="5" style={styles.empty}>No active incidents.</td></tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

const getSeverityStyle = (severity) => {
    switch(severity?.toLowerCase()) {
        case 'critical': return { color: '#F85149', backgroundColor: 'rgba(248,81,73,0.15)' };
        case 'high': return { color: '#D29922', backgroundColor: 'rgba(210,153,34,0.15)' };
        case 'medium': return { color: '#8250DF', backgroundColor: 'rgba(130,80,223,0.15)' };
        default: return { color: '#3FB950', backgroundColor: 'rgba(46,160,67,0.15)' };
    }
}

const styles = {
    title: {
        fontSize: '24px',
        fontWeight: 'bold',
        marginBottom: '24px',
        color: '#E0E6ED',
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
        textTransform: 'uppercase',
    }
};

export default IncidentQueue;
