import React, { useState, useEffect } from 'react';

const ApprovalQueue = ({ token }) => {
    const [approvals, setApprovals] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchApprovals = async () => {
        try {
            const res = await fetch('/api/v1/guardian/approvals', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setApprovals(data.approvals || []);
            }
        } catch (err) {
            console.error("Failed to fetch approvals", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchApprovals();
    }, [token]);

    const handleAction = async (id, action) => {
        try {
            const res = await fetch(`/api/v1/guardian/approvals/${id}/${action}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ notes: `Action: ${action} from UI` })
            });
            if (res.ok) {
                fetchApprovals(); // refresh
            } else {
                alert(`Failed to ${action} approval.`);
            }
        } catch (err) {
            console.error("Action failed", err);
        }
    };

    return (
        <div>
            <h2 style={styles.title}>Approval Queue</h2>
            <div style={styles.tableContainer}>
                <table style={styles.table}>
                    <thead>
                        <tr>
                            <th style={styles.th}>Approval ID</th>
                            <th style={styles.th}>Action</th>
                            <th style={styles.th}>Target</th>
                            <th style={styles.th}>Status</th>
                            <th style={styles.th}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            <tr><td colSpan="5" style={styles.empty}>Loading...</td></tr>
                        ) : approvals.length > 0 ? (
                            approvals.map((app) => (
                                <tr key={app.approval_id} style={styles.tr}>
                                    <td style={styles.td} title={app.approval_id}>
                                        {app.approval_id.substring(0, 8)}...
                                    </td>
                                    <td style={styles.td}>{app.requested_action}</td>
                                    <td style={styles.td}>{JSON.stringify(app.target)}</td>
                                    <td style={styles.td}>
                                        <span style={{
                                            ...styles.badge,
                                            backgroundColor: app.status === 'pending' ? 'rgba(210,153,34,0.15)' : 'rgba(139,148,158,0.15)',
                                            color: app.status === 'pending' ? '#D29922' : '#C9D1D9'
                                        }}>
                                            {app.status}
                                        </span>
                                    </td>
                                    <td style={styles.td}>
                                        {app.status === 'pending' && (
                                            <div style={styles.actionButtons}>
                                                <button 
                                                    style={{...styles.btn, ...styles.btnApprove}}
                                                    onClick={() => handleAction(app.approval_id, 'approve')}
                                                >
                                                    Approve
                                                </button>
                                                <button 
                                                    style={{...styles.btn, ...styles.btnReject}}
                                                    onClick={() => handleAction(app.approval_id, 'reject')}
                                                >
                                                    Reject
                                                </button>
                                            </div>
                                        )}
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr><td colSpan="5" style={styles.empty}>No pending approvals.</td></tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

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
        maxWidth: '200px',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
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
    },
    actionButtons: {
        display: 'flex',
        gap: '8px',
    },
    btn: {
        border: 'none',
        padding: '6px 12px',
        borderRadius: '4px',
        cursor: 'pointer',
        fontSize: '12px',
        fontWeight: 'bold',
        color: '#FFF',
    },
    btnApprove: {
        backgroundColor: '#238636',
    },
    btnReject: {
        backgroundColor: '#DA3633',
    }
};

export default ApprovalQueue;
