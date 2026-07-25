import React from 'react';

const confidence = (value) => {
    if (value === null || value === undefined) return 'n/a';
    return `${(Number(value) * 100).toFixed(1)}%`;
};

const AlertsTable = ({ alerts, isLoading, error, onSelect, selectedAlertId }) => {
    if (isLoading) return <div className="state-panel">Loading alerts...</div>;
    if (error) return <div className="state-panel error-message">{error}</div>;
    if (!alerts.length) return <div className="state-panel">No matching alerts. New detections will appear here.</div>;

    return (
        <div className="table-wrap">
            <table className="alerts-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Classification</th>
                        <th>Confidence</th>
                        <th>Source</th>
                        <th>Route</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts.map(alert => (
                        <tr
                            key={alert.id}
                            className={selectedAlertId === alert.id ? 'selected-row' : ''}
                            onClick={() => onSelect && onSelect(alert)}
                        >
                            <td><span className={`severity-pill severity-${alert.severity || 'low'}`}>{alert.severity || 'low'}</span></td>
                            <td>{alert.status || 'new'}</td>
                            <td>{alert.classification || alert.prediction}</td>
                            <td>{confidence(alert.confidence ?? alert.probability)}</td>
                            <td>{alert.detection_source || 'legacy'}</td>
                            <td className="route-cell">{alert.source_ip || 'unknown'} -&gt; {alert.destination_ip || 'unknown'}</td>
                            <td>{new Date(alert.timestamp).toLocaleString()}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default React.memo(AlertsTable);
