// frontend/src/components/AlertsTable.js

import React from 'react';

const AlertsTable = ({ alerts, isLoading, error }) => {
    if (isLoading) return <p>Loading alerts...</p>;
    if (error) return <p className="error-message">{error}</p>;
    if (alerts.length === 0) return <p>No threats detected yet. The table will update automatically.</p>;

    return (
        <table className="alerts-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Confidence</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {alerts.map(alert => (
                    <tr key={alert.id}>
                        <td>{new Date(alert.timestamp).toLocaleString()}</td>
                        <td>{(alert.probability * 100).toFixed(2)}%</td>
                        <td className="details-cell">{alert.details}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
};

// React.memo optimizes the component so it only re-renders when its props change.
export default React.memo(AlertsTable);