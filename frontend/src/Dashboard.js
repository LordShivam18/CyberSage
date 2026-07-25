// This file can stay the same as your "Newer Version"
// No changes are needed here if you are using the refactored components
import React from 'react';
import { useAlerts } from './hooks/useAlerts';
import AlertsTable from './components/AlertsTable';
import PredictionForm from './components/PredictionForm';
import './Dashboard.css'; // Make sure this is not imported if you deleted the file

function Dashboard() {
    const { alerts, isLoading, error } = useAlerts();

    return (
        <div className="dashboard">
            <div className="alerts-container">
                <AlertsTable alerts={alerts} isLoading={isLoading} error={error} />
            </div>
            <div className="prediction-form-container">
                <PredictionForm />
            </div>
        </div>
    );
}

export default Dashboard;