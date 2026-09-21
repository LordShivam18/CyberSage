import React, { useState } from 'react';
import GuardianNav from './GuardianNav';
import GuardianDashboard from './GuardianDashboard';
import ApprovalQueue from './ApprovalQueue';
import IncidentQueue from './IncidentQueue';

const GuardianOps = ({ token }) => {
    const [activeTab, setActiveTab] = useState('dashboard');

    const renderContent = () => {
        switch (activeTab) {
            case 'dashboard':
                return <GuardianDashboard token={token} />;
            case 'incidents':
                return <IncidentQueue token={token} />;
            case 'approvals':
                return <ApprovalQueue token={token} />;
            default:
                return <GuardianDashboard token={token} />;
        }
    };

    return (
        <div style={styles.container}>
            <GuardianNav currentTab={activeTab} setTab={setActiveTab} />
            <div style={styles.content}>
                {renderContent()}
            </div>
        </div>
    );
};

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        backgroundColor: '#0D1117',
        color: '#C9D1D9',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
    },
    content: {
        flex: 1,
        padding: '32px',
        overflowY: 'auto',
    },
};

export default GuardianOps;
