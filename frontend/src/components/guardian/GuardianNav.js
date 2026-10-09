import React from 'react';

const GuardianNav = ({ currentTab, setTab }) => {
    const tabs = [
        { id: 'dashboard', label: 'Overview' },
        { id: 'policies', label: 'Policies' },
        { id: 'simulate', label: 'Simulate' },
        { id: 'conflicts', label: 'Conflicts' },
        { id: 'executions', label: 'Executions' },
        { id: 'approvals', label: 'Approvals' },
        { id: 'incidents', label: 'Incidents' },
    ];

    return (
        <div style={styles.navContainer}>
            <div style={styles.brand}>
                <span style={styles.shieldIcon} aria-hidden="true">🛡️</span>
                <span style={styles.brandText}>Guardian Ops</span>
            </div>
            <nav style={styles.tabs} aria-label="Guardian operations views">
                {tabs.map((tab) => (
                    <button
                        key={tab.id}
                        onClick={() => setTab(tab.id)}
                        aria-current={currentTab === tab.id ? 'page' : undefined}
                        aria-label={`Guardian ${tab.label}`}
                        style={{
                            ...styles.tabButton,
                            ...(currentTab === tab.id ? styles.activeTab : {}),
                        }}
                    >
                        {tab.label}
                    </button>
                ))}
            </nav>
        </div>
    );
};

const styles = {
    navContainer: {
        display: 'flex',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px',
        padding: '14px 24px',
        backgroundColor: '#1E232E',
        color: 'white',
        borderBottom: '1px solid #2A303C',
    },
    brand: {
        display: 'flex',
        alignItems: 'center',
        marginRight: '24px',
    },
    shieldIcon: {
        fontSize: '22px',
        marginRight: '10px',
    },
    brandText: {
        fontSize: '17px',
        fontWeight: 'bold',
        letterSpacing: '0.5px',
        color: '#E0E6ED',
    },
    tabs: {
        display: 'flex',
        gap: '8px',
        flexWrap: 'wrap',
    },
    tabButton: {
        background: 'transparent',
        border: '1px solid transparent',
        color: '#8B949E',
        fontSize: '13px',
        fontWeight: '600',
        cursor: 'pointer',
        padding: '8px 12px',
        borderRadius: '6px',
        transition: 'all 0.2s ease',
    },
    activeTab: {
        color: '#FFFFFF',
        backgroundColor: '#2A303C',
        borderColor: '#3A434E',
    },
};

export default GuardianNav;
