import React from 'react';

const GuardianNav = ({ currentTab, setTab }) => {
    const tabs = [
        { id: 'dashboard', label: 'Overview' },
        { id: 'incidents', label: 'Incident Queue' },
        { id: 'approvals', label: 'Approval Queue' },
    ];

    return (
        <div style={styles.navContainer}>
            <div style={styles.brand}>
                <span style={styles.shieldIcon}>🛡️</span>
                <span style={styles.brandText}>Guardian Ops</span>
            </div>
            <div style={styles.tabs}>
                {tabs.map((tab) => (
                    <button
                        key={tab.id}
                        onClick={() => setTab(tab.id)}
                        style={{
                            ...styles.tabButton,
                            ...(currentTab === tab.id ? styles.activeTab : {}),
                        }}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>
        </div>
    );
};

const styles = {
    navContainer: {
        display: 'flex',
        alignItems: 'center',
        padding: '16px 32px',
        backgroundColor: '#1E232E',
        color: 'white',
        borderBottom: '1px solid #2A303C',
    },
    brand: {
        display: 'flex',
        alignItems: 'center',
        marginRight: '48px',
    },
    shieldIcon: {
        fontSize: '24px',
        marginRight: '12px',
    },
    brandText: {
        fontSize: '18px',
        fontWeight: 'bold',
        letterSpacing: '0.5px',
        color: '#E0E6ED',
    },
    tabs: {
        display: 'flex',
        gap: '16px',
    },
    tabButton: {
        background: 'transparent',
        border: 'none',
        color: '#8B949E',
        fontSize: '14px',
        fontWeight: '500',
        cursor: 'pointer',
        padding: '8px 12px',
        borderRadius: '6px',
        transition: 'all 0.2s ease',
    },
    activeTab: {
        color: '#FFFFFF',
        backgroundColor: '#2A303C',
    },
};

export default GuardianNav;
