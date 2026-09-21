import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
import Dashboard from './Dashboard';
import GuardianOps from './components/guardian/GuardianOps';
import './App.css';

function App() {
  const [view, setView] = useState('ndr'); // 'ndr' | 'guardian'

  // Placeholder token logic for MVP — in a real app this comes from Auth Context
  const token = localStorage.getItem('access_token');

  return (
    <div className="App">
      <header className="App-header">
        <div style={{ display: 'flex', alignItems: 'center' }}>
            <ShieldCheck size={30} style={{ marginRight: '16px' }} />
            <div>
              <h1 style={{ margin: 0 }}>AI-Assisted Network Detection and Response Platform</h1>
              <span style={{ fontSize: '14px', color: '#8B949E' }}>Hybrid ML, anomaly, rule, and threat-intel alert triage</span>
            </div>
        </div>
        
        <div style={{ display: 'flex', gap: '16px' }}>
          <button 
             onClick={() => setView('ndr')} 
             style={{ 
                 padding: '8px 16px', 
                 cursor: 'pointer',
                 backgroundColor: view === 'ndr' ? '#2A303C' : 'transparent',
                 color: view === 'ndr' ? '#FFF' : '#8B949E',
                 border: '1px solid #2A303C',
                 borderRadius: '6px'
             }}>
             NDR Console
          </button>
          <button 
             onClick={() => setView('guardian')} 
             style={{ 
                 display: 'flex', alignItems: 'center', gap: '8px',
                 padding: '8px 16px', 
                 cursor: 'pointer',
                 backgroundColor: view === 'guardian' ? '#2A303C' : 'transparent',
                 color: view === 'guardian' ? '#FFF' : '#8B949E',
                 border: '1px solid #2A303C',
                 borderRadius: '6px'
             }}>
             <ShieldAlert size={16} /> Guardian Ops
          </button>
        </div>
      </header>
      <main style={{ height: 'calc(100vh - 80px)' }}>
        {view === 'ndr' ? <Dashboard /> : <GuardianOps token={token} />}
      </main>
    </div>
  );
}

export default App;
