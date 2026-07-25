import React from 'react';
import { ShieldCheck } from 'lucide-react';
import Dashboard from './Dashboard';
import './App.css';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <ShieldCheck size={30} />
        <div>
          <h1>AI-Assisted Network Detection and Response Platform</h1>
          <span>Hybrid ML, anomaly, rule, and threat-intel alert triage</span>
        </div>
      </header>
      <main>
        <Dashboard />
      </main>
    </div>
  );
}

export default App;
