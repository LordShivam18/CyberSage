import React from 'react';

// --- Import your components ---
import Dashboard from './Dashboard';
import { ShieldCheck } from 'lucide-react';

// --- Import your stylesheet ---
import './App.css';

function App() {
  return (
    // The inline style for the background image has been removed from this div
    <div className="App">
      
      {/* This is your header at the top */}
      <header className="App-header">
        
        <ShieldCheck size={36} />
        
        <h1>AI-Enhanced Cybersecurity Threat Detector</h1>
      </header>
      
      {/* This is your main content area below the header */}
      <main>
        <Dashboard />
      </main>

    </div>
  );
}

export default App;