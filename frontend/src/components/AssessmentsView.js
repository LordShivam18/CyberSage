import React, { useState, useEffect } from 'react';
import { Monitor, Info, AlertTriangle, XCircle, CheckCircle, UploadCloud } from 'lucide-react';
import { fetchAssessments, fetchAssessmentDetails, importAssessment } from '../apiService';
import './AssessmentsView.css';

function AssessmentsView() {
    const [assessments, setAssessments] = useState([]);
    const [selectedAssessment, setSelectedAssessment] = useState(null);
    const [details, setDetails] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState('');
    
    // Import state
    const [isImporting, setIsImporting] = useState(false);
    const [importFile, setImportFile] = useState(null);
    const [createAlerts, setCreateAlerts] = useState(false);
    const [importError, setImportError] = useState('');
    const [importSuccess, setImportSuccess] = useState('');

    useEffect(() => {
        loadAssessments();
    }, []);

    const loadAssessments = async () => {
        setIsLoading(true);
        try {
            const data = await fetchAssessments();
            setAssessments(data);
            setError('');
        } catch (err) {
            setError('Could not load assessments.');
        } finally {
            setIsLoading(false);
        }
    };

    const handleSelect = async (assessment) => {
        setSelectedAssessment(assessment);
        setDetails(null);
        try {
            const data = await fetchAssessmentDetails(assessment.assessment_id);
            setDetails(data);
        } catch (err) {
            setError('Could not load assessment details.');
        }
    };

    const getStatusIcon = (status) => {
        switch (status) {
            case 'pass': return <CheckCircle size={14} className="status-pass" />;
            case 'fail': return <XCircle size={14} className="status-fail" />;
            case 'warning': return <AlertTriangle size={14} className="status-warning" />;
            default: return <Info size={14} className="status-info" />;
        }
    };

    const handleFileChange = (e) => {
        setImportFile(e.target.files[0]);
        setImportError('');
        setImportSuccess('');
    };

    const handleImport = async () => {
        if (!importFile) return;
        setIsImporting(true);
        setImportError('');
        setImportSuccess('');
        
        try {
            const text = await importFile.text();
            const reportData = JSON.parse(text);
            await importAssessment(reportData, createAlerts);
            setImportSuccess('Assessment imported successfully!');
            setImportFile(null);
            setCreateAlerts(false);
            loadAssessments();
        } catch (err) {
            if (err.name === 'SyntaxError') {
                setImportError('Invalid JSON format.');
            } else if (err.response) {
                const status = err.response.status;
                if (status === 409) {
                    setImportError('Assessment conflict: different checksum.');
                } else if (status === 413) {
                    setImportError('Report is too large.');
                } else if (status === 422 || status === 400) {
                    setImportError(`Validation error: ${err.response.data.detail || 'Malformed report.'}`);
                } else if (status === 401 || status === 403) {
                    setImportError('Unauthorized to import assessments.');
                } else {
                    setImportError('Failed to import assessment.');
                }
            } else {
                setImportError('An unexpected error occurred.');
            }
        } finally {
            setIsImporting(false);
        }
    };

    return (
        <div className="split-view">
            <section className="panel">
                <div className="section-heading">
                    <div>
                        <h2>Device Assessments</h2>
                        <span className="section-kicker">Portable Scanner Imports</span>
                    </div>
                    <Monitor size={20} />
                </div>
                {error && <div className="state-panel error-message">{error}</div>}
                <div className="queue-list selectable">
                    {assessments.map(assessment => (
                        <article
                            key={assessment.id}
                            className={selectedAssessment?.id === assessment.id ? 'selected-card' : ''}
                            onClick={() => handleSelect(assessment)}
                        >
                            <strong>{assessment.hostname || assessment.assessment_id}</strong>
                            <span>{new Date(assessment.imported_at).toLocaleString()} | Score: {assessment.score}</span>
                        </article>
                    ))}
                    {!isLoading && assessments.length === 0 && (
                        <div className="state-panel">No assessments imported yet.</div>
                    )}
                </div>
                
                <div className="import-section" style={{ marginTop: '20px', borderTop: '1px solid #ccc', paddingTop: '15px' }}>
                    <h3>Import Portable Scan</h3>
                    <input type="file" accept=".json" onChange={handleFileChange} />
                    <div style={{ marginTop: '10px' }}>
                        <label>
                            <input 
                                type="checkbox" 
                                checked={createAlerts} 
                                onChange={(e) => setCreateAlerts(e.target.checked)} 
                            />
                            Create SOC Alerts (High/Critical fails only)
                        </label>
                    </div>
                    <button 
                        onClick={handleImport} 
                        disabled={!importFile || isImporting}
                        style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '5px' }}
                    >
                        <UploadCloud size={16} /> {isImporting ? 'Importing...' : 'Import Assessment'}
                    </button>
                    {importError && <div className="state-panel error-message" style={{ marginTop: '10px' }}>{importError}</div>}
                    {importSuccess && <div className="state-panel success-message" style={{ marginTop: '10px', color: 'green' }}>{importSuccess}</div>}
                </div>
            </section>
            
            <section className="panel assessment-detail-panel">
                <div className="section-heading">
                    <div>
                        <h2>Assessment Details</h2>
                    </div>
                </div>
                {!selectedAssessment && <div className="state-panel">Select an assessment to view findings.</div>}
                
                {selectedAssessment && !details && <div className="state-panel">Loading details...</div>}
                
                {details && (
                    <div className="assessment-details">
                        <div className="detail-grid">
                            <span>Hostname</span><strong>{details.host?.hostname || 'unknown'}</strong>
                            <span>OS</span><strong>{details.host?.os_name} {details.host?.os_version}</strong>
                            <span>Score</span><strong>{details.score} / 100</strong>
                            <span>Coverage</span><strong>{(details.coverage * 100).toFixed(1)}%</strong>
                            <span>Imported By</span><strong>{details.imported_by || 'system'}</strong>
                            <span>Scanner Ver</span><strong>{details.scanner_version}</strong>
                        </div>
                        <div className="score-caveat" style={{ fontSize: '0.85em', color: '#666', marginTop: '10px', fontStyle: 'italic' }}>
                            Posture score is a prioritization aid only. It does not represent a complete security assessment.
                            Unavailable or permission-required checks reduce coverage, but do not reduce the score.
                        </div>
                        
                        <h3 className="findings-header">Findings ({details.findings.length})</h3>
                        
                        <div className="findings-list">
                            {details.findings.map((f, i) => (
                                <div key={i} className={`finding-card severity-${f.severity}`}>
                                    <div className="finding-header">
                                        <div className="finding-title">
                                            {getStatusIcon(f.status)}
                                            <strong>{f.title}</strong>
                                        </div>
                                        <span className={`finding-badge bg-${f.severity}`}>{f.severity}</span>
                                    </div>
                                    <div className="finding-category">{f.category}</div>
                                    {f.explanation && <p className="finding-explanation">{f.explanation}</p>}
                                    {f.remediation && (
                                        <div className="finding-remediation">
                                            <strong>Remediation:</strong> {f.remediation}
                                        </div>
                                    )}
                                    {f.evidence && Object.keys(f.evidence).length > 0 && (
                                        <div className="finding-evidence">
                                            <strong>Evidence:</strong>
                                            <pre>{JSON.stringify(f.evidence, null, 2)}</pre>
                                        </div>
                                    )}
                                </div>
                            ))}
                            {details.findings.length === 0 && <div className="state-panel">No findings in this assessment.</div>}
                        </div>
                    </div>
                )}
            </section>
        </div>
    );
}

export default AssessmentsView;
