import React, { useState } from 'react';
import { Play, Upload, FileText, CheckCircle, XCircle, AlertCircle, Clock } from 'lucide-react';
import Modal from '../common/Modal';
import Button from '../common/Button';
import LoadingSpinner from '../common/LoadingSpinner';
import { rulesService } from '../../services/rulesService';
import { formatDateTime, formatDuration } from '../../utils/formatters';

const RuleTester = ({ isOpen, onClose, rule }) => {
  const [testData, setTestData] = useState('');
  const [testFile, setTestFile] = useState(null);
  const [testType, setTestType] = useState('raw');
  const [isRunning, setIsRunning] = useState(false);
  const [testResults, setTestResults] = useState(null);
  const [error, setError] = useState(null);

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      setTestFile(file);
      setTestType('file');
      setTestData('');
      
      // Read file content for display
      const reader = new FileReader();
      reader.onload = (e) => {
        setTestData(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  const runTest = async () => {
    if (!rule || (!testData && !testFile)) return;

    setIsRunning(true);
    setError(null);
    setTestResults(null);

    try {
      const results = await rulesService.testRule(rule.id, {
        data: testData,
        type: testType,
        timeout: 30
      });
      
      setTestResults(results);
    } catch (err) {
      setError(err.message || 'Test failed');
    } finally {
      setIsRunning(false);
    }
  };

  const renderTestResults = () => {
    if (!testResults) return null;

    const hasMatches = testResults.matches && testResults.matches.length > 0;

    return (
      <div className="space-y-4">
        {/* Summary */}
        <div className={`
          p-4 rounded-lg border
          ${hasMatches 
            ? 'bg-red-500/10 border-red-500/50' 
            : 'bg-green-500/10 border-green-500/50'
          }
        `}>
          <div className="flex items-start space-x-3">
            {hasMatches ? (
              <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
            ) : (
              <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
            )}
            <div className="flex-1">
              <p className={`font-medium ${hasMatches ? 'text-red-400' : 'text-green-400'}`}>
                {hasMatches 
                  ? `Rule matched ${testResults.matches.length} time(s)` 
                  : 'No matches found'
                }
              </p>
              <p className="text-sm text-gray-300 mt-1">
                Test completed in {formatDuration(testResults.execution_time)}
              </p>
            </div>
          </div>
        </div>

        {/* Matches Details */}
        {hasMatches && (
          <div className="space-y-3">
            <h4 className="text-sm font-semibold text-gray-300">Match Details</h4>
            {testResults.matches.map((match, index) => (
              <div key={index} className="p-3 bg-gray-800 rounded-lg space-y-2">
                {match.line && (
                  <div className="flex items-center space-x-2 text-sm">
                    <span className="text-gray-400">Line:</span>
                    <span className="text-white font-mono">{match.line}</span>
                  </div>
                )}
                {match.offset && (
                  <div className="flex items-center space-x-2 text-sm">
                    <span className="text-gray-400">Offset:</span>
                    <span className="text-white font-mono">0x{match.offset.toString(16)}</span>
                  </div>
                )}
                {match.matched_string && (
                  <div className="space-y-1">
                    <span className="text-sm text-gray-400">Matched String:</span>
                    <pre className="text-sm text-cyan-400 font-mono bg-gray-900 p-2 rounded overflow-x-auto">
                      {match.matched_string}
                    </pre>
                  </div>
                )}
                {match.context && (
                  <div className="space-y-1">
                    <span className="text-sm text-gray-400">Context:</span>
                    <pre className="text-xs text-gray-300 font-mono bg-gray-900 p-2 rounded overflow-x-auto">
                      {match.context}
                    </pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Performance Metrics */}
        {testResults.metrics && (
          <div className="p-3 bg-gray-800 rounded-lg">
            <h4 className="text-sm font-semibold text-gray-300 mb-2">Performance Metrics</h4>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-gray-400">Execution Time:</span>
                <span className="ml-2 text-white">
                  {testResults.metrics.execution_time_ms}ms
                </span>
              </div>
              <div>
                <span className="text-gray-400">Memory Used:</span>
                <span className="ml-2 text-white">
                  {(testResults.metrics.memory_used_kb / 1024).toFixed(2)}MB
                </span>
              </div>
              <div>
                <span className="text-gray-400">Data Processed:</span>
                <span className="ml-2 text-white">
                  {(testResults.metrics.bytes_processed / 1024).toFixed(2)}KB
                </span>
              </div>
              <div>
                <span className="text-gray-400">Patterns Evaluated:</span>
                <span className="ml-2 text-white">
                  {testResults.metrics.patterns_evaluated || 'N/A'}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const sampleData = {
    yara: `MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF
This is a sample file for testing YARA rules.
Contains suspicious strings: cmd.exe powershell.exe
VirtualAllocEx WriteProcessMemory CreateRemoteThread`,
    sigma: `2024-01-15 10:23:45 EventID: 4688 ProcessName: "powershell.exe" CommandLine: "powershell -enc SGVsbG8gV29ybGQ="
2024-01-15 10:23:46 EventID: 4688 ProcessName: "cmd.exe" CommandLine: "cmd /c net user admin P@ssw0rd /add"
2024-01-15 10:23:47 EventID: 4624 LogonType: 3 SourceIP: "192.168.1.100"`,
    custom: JSON.stringify({
      timestamp: new Date().toISOString(),
      event_type: "suspicious_activity",
      source_ip: "10.0.0.1",
      destination_ip: "192.168.1.1",
      count: 15,
      severity: "high"
    }, null, 2)
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Test Rule: ${rule?.name || 'Unknown'}`}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          <Button
            variant="primary"
            onClick={runTest}
            disabled={!testData || isRunning}
            loading={isRunning}
            leftIcon={<Play className="w-4 h-4" />}
          >
            Run Test
          </Button>
        </>
      }
    >
      <div className="space-y-6">
        {/* Rule Info */}
        <div className="p-4 bg-gray-800 rounded-lg">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Rule Type:</span>
              <span className="ml-2 text-white font-medium">
                {rule?.type?.toUpperCase() || 'Unknown'}
              </span>
            </div>
            <div>
              <span className="text-gray-400">Severity:</span>
              <span className={`ml-2 font-medium text-${
                rule?.severity === 'critical' ? 'red' :
                rule?.severity === 'high' ? 'orange' :
                rule?.severity === 'medium' ? 'yellow' : 'green'
              }-400`}>
                {rule?.severity?.toUpperCase() || 'Unknown'}
              </span>
            </div>
          </div>
        </div>

        {/* Test Data Input */}
        {!testResults && (
          <>
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-gray-300">
                  Test Data
                </label>
                <div className="flex items-center space-x-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => setTestData(sampleData[rule?.type] || '')}
                  >
                    Load Sample
                  </Button>
                  <label className="cursor-pointer">
                    <input
                      type="file"
                      onChange={handleFileUpload}
                      className="hidden"
                      accept=".log,.txt,.json,.xml,.csv"
                    />
                    <Button
                      as="span"
                      size="sm"
                      variant="secondary"
                      leftIcon={<Upload className="w-4 h-4" />}
                    >
                      Upload File
                    </Button>
                  </label>
                </div>
              </div>

              {testFile && (
                <div className="mb-2 p-2 bg-gray-800 rounded flex items-center space-x-2">
                  <FileText className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-300">{testFile.name}</span>
                  <span className="text-xs text-gray-500">
                    ({(testFile.size / 1024).toFixed(2)} KB)
                  </span>
                </div>
              )}

              <textarea
                value={testData}
                onChange={(e) => {
                  setTestData(e.target.value);
                  setTestType('raw');
                  setTestFile(null);
                }}
                rows={10}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white font-mono text-sm focus:outline-none focus:border-cyan-500"
                placeholder={`Enter test data for ${rule?.type?.toUpperCase()} rule...`}
                spellCheck={false}
              />
            </div>

            {/* Test Options */}
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2">
                <input
                  type="radio"
                  name="testType"
                  value="raw"
                  checked={testType === 'raw'}
                  onChange={(e) => setTestType(e.target.value)}
                  className="w-4 h-4 text-cyan-500"
                />
                <span className="text-sm text-gray-300">Raw Text</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="radio"
                  name="testType"
                  value="hex"
                  checked={testType === 'hex'}
                  onChange={(e) => setTestType(e.target.value)}
                  className="w-4 h-4 text-cyan-500"
                />
                <span className="text-sm text-gray-300">Hex Data</span>
              </label>
              <label className="flex items-center space-x-2">
                <input
                  type="radio"
                  name="testType"
                  value="base64"
                  checked={testType === 'base64'}
                  onChange={(e) => setTestType(e.target.value)}
                  className="w-4 h-4 text-cyan-500"
                />
                <span className="text-sm text-gray-300">Base64</span>
              </label>
            </div>
          </>
        )}

        {/* Loading State */}
        {isRunning && (
          <div className="py-8">
            <LoadingSpinner text="Running rule test..." />
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
            <div className="flex items-start space-x-3">
              <XCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-red-400 font-medium">Test Error</p>
                <p className="text-sm text-gray-300 mt-1">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Test Results */}
        {renderTestResults()}
      </div>
    </Modal>
  );
};

export default RuleTester;