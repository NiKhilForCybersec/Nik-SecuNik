import React, { useState, useEffect, useRef } from 'react';
import { X, Save, Code, AlertCircle, CheckCircle, Copy, FileText } from 'lucide-react';
import Button from '../common/Button';
import { rulesService } from '../../services/rulesService';

const RuleEditor = ({ rule = null, isOpen, onClose, onSave }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'yara',
    severity: 'medium',
    enabled: true,
    content: '',
    tags: [],
    metadata: {}
  });
  const [errors, setErrors] = useState({});
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState(null);
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const textareaRef = useRef(null);

  // Rule templates
  const templates = {
    yara: {
      basic: `rule ${formData.name || 'rule_name'} {
    meta:
        description = "${formData.description || 'Rule description'}"
        author = "SecuNik LogX"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "${formData.severity}"
    
    strings:
        $string1 = "suspicious_string"
        $string2 = {48 65 6C 6C 6F}
        $regex = /pattern[0-9]+/
    
    condition:
        any of them
}`,
      malware: `rule ${formData.name || 'malware_detection'} {
    meta:
        description = "Detects potential malware indicators"
        severity = "high"
        mitre_attack = "T1055"
    
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $sus_string = "INJECTED"
        
    condition:
        uint16(0) == 0x5A4D and
        all of ($api*) and
        $sus_string
}`,
      webshell: `rule ${formData.name || 'webshell_detection'} {
    meta:
        description = "Detects potential webshell"
        severity = "critical"
    
    strings:
        $php1 = "eval($_POST"
        $php2 = "base64_decode"
        $asp1 = "Request.QueryString"
        $asp2 = "eval(Request"
        
    condition:
        any of them
}`
    },
    sigma: {
      basic: `title: ${formData.name || 'Rule Name'}
id: ${generateUUID()}
status: experimental
description: ${formData.description || 'Rule description'}
author: SecuNik LogX
date: ${new Date().toISOString().split('T')[0]}
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        CommandLine|contains:
            - 'suspicious.exe'
            - 'malware.dll'
    condition: selection
falsepositives:
    - Unknown
level: ${formData.severity}`,
      network: `title: ${formData.name || 'Suspicious Network Activity'}
id: ${generateUUID()}
description: Detects suspicious network connections
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 
            - 4444
            - 5555
            - 8888
        Initiated: 'true'
    filter:
        DestinationIp|startswith:
            - '10.'
            - '192.168.'
            - '172.16.'
    condition: selection and not filter
level: high`
    },
    custom: {
      basic: `{
  "name": "${formData.name || 'Custom Rule'}",
  "description": "${formData.description || 'Custom detection rule'}",
  "severity": "${formData.severity}",
  "conditions": [
    {
      "field": "event_type",
      "operator": "equals",
      "value": "suspicious_activity"
    },
    {
      "field": "count",
      "operator": "greater_than",
      "value": 10
    }
  ],
  "logic": "AND",
  "actions": ["alert", "log"]
}`
    }
  };

  useEffect(() => {
    if (rule) {
      setFormData({
        name: rule.name || '',
        description: rule.description || '',
        type: rule.type || 'yara',
        severity: rule.severity || 'medium',
        enabled: rule.enabled !== false,
        content: rule.content || '',
        tags: rule.tags || [],
        metadata: rule.metadata || {}
      });
    }
  }, [rule]);

  function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
    // Clear error for this field
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const handleContentChange = (e) => {
    setFormData(prev => ({ ...prev, content: e.target.value }));
    setValidationResult(null);
  };

  const handleTagInput = (e) => {
    if (e.key === 'Enter' && e.target.value.trim()) {
      e.preventDefault();
      const newTag = e.target.value.trim();
      if (!formData.tags.includes(newTag)) {
        setFormData(prev => ({
          ...prev,
          tags: [...prev.tags, newTag]
        }));
      }
      e.target.value = '';
    }
  };

  const removeTag = (tagToRemove) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagToRemove)
    }));
  };

  const applyTemplate = (templateKey) => {
    const template = templates[formData.type]?.[templateKey];
    if (template) {
      setFormData(prev => ({ ...prev, content: template }));
      setSelectedTemplate(templateKey);
    }
  };

  const validateRule = async () => {
    setIsValidating(true);
    setValidationResult(null);
    
    try {
      const result = await rulesService.validateRule({
        type: formData.type,
        content: formData.content
      });
      
      setValidationResult(result);
      return result.valid;
    } catch (error) {
      setValidationResult({
        valid: false,
        errors: [error.message || 'Validation failed']
      });
      return false;
    } finally {
      setIsValidating(false);
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.name.trim()) {
      newErrors.name = 'Rule name is required';
    }
    
    if (!formData.description.trim()) {
      newErrors.description = 'Description is required';
    }
    
    if (!formData.content.trim()) {
      newErrors.content = 'Rule content is required';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    const isValid = await validateRule();
    if (!isValid) {
      return;
    }
    
    onSave(formData);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(formData.content);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 rounded-lg border border-gray-800 w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-800">
          <h2 className="text-xl font-semibold text-white">
            {rule ? 'Edit Rule' : 'Create New Rule'}
          </h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Basic Info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Rule Name
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  className={`
                    w-full px-3 py-2 bg-gray-800 border rounded-lg
                    text-white focus:outline-none focus:border-cyan-500
                    ${errors.name ? 'border-red-500' : 'border-gray-700'}
                  `}
                  placeholder="e.g., detect_suspicious_process"
                />
                {errors.name && (
                  <p className="mt-1 text-sm text-red-500">{errors.name}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Rule Type
                </label>
                <select
                  name="type"
                  value={formData.type}
                  onChange={handleChange}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="yara">YARA</option>
                  <option value="sigma">Sigma</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Description
              </label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleChange}
                rows={2}
                className={`
                  w-full px-3 py-2 bg-gray-800 border rounded-lg
                  text-white focus:outline-none focus:border-cyan-500
                  ${errors.description ? 'border-red-500' : 'border-gray-700'}
                `}
                placeholder="Describe what this rule detects..."
              />
              {errors.description && (
                <p className="mt-1 text-sm text-red-500">{errors.description}</p>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Severity
                </label>
                <select
                  name="severity"
                  value={formData.severity}
                  onChange={handleChange}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Tags
                </label>
                <input
                  type="text"
                  onKeyDown={handleTagInput}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                  placeholder="Press Enter to add tags..."
                />
                {formData.tags.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {formData.tags.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 bg-cyan-500/20 text-cyan-400 text-xs rounded flex items-center"
                      >
                        {tag}
                        <button
                          type="button"
                          onClick={() => removeTag(tag)}
                          className="ml-1 hover:text-cyan-300"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Templates */}
            {templates[formData.type] && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Templates
                </label>
                <div className="flex flex-wrap gap-2">
                  {Object.keys(templates[formData.type]).map(templateKey => (
                    <Button
                      key={templateKey}
                      type="button"
                      onClick={() => applyTemplate(templateKey)}
                      variant={selectedTemplate === templateKey ? 'primary' : 'secondary'}
                      size="sm"
                      leftIcon={<FileText className="w-4 h-4" />}
                    >
                      {templateKey.charAt(0).toUpperCase() + templateKey.slice(1)}
                    </Button>
                  ))}
                </div>
              </div>
            )}

            {/* Rule Content */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-gray-300">
                  Rule Content
                </label>
                <div className="flex items-center space-x-2">
                  <Button
                    type="button"
                    onClick={validateRule}
                    variant="secondary"
                    size="sm"
                    loading={isValidating}
                    leftIcon={<Code className="w-4 h-4" />}
                  >
                    Validate
                  </Button>
                  <Button
                    type="button"
                    onClick={copyToClipboard}
                    variant="secondary"
                    size="sm"
                    leftIcon={<Copy className="w-4 h-4" />}
                  >
                    Copy
                  </Button>
                </div>
              </div>
              <textarea
                ref={textareaRef}
                name="content"
                value={formData.content}
                onChange={handleContentChange}
                rows={15}
                className={`
                  w-full px-3 py-2 bg-gray-800 border rounded-lg
                  text-white font-mono text-sm focus:outline-none focus:border-cyan-500
                  ${errors.content ? 'border-red-500' : 'border-gray-700'}
                `}
                placeholder={`Enter your ${formData.type.toUpperCase()} rule here...`}
                spellCheck={false}
              />
              {errors.content && (
                <p className="mt-1 text-sm text-red-500">{errors.content}</p>
              )}
            </div>

            {/* Validation Result */}
            {validationResult && (
              <div className={`
                p-4 rounded-lg border
                ${validationResult.valid 
                  ? 'bg-green-500/10 border-green-500/50' 
                  : 'bg-red-500/10 border-red-500/50'
                }
              `}>
                <div className="flex items-start space-x-3">
                  {validationResult.valid ? (
                    <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  ) : (
                    <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1">
                    <p className={`font-medium ${
                      validationResult.valid ? 'text-green-400' : 'text-red-400'
                    }`}>
                      {validationResult.valid ? 'Rule is valid' : 'Validation failed'}
                    </p>
                    {validationResult.errors && validationResult.errors.length > 0 && (
                      <ul className="mt-2 space-y-1">
                        {validationResult.errors.map((error, idx) => (
                          <li key={idx} className="text-sm text-gray-300">
                            • {error}
                          </li>
                        ))}
                      </ul>
                    )}
                    {validationResult.warnings && validationResult.warnings.length > 0 && (
                      <ul className="mt-2 space-y-1">
                        {validationResult.warnings.map((warning, idx) => (
                          <li key={idx} className="text-sm text-yellow-400">
                            ⚠ {warning}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Enable/Disable */}
            <div className="flex items-center space-x-3">
              <input
                type="checkbox"
                id="enabled"
                name="enabled"
                checked={formData.enabled}
                onChange={handleChange}
                className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-cyan-500 focus:ring-cyan-500"
              />
              <label htmlFor="enabled" className="text-sm text-gray-300">
                Enable this rule immediately
              </label>
            </div>
          </form>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-800">
          <Button
            onClick={onClose}
            variant="secondary"
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            variant="primary"
            leftIcon={<Save className="w-4 h-4" />}
          >
            {rule ? 'Update Rule' : 'Create Rule'}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default RuleEditor;