import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  KeyIcon,
  BellIcon,
  CogIcon,
  DatabaseIcon,
  UserCircleIcon,
  MoonIcon,
  SunIcon,
  ShieldCheckIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import Card from '@/components/common/Card';
import Button from '@/components/common/Button';
import { settingsService } from '@/services/settingsService';
import { virusTotalService } from '@/services/virusTotalService';

const TABS = [
  { id: 'general', label: 'General', icon: CogIcon },
  { id: 'api', label: 'API Keys', icon: KeyIcon },
  { id: 'notifications', label: 'Notifications', icon: BellIcon },
  { id: 'storage', label: 'Storage', icon: DatabaseIcon },
  { id: 'profile', label: 'Profile', icon: UserCircleIcon }
];

const THEMES = [
  { id: 'dark', label: 'Dark', icon: MoonIcon },
  { id: 'darker', label: 'Darker', icon: MoonIcon },
  { id: 'cyber', label: 'Cyber', icon: ShieldCheckIcon }
];

const RETENTION_OPTIONS = [
  { value: 7, label: '7 days' },
  { value: 30, label: '30 days' },
  { value: 90, label: '90 days' },
  { value: 180, label: '180 days' },
  { value: 365, label: '1 year' },
  { value: -1, label: 'Forever' }
];

export default function Settings() {
  const [activeTab, setActiveTab] = useState('general');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [settings, setSettings] = useState({
    general: {
      theme: 'cyber',
      language: 'en',
      timezone: 'UTC',
      dateFormat: 'YYYY-MM-DD',
      timeFormat: '24h'
    },
    api: {
      virustotal_key: '',
      openai_key: '',
      webhook_url: ''
    },
    notifications: {
      email_enabled: false,
      email_address: '',
      webhook_enabled: false,
      notify_on_complete: true,
      notify_on_error: true,
      notify_on_threat: true,
      threat_threshold: 60
    },
    storage: {
      retention_days: 30,
      auto_cleanup: true,
      max_file_size: 500,
      allowed_extensions: [],
      compression_enabled: true
    },
    profile: {
      name: '',
      email: '',
      organization: '',
      role: ''
    }
  });
  const [vtQuota, setVtQuota] = useState(null);
  const [testingWebhook, setTestingWebhook] = useState(false);

  // Load settings
  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const data = await settingsService.getSettings();
      setSettings(data);
      
      // Check VT quota if key exists
      if (data.api.virustotal_key) {
        checkVTQuota();
      }
    } catch (error) {
      toast.error('Failed to load settings');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  // Save settings
  const handleSave = async () => {
    try {
      setSaving(true);
      await settingsService.updateSettings(settings);
      toast.success('Settings saved successfully');
      
      // Re-check VT quota if key changed
      if (settings.api.virustotal_key) {
        checkVTQuota();
      }
    } catch (error) {
      toast.error('Failed to save settings');
      console.error(error);
    } finally {
      setSaving(false);
    }
  };

  // Update setting
  const updateSetting = (category, key, value) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
  };

  // Check VirusTotal quota
  const checkVTQuota = async () => {
    try {
      const quota = await virusTotalService.getQuota();
      setVtQuota(quota);
    } catch (error) {
      console.error('Failed to check VT quota:', error);
    }
  };

  // Test webhook
  const testWebhook = async () => {
    if (!settings.api.webhook_url) {
      toast.error('Please enter a webhook URL');
      return;
    }

    try {
      setTestingWebhook(true);
      await settingsService.testWebhook(settings.api.webhook_url);
      toast.success('Webhook test successful');
    } catch (error) {
      toast.error('Webhook test failed');
    } finally {
      setTestingWebhook(false);
    }
  };

  // Clear storage
  const clearStorage = async () => {
    if (!confirm('This will delete all stored files and analysis data. Continue?')) {
      return;
    }

    try {
      await settingsService.clearStorage();
      toast.success('Storage cleared successfully');
    } catch (error) {
      toast.error('Failed to clear storage');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-blue mx-auto mb-4" />
          <p className="text-gray-400">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800/50 backdrop-blur border border-gray-700 rounded-lg p-6">
        <h1 className="text-2xl font-bold text-white mb-2">Settings</h1>
        <p className="text-gray-400">
          Configure SecuNik LogX to match your security workflow
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar */}
        <div className="lg:col-span-1">
          <Card className="bg-gray-800/50 p-0">
            <nav className="space-y-1">
              {TABS.map(tab => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`
                      w-full flex items-center space-x-3 px-4 py-3 text-left transition-colors
                      ${activeTab === tab.id
                        ? 'bg-cyber-blue/20 text-cyber-blue border-l-4 border-cyber-blue'
                        : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
                      }
                    `}
                  >
                    <Icon className="h-5 w-5" />
                    <span className="font-medium">{tab.label}</span>
                  </button>
                );
              })}
            </nav>
          </Card>
        </div>

        {/* Content */}
        <div className="lg:col-span-3">
          <Card className="bg-gray-800/50">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2 }}
            >
              {/* General Settings */}
              {activeTab === 'general' && (
                <div className="space-y-6">
                  <h2 className="text-lg font-medium text-white mb-4">General Settings</h2>
                  
                  {/* Theme */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Theme
                    </label>
                    <div className="grid grid-cols-3 gap-3">
                      {THEMES.map(theme => {
                        const Icon = theme.icon;
                        return (
                          <button
                            key={theme.id}
                            onClick={() => updateSetting('general', 'theme', theme.id)}
                            className={`
                              p-4 rounded-lg border-2 transition-all
                              ${settings.general.theme === theme.id
                                ? 'border-cyber-blue bg-cyber-blue/10'
                                : 'border-gray-700 hover:border-gray-600'
                              }
                            `}
                          >
                            <Icon className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                            <p className="text-sm text-gray-300">{theme.label}</p>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Date Format */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Date Format
                      </label>
                      <select
                        value={settings.general.dateFormat}
                        onChange={(e) => updateSetting('general', 'dateFormat', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                      >
                        <option value="YYYY-MM-DD">2024-03-15</option>
                        <option value="DD/MM/YYYY">15/03/2024</option>
                        <option value="MM/DD/YYYY">03/15/2024</option>
                        <option value="MMM DD, YYYY">Mar 15, 2024</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Time Format
                      </label>
                      <select
                        value={settings.general.timeFormat}
                        onChange={(e) => updateSetting('general', 'timeFormat', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                      >
                        <option value="24h">24-hour (14:30)</option>
                        <option value="12h">12-hour (2:30 PM)</option>
                      </select>
                    </div>
                  </div>

                  {/* Language & Timezone */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Language
                      </label>
                      <select
                        value={settings.general.language}
                        onChange={(e) => updateSetting('general', 'language', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                      >
                        <option value="en">English</option>
                        <option value="es">Español</option>
                        <option value="fr">Français</option>
                        <option value="de">Deutsch</option>
                        <option value="ja">日本語</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Timezone
                      </label>
                      <select
                        value={settings.general.timezone}
                        onChange={(e) => updateSetting('general', 'timezone', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                      >
                        <option value="UTC">UTC</option>
                        <option value="America/New_York">Eastern Time</option>
                        <option value="America/Chicago">Central Time</option>
                        <option value="America/Denver">Mountain Time</option>
                        <option value="America/Los_Angeles">Pacific Time</option>
                        <option value="Europe/London">London</option>
                        <option value="Europe/Paris">Paris</option>
                        <option value="Asia/Tokyo">Tokyo</option>
                      </select>
                    </div>
                  </div>
                </div>
              )}

              {/* API Settings */}
              {activeTab === 'api' && (
                <div className="space-y-6">
                  <h2 className="text-lg font-medium text-white mb-4">API Configuration</h2>
                  
                  {/* VirusTotal */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      VirusTotal API Key
                    </label>
                    <div className="flex space-x-3">
                      <input
                        type="password"
                        value={settings.api.virustotal_key}
                        onChange={(e) => updateSetting('api', 'virustotal_key', e.target.value)}
                        placeholder="Enter your VirusTotal API key"
                        className="flex-1 px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                      />
                      <Button
                        variant="secondary"
                        onClick={checkVTQuota}
                        disabled={!settings.api.virustotal_key}
                      >
                        Check Quota
                      </Button>
                    </div>
                    
                    {vtQuota && (
                      <div className="mt-2 p-3 bg-gray-900/50 rounded-lg">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-gray-400">Daily Quota:</span>
                          <span className="text-white">
                            {vtQuota.used} / {vtQuota.allowed}
                          </span>
                        </div>
                        <div className="mt-2 bg-gray-700 rounded-full h-2">
                          <div 
                            className="bg-cyber-blue h-2 rounded-full transition-all"
                            style={{ width: `${(vtQuota.used / vtQuota.allowed) * 100}%` }}
                          />
                        </div>
                      </div>
                    )}
                    
                    <p className="mt-2 text-xs text-gray-500">
                      Get your API key from <a href="https://www.virustotal.com" target="_blank" rel="noopener noreferrer" className="text-cyber-blue hover:underline">virustotal.com</a>
                    </p>
                  </div>

                  {/* OpenAI */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      OpenAI API Key
                    </label>
                    <input
                      type="password"
                      value={settings.api.openai_key}
                      onChange={(e) => updateSetting('api', 'openai_key', e.target.value)}
                      placeholder="Enter your OpenAI API key"
                      className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                    />
                    <p className="mt-2 text-xs text-gray-500">
                      Used for AI-powered analysis. Get your key from <a href="https://platform.openai.com" target="_blank" rel="noopener noreferrer" className="text-cyber-blue hover:underline">platform.openai.com</a>
                    </p>
                  </div>

                  {/* Webhook */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Webhook URL
                    </label>
                    <div className="flex space-x-3">
                      <input
                        type="url"
                        value={settings.api.webhook_url}
                        onChange={(e) => updateSetting('api', 'webhook_url', e.target.value)}
                        placeholder="https://your-webhook-endpoint.com"
                        className="flex-1 px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                      />
                      <Button
                        variant="secondary"
                        onClick={testWebhook}
                        loading={testingWebhook}
                        disabled={!settings.api.webhook_url}
                      >
                        Test
                      </Button>
                    </div>
                    <p className="mt-2 text-xs text-gray-500">
                      Receive real-time notifications about analysis results
                    </p>
                  </div>
                </div>
              )}

              {/* Notification Settings */}
              {activeTab === 'notifications' && (
                <div className="space-y-6">
                  <h2 className="text-lg font-medium text-white mb-4">Notification Preferences</h2>
                  
                  {/* Email Notifications */}
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-white">Email Notifications</h3>
                        <p className="text-xs text-gray-400">Receive email alerts for important events</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={settings.notifications.email_enabled}
                          onChange={(e) => updateSetting('notifications', 'email_enabled', e.target.checked)}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-blue"></div>
                      </label>
                    </div>

                    {settings.notifications.email_enabled && (
                      <input
                        type="email"
                        value={settings.notifications.email_address}
                        onChange={(e) => updateSetting('notifications', 'email_address', e.target.value)}
                        placeholder="your-email@example.com"
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                      />
                    )}
                  </div>

                  {/* Webhook Notifications */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-medium text-white">Webhook Notifications</h3>
                      <p className="text-xs text-gray-400">Send events to your webhook endpoint</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings.notifications.webhook_enabled}
                        onChange={(e) => updateSetting('notifications', 'webhook_enabled', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-blue"></div>
                    </label>
                  </div>

                  {/* Event Types */}
                  <div className="space-y-3">
                    <h3 className="text-sm font-medium text-white">Notify me when:</h3>
                    
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={settings.notifications.notify_on_complete}
                        onChange={(e) => updateSetting('notifications', 'notify_on_complete', e.target.checked)}
                        className="rounded border-gray-600 bg-gray-800 text-cyber-blue focus:ring-cyber-blue"
                      />
                      <span className="text-sm text-gray-300">Analysis completes</span>
                    </label>

                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={settings.notifications.notify_on_error}
                        onChange={(e) => updateSetting('notifications', 'notify_on_error', e.target.checked)}
                        className="rounded border-gray-600 bg-gray-800 text-cyber-blue focus:ring-cyber-blue"
                      />
                      <span className="text-sm text-gray-300">Analysis encounters an error</span>
                    </label>

                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={settings.notifications.notify_on_threat}
                        onChange={(e) => updateSetting('notifications', 'notify_on_threat', e.target.checked)}
                        className="rounded border-gray-600 bg-gray-800 text-cyber-blue focus:ring-cyber-blue"
                      />
                      <span className="text-sm text-gray-300">High threat detected</span>
                    </label>
                  </div>

                  {/* Threat Threshold */}
                  {settings.notifications.notify_on_threat && (
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Threat Score Threshold
                      </label>
                      <div className="flex items-center space-x-4">
                        <input
                          type="range"
                          min="0"
                          max="100"
                          value={settings.notifications.threat_threshold}
                          onChange={(e) => updateSetting('notifications', 'threat_threshold', parseInt(e.target.value))}
                          className="flex-1"
                        />
                        <span className="text-white font-medium w-12 text-right">
                          {settings.notifications.threat_threshold}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Storage Settings */}
              {activeTab === 'storage' && (
                <div className="space-y-6">
                  <h2 className="text-lg font-medium text-white mb-4">Storage Management</h2>
                  
                  {/* Data Retention */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Data Retention Period
                    </label>
                    <select
                      value={settings.storage.retention_days}
                      onChange={(e) => updateSetting('storage', 'retention_days', parseInt(e.target.value))}
                      className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                    >
                      {RETENTION_OPTIONS.map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <p className="mt-2 text-xs text-gray-500">
                      Analysis data older than this will be automatically deleted
                    </p>
                  </div>

                  {/* Auto Cleanup */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-medium text-white">Automatic Cleanup</h3>
                      <p className="text-xs text-gray-400">Delete old files according to retention policy</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings.storage.auto_cleanup}
                        onChange={(e) => updateSetting('storage', 'auto_cleanup', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-blue"></div>
                    </label>
                  </div>

                  {/* Max File Size */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Maximum File Size (MB)
                    </label>
                    <input
                      type="number"
                      value={settings.storage.max_file_size}
                      onChange={(e) => updateSetting('storage', 'max_file_size', parseInt(e.target.value))}
                      min="1"
                      max="5000"
                      className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                    />
                  </div>

                  {/* Compression */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-medium text-white">Enable Compression</h3>
                      <p className="text-xs text-gray-400">Compress stored files to save space</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings.storage.compression_enabled}
                        onChange={(e) => updateSetting('storage', 'compression_enabled', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-blue"></div>
                    </label>
                  </div>

                  {/* Clear Storage */}
                  <div className="pt-6 border-t border-gray-700">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-white">Clear All Storage</h3>
                        <p className="text-xs text-gray-400">Delete all files and analysis data</p>
                      </div>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={clearStorage}
                      >
                        Clear Storage
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {/* Profile Settings */}
              {activeTab === 'profile' && (
                <div className="space-y-6">
                  <h2 className="text-lg font-medium text-white mb-4">Profile Information</h2>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Name
                      </label>
                      <input
                        type="text"
                        value={settings.profile.name}
                        onChange={(e) => updateSetting('profile', 'name', e.target.value)}
                        placeholder="Your name"
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Email
                      </label>
                      <input
                        type="email"
                        value={settings.profile.email}
                        onChange={(e) => updateSetting('profile', 'email', e.target.value)}
                        placeholder="your-email@example.com"
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Organization
                      </label>
                      <input
                        type="text"
                        value={settings.profile.organization}
                        onChange={(e) => updateSetting('profile', 'organization', e.target.value)}
                        placeholder="Your organization"
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        Role
                      </label>
                      <input
                        type="text"
                        value={settings.profile.role}
                        onChange={(e) => updateSetting('profile', 'role', e.target.value)}
                        placeholder="Security Analyst"
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500"
                      />
                    </div>
                  </div>

                  <div className="pt-6 border-t border-gray-700">
                    <h3 className="text-sm font-medium text-white mb-4">Account Actions</h3>
                    <div className="space-y-3">
                      <Button variant="secondary" className="w-full justify-center">
                        Export All Data
                      </Button>
                      <Button variant="danger" className="w-full justify-center">
                        Delete Account
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </motion.div>

            {/* Save Button */}
            <div className="mt-8 pt-6 border-t border-gray-700 flex justify-end">
              <Button
                size="lg"
                loading={saving}
                onClick={handleSave}
                icon={CheckCircleIcon}
              >
                Save Changes
              </Button>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}