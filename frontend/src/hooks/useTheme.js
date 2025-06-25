import { useState, useEffect, useCallback, createContext, useContext } from 'react';
import { settingsService } from '../services/settingsService';
import { STORAGE_KEYS } from '../utils/constants';

// Theme context
const ThemeContext = createContext(null);

// Available themes
export const THEMES = {
  DARK: 'dark',
  LIGHT: 'light',
  CYBER: 'cyber',
  MIDNIGHT: 'midnight',
  MATRIX: 'matrix'
};

// Theme configurations
const themeConfigs = {
  dark: {
    name: 'Dark',
    primary: '#06b6d4', // cyan-500
    background: '#0f172a',
    surface: '#1e293b',
    text: '#f1f5f9',
    description: 'Default dark theme'
  },
  light: {
    name: 'Light',
    primary: '#0891b2', // cyan-600
    background: '#ffffff',
    surface: '#f8fafc',
    text: '#0f172a',
    description: 'Light theme for daytime use'
  },
  cyber: {
    name: 'Cyber',
    primary: '#00ff00',
    background: '#000000',
    surface: '#0a0a0a',
    text: '#00ff00',
    description: 'Matrix-inspired cyber theme'
  },
  midnight: {
    name: 'Midnight',
    primary: '#818cf8', // indigo-400
    background: '#0f0f23',
    surface: '#1a1a2e',
    text: '#e0e7ff',
    description: 'Deep midnight blue theme'
  },
  matrix: {
    name: 'Matrix',
    primary: '#00ff41',
    background: '#0d0208',
    surface: '#003b00',
    text: '#008f11',
    description: 'Matrix rain theme'
  }
};

/**
 * Theme Provider Component
 */
export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(THEMES.DARK);
  const [customColors, setCustomColors] = useState({});
  const [isLoading, setIsLoading] = useState(true);

  // Load theme from storage on mount
  useEffect(() => {
    const loadTheme = async () => {
      try {
        // Try local storage first
        const savedTheme = localStorage.getItem(STORAGE_KEYS.THEME);
        if (savedTheme && Object.values(THEMES).includes(savedTheme)) {
          setTheme(savedTheme);
          applyTheme(savedTheme);
        }

        // Load from server settings
        const settings = await settingsService.getThemeSettings();
        if (settings.theme) {
          setTheme(settings.theme);
          applyTheme(settings.theme);
        }
        if (settings.customColors) {
          setCustomColors(settings.customColors);
        }
      } catch (error) {
        console.error('Failed to load theme settings:', error);
      } finally {
        setIsLoading(false);
      }
    };

    loadTheme();
  }, []);

  // Apply theme to document
  const applyTheme = useCallback((themeName) => {
    const config = themeConfigs[themeName] || themeConfigs.dark;
    const root = document.documentElement;

    // Set CSS variables
    root.style.setProperty('--color-primary', config.primary);
    root.style.setProperty('--color-background', config.background);
    root.style.setProperty('--color-surface', config.surface);
    root.style.setProperty('--color-text', config.text);

    // Set data attribute for CSS
    root.setAttribute('data-theme', themeName);

    // Add theme classes
    root.classList.remove(...Object.keys(THEMES).map(k => `theme-${THEMES[k]}`));
    root.classList.add(`theme-${themeName}`);
  }, []);

  // Change theme
  const changeTheme = useCallback(async (newTheme) => {
    if (!Object.values(THEMES).includes(newTheme)) {
      console.error('Invalid theme:', newTheme);
      return;
    }

    setTheme(newTheme);
    applyTheme(newTheme);
    
    // Save to local storage
    localStorage.setItem(STORAGE_KEYS.THEME, newTheme);

    // Save to server
    try {
      await settingsService.updateThemeSettings({ theme: newTheme });
    } catch (error) {
      console.error('Failed to save theme settings:', error);
    }
  }, [applyTheme]);

  // Update custom colors
  const updateCustomColors = useCallback(async (colors) => {
    setCustomColors(colors);
    
    // Apply custom colors
    const root = document.documentElement;
    Object.entries(colors).forEach(([key, value]) => {
      root.style.setProperty(`--color-custom-${key}`, value);
    });

    // Save to server
    try {
      await settingsService.updateThemeSettings({ 
        theme,
        customColors: colors 
      });
    } catch (error) {
      console.error('Failed to save custom colors:', error);
    }
  }, [theme]);

  // Reset to default theme
  const resetTheme = useCallback(() => {
    changeTheme(THEMES.DARK);
    setCustomColors({});
  }, [changeTheme]);

  const value = {
    theme,
    themes: THEMES,
    themeConfig: themeConfigs[theme],
    customColors,
    isLoading,
    changeTheme,
    updateCustomColors,
    resetTheme
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};

/**
 * Hook to use theme context
 */
export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return context;
};

/**
 * Hook for theme-aware styling
 */
export const useThemeStyles = () => {
  const { theme, themeConfig } = useTheme();

  const styles = {
    // Background styles
    background: {
      primary: `bg-${theme === 'light' ? 'white' : 'gray-900'}`,
      secondary: `bg-${theme === 'light' ? 'gray-50' : 'gray-800'}`,
      tertiary: `bg-${theme === 'light' ? 'gray-100' : 'gray-700'}`
    },
    
    // Text styles
    text: {
      primary: `text-${theme === 'light' ? 'gray-900' : 'white'}`,
      secondary: `text-${theme === 'light' ? 'gray-700' : 'gray-300'}`,
      tertiary: `text-${theme === 'light' ? 'gray-500' : 'gray-400'}`
    },
    
    // Border styles
    border: {
      primary: `border-${theme === 'light' ? 'gray-200' : 'gray-700'}`,
      secondary: `border-${theme === 'light' ? 'gray-300' : 'gray-600'}`
    },
    
    // Component styles
    card: `${
      theme === 'light' ? 'bg-white border-gray-200' : 'bg-gray-800 border-gray-700'
    } border rounded-lg`,
    
    button: {
      primary: `bg-${themeConfig.primary} hover:bg-opacity-80 text-white`,
      secondary: `bg-${theme === 'light' ? 'gray-200' : 'gray-700'} hover:bg-opacity-80 text-${
        theme === 'light' ? 'gray-900' : 'white'
      }`
    },
    
    input: `bg-${theme === 'light' ? 'white' : 'gray-800'} border-${
      theme === 'light' ? 'gray-300' : 'gray-600'
    } text-${theme === 'light' ? 'gray-900' : 'white'}`
  };

  return styles;
};

/**
 * Hook for theme animations
 */
export const useThemeAnimations = () => {
  const { theme } = useTheme();

  const animations = {
    // Cyber theme animations
    cyber: theme === 'cyber' || theme === 'matrix' ? {
      glow: 'animate-pulse shadow-lg shadow-green-500/50',
      flicker: 'animate-flicker',
      scan: 'animate-scan'
    } : {},
    
    // General animations
    fadeIn: 'animate-fadeIn',
    slideIn: 'animate-slideIn',
    bounce: 'animate-bounce',
    spin: 'animate-spin',
    pulse: 'animate-pulse'
  };

  return animations;
};

/**
 * Hook for theme-specific effects
 */
export const useThemeEffects = () => {
  const { theme } = useTheme();

  useEffect(() => {
    // Add theme-specific effects
    if (theme === 'matrix') {
      // Add matrix rain effect
      const canvas = document.createElement('canvas');
      canvas.id = 'matrix-rain';
      canvas.style.position = 'fixed';
      canvas.style.top = '0';
      canvas.style.left = '0';
      canvas.style.width = '100%';
      canvas.style.height = '100%';
      canvas.style.pointerEvents = 'none';
      canvas.style.opacity = '0.1';
      canvas.style.zIndex = '0';
      
      document.body.appendChild(canvas);
      
      // Matrix rain animation would go here
      
      return () => {
        document.body.removeChild(canvas);
      };
    }
  }, [theme]);
};

// Export theme utilities
export const getThemeColor = (colorName, theme = 'dark') => {
  const config = themeConfigs[theme];
  return config[colorName] || config.primary;
};

export const isLightTheme = (theme) => {
  return theme === 'light';
};

export const isDarkTheme = (theme) => {
  return !isLightTheme(theme);
};