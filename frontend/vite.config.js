import forms from '@tailwindcss/forms';
import typography from '@tailwindcss/typography';

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Primary cyber colors
        cyber: {
          50: '#ecfeff',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
          950: '#083344',
        },
        
        // Neon accent colors
        neon: {
          blue: '#00d4ff',
          green: '#00ff88',
          purple: '#9333ea',
          pink: '#ff0080',
          yellow: '#ffff00',
          orange: '#ff8800',
        },
        
        // Dark theme colors
        dark: {
          50: '#18181b',
          100: '#27272a',
          200: '#3f3f46',
          300: '#52525b',
          400: '#71717a',
          500: '#a1a1aa',
          600: '#d4d4d8',
          700: '#e4e4e7',
          800: '#f4f4f5',
          900: '#fafafa',
        },
        
        // Status colors
        status: {
          success: '#10b981',
          warning: '#f59e0b',
          error: '#ef4444',
          info: '#3b82f6',
        },
        
        // Threat level colors
        threat: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#f59e0b',
          low: '#84cc16',
          info: '#06b6d4',
        },
      },
      
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'Monaco', 'monospace'],
        cyber: ['Orbitron', 'sans-serif'],
      },
      
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan': 'scan 3s ease-in-out infinite',
        'flicker': 'flicker 2s infinite',
        'slide-up': 'slide-up 0.3s ease-out',
        'slide-down': 'slide-down 0.3s ease-out',
        'fade-in': 'fade-in 0.2s ease-out',
        'progress': 'progress 2s ease-in-out infinite',
        'matrix': 'matrix 20s linear infinite',
      },
      
      keyframes: {
        glow: {
          'from': { 
            textShadow: '0 0 10px #00d4ff, 0 0 20px #00d4ff, 0 0 30px #00d4ff',
            filter: 'brightness(1)',
          },
          'to': { 
            textShadow: '0 0 20px #00d4ff, 0 0 30px #00d4ff, 0 0 40px #00d4ff',
            filter: 'brightness(1.1)',
          },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        flicker: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.8 },
        },
        'slide-up': {
          '0%': { transform: 'translateY(10px)', opacity: 0 },
          '100%': { transform: 'translateY(0)', opacity: 1 },
        },
        'slide-down': {
          '0%': { transform: 'translateY(-10px)', opacity: 0 },
          '100%': { transform: 'translateY(0)', opacity: 1 },
        },
        'fade-in': {
          '0%': { opacity: 0 },
          '100%': { opacity: 1 },
        },
        progress: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        matrix: {
          '0%': { transform: 'translateY(0)' },
          '100%': { transform: 'translateY(100%)' },
        },
      },
      
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'cyber-grid': 'linear-gradient(rgba(6, 182, 212, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(6, 182, 212, 0.1) 1px, transparent 1px)',
        'scan-line': 'linear-gradient(to bottom, transparent 0%, rgba(0, 212, 255, 0.1) 50%, transparent 100%)',
      },
      
      boxShadow: {
        'neon': '0 0 5px theme("colors.neon.blue"), 0 0 20px theme("colors.neon.blue")',
        'neon-lg': '0 0 10px theme("colors.neon.blue"), 0 0 40px theme("colors.neon.blue")',
        'inner-glow': 'inset 0 0 20px rgba(0, 212, 255, 0.2)',
      },
      
      backdropBlur: {
        xs: '2px',
      },
      
      transitionTimingFunction: {
        'bounce-in': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
      },
      
      screens: {
        '3xl': '1920px',
      },
      
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },
    },
  },
  plugins: [
    forms({
      strategy: 'class',
    }),
    typography,
    
    // Custom plugin for cyber effects
    function({ addUtilities, addComponents, theme }) {
      // Utility classes
      addUtilities({
        '.text-glow': {
          textShadow: '0 0 10px currentColor',
        },
        '.no-scrollbar': {
          '-ms-overflow-style': 'none',
          'scrollbar-width': 'none',
          '&::-webkit-scrollbar': {
            display: 'none',
          },
        },
        '.cyber-border': {
          border: '1px solid',
          borderImage: 'linear-gradient(45deg, #00d4ff, #0891b2) 1',
        },
      });
      
      // Component classes
      addComponents({
        '.btn-cyber': {
          '@apply relative px-6 py-2 font-medium text-cyber-400 bg-gray-900 border border-cyber-500 rounded-lg transition-all duration-300 hover:bg-cyber-500 hover:text-gray-900 hover:shadow-neon': {},
          '&::before': {
            content: '""',
            '@apply absolute inset-0 rounded-lg bg-cyber-500 opacity-0 blur-md transition-opacity duration-300': {},
          },
          '&:hover::before': {
            '@apply opacity-30': {},
          },
        },
        '.btn-cyber-primary': {
          '@apply relative px-6 py-2.5 bg-cyber-600 text-white font-medium rounded-lg overflow-hidden transition-all duration-300 hover:bg-cyber-700 hover:shadow-lg hover:shadow-cyber-500/25 active:scale-95': {},
          '&::before': {
            content: '""',
            '@apply absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full transition-transform duration-700': {},
          },
          '&:hover::before': {
            '@apply translate-x-full': {},
          },
        },
        '.card-cyber': {
          '@apply bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6 transition-all duration-300 hover:border-cyber-500/50 hover:shadow-lg hover:shadow-cyber-500/10': {},
        },
        '.input-cyber': {
          '@apply bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-gray-100 placeholder-gray-500 transition-all duration-200 focus:border-cyber-500 focus:ring-2 focus:ring-cyber-500/20 focus:bg-gray-900 focus:outline-none': {},
        },
        '.text-gradient': {
          '@apply bg-clip-text text-transparent bg-gradient-to-r from-cyber-400 to-blue-500': {},
        },
      });
    },
  ],
}