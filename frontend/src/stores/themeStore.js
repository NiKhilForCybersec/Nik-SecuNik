import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export const useThemeStore = create(
  persist(
    (set) => ({
      theme: 'dark',
      
      initializeTheme: () => {
        const savedTheme = localStorage.getItem('theme-storage');
        if (savedTheme) {
          const { state } = JSON.parse(savedTheme);
          set({ theme: state.theme });
          document.documentElement.classList.toggle('dark', state.theme === 'dark');
        }
      },
      
      toggleTheme: () => set((state) => {
        const newTheme = state.theme === 'dark' ? 'light' : 'dark';
        document.documentElement.classList.toggle('dark', newTheme === 'dark');
        return { theme: newTheme };
      }),
      
      setTheme: (theme) => set(() => {
        document.documentElement.classList.toggle('dark', theme === 'dark');
        return { theme };
      }),
    }),
    {
      name: 'theme-storage',
    }
  )
);