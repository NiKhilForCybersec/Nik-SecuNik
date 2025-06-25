import { create } from 'zustand';

export const useNotificationStore = create((set) => ({
  notifications: [],
  
  addNotification: (notification) => set((state) => ({
    notifications: [
      {
        id: Date.now(),
        timestamp: new Date(),
        read: false,
        ...notification,
      },
      ...state.notifications,
    ].slice(0, 50), // Keep only last 50 notifications
  })),
  
  markAsRead: (id) => set((state) => ({
    notifications: state.notifications.map((n) =>
      n.id === id ? { ...n, read: true } : n
    ),
  })),
  
  markAllAsRead: () => set((state) => ({
    notifications: state.notifications.map((n) => ({ ...n, read: true })),
  })),
  
  clearAll: () => set({ notifications: [] }),
  
  removeNotification: (id) => set((state) => ({
    notifications: state.notifications.filter((n) => n.id !== id),
  })),
}));