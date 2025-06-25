import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronUpIcon,
  ChevronDownIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';
import clsx from 'clsx';
import LoadingSpinner from './LoadingSpinner';

const Table = ({
  data = [],
  columns = [],
  loading = false,
  error = null,
  onRowClick,
  selectedRows = [],
  onSelectionChange,
  pagination,
  onPageChange,
  searchable = false,
  sortable = true,
  striped = true,
  compact = false,
  className,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: null, direction: null });

  // Filter data based on search
  const filteredData = useMemo(() => {
    if (!searchable || !searchTerm) return data;

    return data.filter(row => {
      return columns.some(column => {
        const value = column.accessor ? row[column.accessor] : '';
        return String(value).toLowerCase().includes(searchTerm.toLowerCase());
      });
    });
  }, [data, searchTerm, columns, searchable]);

  // Sort data
  const sortedData = useMemo(() => {
    if (!sortable || !sortConfig.key) return filteredData;

    const sorted = [...filteredData].sort((a, b) => {
      const aValue = a[sortConfig.key];
      const bValue = b[sortConfig.key];

      if (aValue === null || aValue === undefined) return 1;
      if (bValue === null || bValue === undefined) return -1;

      if (aValue < bValue) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      if (aValue > bValue) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });

    return sorted;
  }, [filteredData, sortConfig, sortable]);

  // Handle sort
  const handleSort = (key) => {
    if (!sortable) return;

    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  // Handle row selection
  const handleRowSelection = (row) => {
    if (!onSelectionChange) return;

    const isSelected = selectedRows.some(r => r.id === row.id);
    if (isSelected) {
      onSelectionChange(selectedRows.filter(r => r.id !== row.id));
    } else {
      onSelectionChange([...selectedRows, row]);
    }
  };

  // Select all rows
  const handleSelectAll = () => {
    if (!onSelectionChange) return;

    if (selectedRows.length === sortedData.length) {
      onSelectionChange([]);
    } else {
      onSelectionChange(sortedData);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <LoadingSpinner size="lg" text="Loading data..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center p-8">
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className={clsx('space-y-4', className)}>
      {/* Search */}
      {searchable && (
        <div className="relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500 focus:outline-none"
          />
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-700">
              {onSelectionChange && (
                <th className="px-4 py-3 text-left">
                  <input
                    type="checkbox"
                    checked={selectedRows.length === sortedData.length && sortedData.length > 0}
                    indeterminate={selectedRows.length > 0 && selectedRows.length < sortedData.length}
                    onChange={handleSelectAll}
                    className="rounded border-gray-600 text-cyber-500 focus:ring-cyber-500"
                  />
                </th>
              )}
              {columns.map((column) => (
                <th
                  key={column.accessor}
                  className={clsx(
                    'px-4 text-left text-sm font-medium text-gray-400',
                    compact ? 'py-2' : 'py-3',
                    sortable && column.sortable !== false && 'cursor-pointer hover:text-white'
                  )}
                  onClick={() => column.sortable !== false && handleSort(column.accessor)}
                >
                  <div className="flex items-center space-x-2">
                    <span>{column.header}</span>
                    {sortable && column.sortable !== false && (
                      <div className="flex flex-col">
                        <ChevronUpIcon
                          className={clsx(
                            'w-3 h-3',
                            sortConfig.key === column.accessor && sortConfig.direction === 'asc'
                              ? 'text-cyber-500'
                              : 'text-gray-600'
                          )}
                        />
                        <ChevronDownIcon
                          className={clsx(
                            'w-3 h-3 -mt-1',
                            sortConfig.key === column.accessor && sortConfig.direction === 'desc'
                              ? 'text-cyber-500'
                              : 'text-gray-600'
                          )}
                        />
                      </div>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <AnimatePresence>
              {sortedData.map((row, index) => (
                <motion.tr
                  key={row.id || index}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className={clsx(
                    'border-b border-gray-800 transition-colors',
                    onRowClick && 'cursor-pointer hover:bg-gray-800/50',
                    striped && index % 2 === 0 && 'bg-gray-900/30',
                    selectedRows.some(r => r.id === row.id) && 'bg-cyber-900/20'
                  )}
                  onClick={() => onRowClick && onRowClick(row)}
                >
                  {onSelectionChange && (
                    <td className={clsx('px-4', compact ? 'py-2' : 'py-3')}>
                      <input
                        type="checkbox"
                        checked={selectedRows.some(r => r.id === row.id)}
                        onChange={(e) => {
                          e.stopPropagation();
                          handleRowSelection(row);
                        }}
                        className="rounded border-gray-600 text-cyber-500 focus:ring-cyber-500"
                      />
                    </td>
                  )}
                  {columns.map((column) => (
                    <td
                      key={column.accessor}
                      className={clsx(
                        'px-4 text-sm text-gray-300',
                        compact ? 'py-2' : 'py-3'
                      )}
                    >
                      {column.cell
                        ? column.cell(row[column.accessor], row)
                        : row[column.accessor]}
                    </td>
                  ))}
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>

        {sortedData.length === 0 && (
          <div className="text-center py-8 text-gray-500">
            No data available
          </div>
        )}
      </div>

      {/* Pagination */}
      {pagination && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-400">
            Showing {((pagination.page - 1) * pagination.limit) + 1} to{' '}
            {Math.min(pagination.page * pagination.limit, pagination.total)} of{' '}
            {pagination.total} results
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => onPageChange(pagination.page - 1)}
              disabled={pagination.page === 1}
              className="p-2 hover:bg-gray-800 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeftIcon className="w-5 h-5" />
            </button>
            <span className="px-3 py-1 text-sm">
              Page {pagination.page} of {pagination.totalPages}
            </span>
            <button
              onClick={() => onPageChange(pagination.page + 1)}
              disabled={pagination.page === pagination.totalPages}
              className="p-2 hover:bg-gray-800 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronRightIcon className="w-5 h-5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};