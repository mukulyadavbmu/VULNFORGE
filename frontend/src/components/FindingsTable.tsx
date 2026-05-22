import React, { useMemo } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
} from '@tanstack/react-table';

const columnHelper = createColumnHelper<any>();

const columns = [
  columnHelper.accessor('type', {
    header: 'Vulnerability Type',
    cell: info => <span className="font-semibold">{info.getValue()}</span>,
  }),
  columnHelper.accessor('severity', {
    header: 'Severity',
    cell: info => {
      const sev = info.getValue() as string;
      const colors: Record<string, string> = {
        critical: 'bg-danger text-background',
        high: 'bg-danger/80 text-background',
        medium: 'bg-warning text-background',
        low: 'bg-primary/80 text-background',
      };
      return (
        <span className={`px-2 py-1 rounded text-xs uppercase font-bold ${colors[sev] || 'bg-border text-textMain'}`}>
          {sev}
        </span>
      );
    },
  }),
  columnHelper.accessor('url', {
    header: 'Affected Endpoint',
    cell: info => <div className="max-w-xs truncate font-mono text-xs" title={info.getValue()}>{info.getValue()}</div>,
  }),
  columnHelper.accessor('reliabilityTier', {
    header: 'Reliability',
    cell: info => {
      const tier = info.getValue() || 'signal';
      return (
        <span className="bg-surface border border-border px-2 py-1 rounded text-xs capitalize text-textMuted">
          {tier}
        </span>
      );
    },
  }),
];

export const FindingsTable: React.FC<{ findings: any[] }> = ({ findings }) => {
  const data = useMemo(() => findings || [], [findings]);

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  if (!findings || findings.length === 0) {
    return <div className="p-6 text-center text-textMuted border border-dashed border-border rounded-lg">No findings discovered yet.</div>;
  }

  return (
    <div className="overflow-x-auto border border-border rounded-lg bg-surface">
      <table className="w-full text-sm text-left">
        <thead className="bg-[#0D1117] text-textMuted border-b border-border">
          {table.getHeaderGroups().map(headerGroup => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map(header => (
                <th key={header.id} className="px-4 py-3 font-medium cursor-pointer" onClick={header.column.getToggleSortingHandler()}>
                  {flexRender(header.column.columnDef.header, header.getContext())}
                  {{
                    asc: ' ▲',
                    desc: ' ▼',
                  }[header.column.getIsSorted() as string] ?? null}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map(row => (
            <tr key={row.id} className="border-b border-border/50 hover:bg-[#0D1117]/50 transition-colors">
              {row.getVisibleCells().map(cell => (
                <td key={cell.id} className="px-4 py-3">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
