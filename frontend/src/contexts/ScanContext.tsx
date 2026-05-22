import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { getScan, getScanState, getScanSurfaceSummary } from '../api';

interface ScanContextValue {
  scanId: string | null;
  scanData: any | null;
  scanState: any | null;
  surfaceSummary: any | null;
  isLoading: boolean;
  error: string | null;
  refreshScan: () => Promise<void>;
}

const ScanContext = createContext<ScanContextValue | undefined>(undefined);

export const ScanProvider: React.FC<{ scanId: string; children: ReactNode }> = ({ scanId, children }) => {
  const [scanData, setScanData] = useState<any | null>(null);
  const [scanState, setScanState] = useState<any | null>(null);
  const [surfaceSummary, setSurfaceSummary] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshScan = async () => {
    if (!scanId) return;
    try {
      setError(null);
      const [data, state, summary] = await Promise.all([
        getScan(scanId).catch(() => null),
        getScanState(scanId).catch(() => null),
        getScanSurfaceSummary(scanId).catch(() => null),
      ]);
      setScanData(data);
      setScanState(state);
      setSurfaceSummary(summary);
    } catch (err: any) {
      setError(err.message || 'Failed to load scan data');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    setIsLoading(true);
    setScanData(null);
    setScanState(null);
    setSurfaceSummary(null);
    void refreshScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  return (
    <ScanContext.Provider value={{ scanId, scanData, scanState, surfaceSummary, isLoading, error, refreshScan }}>
      {children}
    </ScanContext.Provider>
  );
};

export const useScanContext = () => {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error('useScanContext must be used within a ScanProvider');
  }
  return context;
};
