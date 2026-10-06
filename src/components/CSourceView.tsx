import React, { useState } from 'react';
import { Check, Copy, Download, PackageCheck } from 'lucide-react';
import {
  buildSelfExtractingCBundle,
  C_SOURCE_FILES,
} from '../core/cCodeArch';
import { ActionType, AppAction, AppState } from '../core/stateManager';

interface CSourceViewProps {
  readonly state: AppState;
  readonly dispatch: (action: AppAction) => void;
}

const triggerTextFileDownload = (filename: string, content: string) => {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

export const CSourceView: React.FC<CSourceViewProps> = ({
  state,
  dispatch,
}) => {
  const [copiedFile, setCopiedFile] = useState<string | null>(null);
  const activeTab = state.route.activeCFileTab;
  const currentFile =
    C_SOURCE_FILES.find((f) => f.filename === activeTab) ?? C_SOURCE_FILES[0];

  const handleCopyCode = async () => {
    try {
      await navigator.clipboard.writeText(currentFile.code);
      setCopiedFile(currentFile.filename);
      setTimeout(() => setCopiedFile(null), 1800);
    } catch {
      setCopiedFile(null);
    }
  };

  const handleDownloadCurrentFile = () => {
    triggerTextFileDownload(currentFile.filename, currentFile.code);
  };

  const handleDownloadFullBundle = () => {
    const bundleScript = buildSelfExtractingCBundle(C_SOURCE_FILES);
    triggerTextFileDownload('secadminc_c11_bundle.sh', bundleScript);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="space-y-2 max-w-2xl">
          <p className="text-xs text-emerald-400 font-medium">
            03. Complete Compilable C11 + OpenSSL 3.x Source Codebase
          </p>
          <h1 className="text-2xl sm:text-3xl font-semibold text-slate-100 tracking-tight">
            Mutual TLS 1.3 Client, Server, Managers &amp; C11 Test Suite
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            Complete ISO C11 implementation including{' '}
            <code className="text-slate-200">protocol.h</code>,{' '}
            <code className="text-slate-200">managers.c</code> (Functional
            Error, State, and Route Managers in C),{' '}
            <code className="text-slate-200">sandbox_fs.c</code>,{' '}
            <code className="text-slate-200">tls_server.c</code>,{' '}
            <code className="text-slate-200">tls_client.c</code>,{' '}
            <code className="text-slate-200">test_suite.c</code>, and{' '}
            <code className="text-slate-200">Makefile</code>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleDownloadFullBundle}
            className="min-h-[42px] px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap cursor-pointer"
          >
            <PackageCheck className="w-4 h-4" />
            <span>Download Full C11 Project (.sh Bundle)</span>
          </button>
        </div>
      </div>

      {/* Interactive File Selector Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-slate-900 border border-slate-800 rounded-xl">
        {C_SOURCE_FILES.map((file) => {
          const isSelected = file.filename === currentFile.filename;
          return (
            <button
              key={file.filename}
              type="button"
              onClick={() =>
                dispatch({
                  type: ActionType.SelectCSourceFile,
                  filename: file.filename,
                })
              }
              className={`min-h-[40px] px-3.5 py-2 text-xs font-mono rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                isSelected
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-300 hover:text-slate-100 hover:bg-slate-800'
              }`}
            >
              {file.filename}
            </button>
          );
        })}
      </div>

      {/* Selected C Module Details & Source Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-4 space-y-6">
          <div className="border border-slate-800 rounded-xl bg-slate-900/60 p-5 space-y-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                <span>{currentFile.role}</span>
                <span aria-hidden="true">·</span>
                <span>{currentFile.linesOfCode} LOC</span>
              </div>
              <h2 className="text-lg font-semibold text-slate-100">
                {currentFile.title}
              </h2>
              <p className="text-xs text-slate-400 leading-relaxed">
                {currentFile.summary}
              </p>
            </div>

            <div className="pt-3 border-t border-slate-800 space-y-2">
              <h3 className="text-xs font-semibold text-slate-200">
                Verified Defensive Invariants
              </h3>
              <ul className="space-y-2 text-xs text-slate-300">
                {currentFile.securityGuarantees.map((guarantee) => (
                  <li key={guarantee} className="leading-relaxed">
                    • {guarantee}
                  </li>
                ))}
              </ul>
            </div>

            <div className="pt-3 border-t border-slate-800 space-y-2">
              <h3 className="text-xs font-semibold text-slate-200">
                Compile &amp; Run C11 Unit Tests
              </h3>
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-[11px] text-emerald-400 overflow-x-auto">
                {`sh secadminc_c11_bundle.sh\ncd secadminc_c11\nmake all && make test`}
              </pre>
            </div>
          </div>
        </div>

        <div className="lg:col-span-8">
          <div className="border border-slate-800 rounded-xl bg-slate-950 overflow-hidden">
            <div className="px-4 py-3 bg-slate-900/90 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
                <span className="font-semibold text-emerald-400">
                  {currentFile.filename}
                </span>
                <span aria-hidden="true">·</span>
                <span className="text-slate-400">ISO C11 / POSIX.1-2008</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleDownloadCurrentFile}
                  className="min-h-[38px] px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors whitespace-nowrap cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download {currentFile.filename}</span>
                </button>
                <button
                  type="button"
                  onClick={handleCopyCode}
                  className="min-h-[38px] px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors whitespace-nowrap cursor-pointer"
                >
                  {copiedFile === currentFile.filename ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Source</span>
                    </>
                  )}
                </button>
              </div>
            </div>
            <pre className="p-4 sm:p-5 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed max-h-[560px] overflow-y-auto">
              <code>{currentFile.code}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
