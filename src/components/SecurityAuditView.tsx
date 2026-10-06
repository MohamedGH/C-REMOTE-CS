import React from 'react';
import { AlertTriangle, CheckCircle2, ShieldAlert, Trash2 } from 'lucide-react';
import {
  C_SOURCE_FILES,
  runStaticSecurityAudit,
  STATIC_AUDIT_LIMITATIONS,
} from '../core/cCodeArch';
import {
  ErrorSeverity,
  selectErrorsBySeverity,
} from '../core/errorManager';
import { ActionType, AppAction, AppState } from '../core/stateManager';

interface SecurityAuditViewProps {
  readonly state: AppState;
  readonly dispatch: (action: AppAction) => void;
}

const FILTER_OPTIONS: ReadonlyArray<{
  readonly label: string;
  readonly value: ErrorSeverity | 'ALL';
}> = [
  { label: 'All Events', value: 'ALL' },
  { label: 'Security Blocks', value: ErrorSeverity.SecurityBlock },
  { label: 'Warnings', value: ErrorSeverity.Warning },
];

export const SecurityAuditView: React.FC<SecurityAuditViewProps> = ({
  state,
  dispatch,
}) => {
  const staticFindings = runStaticSecurityAudit(C_SOURCE_FILES);
  const filteredErrors = selectErrorsBySeverity(
    state.errorManager,
    state.errorSeverityFilter
  );

  const passingChecks = staticFindings.filter(
    (f) => f.status !== 'VIOLATION_DETECTED'
  ).length;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="space-y-2 max-w-2xl">
          <p className="text-xs text-emerald-400 font-medium">
            04. Syntactic C11 Heuristic Scanner &amp; Runtime Error Manager
          </p>
          <h1 className="text-2xl sm:text-3xl font-semibold text-slate-100 tracking-tight">
            Heuristic Source Checks, Scope Limits &amp; Error Log
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            Reports syntactic regex/substring checks over{' '}
            <code className="text-slate-200">c_project/*</code> (using honest{' '}
            <code className="text-emerald-400">PATTERN_NOT_FOUND</code> and{' '}
            <code className="text-sky-400">HEURISTIC_PRESENT</code> statuses
            rather than claiming formal verification), alongside explicit
            architectural limitations.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
          <span className="text-emerald-400 font-semibold">
            {passingChecks}/{staticFindings.length} Syntactic Checks Passed
          </span>
          <span aria-hidden="true">·</span>
          <span>{state.errorManager.errors.length} UI Events Logged</span>
        </div>
      </div>

      {/* Explicit Scope & Limitations of Static Heuristic Scanning */}
      <div className="border border-amber-800/60 rounded-xl bg-amber-950/20 p-5 space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>
            Why Regex &amp; Substring Scanning Is Not a Complete Security Proof
          </span>
        </div>
        <ul className="space-y-1.5 text-xs text-slate-300 leading-relaxed">
          {STATIC_AUDIT_LIMITATIONS.map((limit) => (
            <li key={limit}>• {limit}</li>
          ))}
        </ul>
      </div>

      {/* Syntactic Heuristic Findings Grid */}
      <div className="space-y-3">
        <h2 className="text-base font-semibold text-slate-200">
          Syntactic C11 Source Checks (Live Scan of <code>c_project/*</code>)
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {staticFindings.map((finding) => (
            <div
              key={finding.id}
              className="border border-slate-800 rounded-xl bg-slate-900/60 p-4 space-y-2.5"
            >
              <div className="flex items-center justify-between gap-2 text-xs font-mono">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span
                    className={
                      finding.status === 'PATTERN_NOT_FOUND'
                        ? 'text-emerald-400 font-semibold'
                        : finding.status === 'HEURISTIC_PRESENT'
                          ? 'text-sky-400 font-semibold'
                          : 'text-red-400 font-semibold'
                    }
                  >
                    {finding.status}
                  </span>
                </div>
                <div className="text-slate-400 tabular-nums">
                  <span>{finding.ruleId}</span>
                  <span aria-hidden="true"> · </span>
                  <span>{finding.cwe}</span>
                </div>
              </div>
              <h3 className="text-sm font-semibold text-slate-100">
                {finding.title}
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                {finding.description}
              </p>
              <div className="pt-1 text-[11px] font-mono text-slate-300 break-all">
                Pattern Checked: {finding.patternChecked}
              </div>
              <div className="text-[11px] text-amber-300/90 leading-relaxed">
                Limitation: {finding.scopeLimitation}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Runtime Error Manager Log */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="text-base font-semibold text-slate-200">
            Simulated UI Error Manager Event Log (Protocol vs Filesystem Domains)
          </h2>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
              {FILTER_OPTIONS.map((opt) => {
                const isActive = state.errorSeverityFilter === opt.value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() =>
                      dispatch({
                        type: ActionType.SetErrorFilter,
                        filter: opt.value,
                      })
                    }
                    className={`min-h-[36px] px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                      isActive
                        ? 'bg-emerald-500 text-slate-950 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>

            {state.errorManager.errors.length > 0 && (
              <button
                type="button"
                onClick={() => dispatch({ type: ActionType.ClearErrors })}
                className="min-h-[38px] px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear Log</span>
              </button>
            )}
          </div>
        </div>

        <div className="border border-slate-800 rounded-xl bg-slate-900/60 divide-y divide-slate-800">
          {filteredErrors.length === 0 ? (
            <div className="p-8 text-center space-y-3">
              <p className="text-sm text-slate-400">
                No runtime security blocks or operational errors matching the
                current filter.
              </p>
              <div className="flex flex-wrap items-center justify-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    dispatch({
                      type: ActionType.ExecuteCommand,
                      rawCommand: 'uname; cat /etc/passwd',
                    })
                  }
                  className="min-h-[40px] px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-amber-300 rounded-lg transition-colors cursor-pointer"
                >
                  Trigger Protocol Error (CWE-78)
                </button>
                <button
                  type="button"
                  onClick={() =>
                    dispatch({
                      type: ActionType.ChangeDirectory,
                      targetPath: '../../../etc/shadow',
                    })
                  }
                  className="min-h-[40px] px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-amber-300 rounded-lg transition-colors cursor-pointer"
                >
                  Trigger Filesystem Error (CWE-22)
                </button>
              </div>
            </div>
          ) : (
            filteredErrors.map((errItem) => (
              <div key={errItem.id} className="p-4 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2 font-semibold text-amber-300">
                    <ShieldAlert className="w-4 h-4 shrink-0" />
                    <span>{errItem.title}</span>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-slate-400 tabular-nums">
                    <span>{errItem.domain}</span>
                    <span aria-hidden="true">·</span>
                    <span>{errItem.code}</span>
                    {errItem.cweReference && (
                      <>
                        <span aria-hidden="true">·</span>
                        <span>{errItem.cweReference}</span>
                      </>
                    )}
                    <span aria-hidden="true">·</span>
                    <span>{errItem.timestampIso.slice(11, 19)} UTC</span>
                  </div>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed">
                  {errItem.message}
                </p>
                {errItem.contextInput && (
                  <div className="text-xs font-mono text-slate-400">
                    Rejected Input:{' '}
                    <code className="text-red-300">{errItem.contextInput}</code>
                  </div>
                )}
                <div className="text-xs text-emerald-400">
                  Remediation: {errItem.remediation}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
