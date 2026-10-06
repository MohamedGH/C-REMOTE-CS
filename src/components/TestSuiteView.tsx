import React, { useState } from 'react';
import { CheckCircle2, Play, XCircle } from 'lucide-react';
import {
  executeAllFunctionalTests,
  TestSuiteSummary,
} from '../core/testSuite';

export const TestSuiteView: React.FC = () => {
  const [summary, setSummary] = useState<TestSuiteSummary>(() =>
    executeAllFunctionalTests()
  );
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const categories = [
    'ALL',
    ...Array.from(new Set(summary.results.map((r) => r.category))),
  ];

  const visibleResults =
    selectedCategory === 'ALL'
      ? summary.results
      : summary.results.filter((r) => r.category === selectedCategory);

  const handleRerun = () => {
    setSummary(executeAllFunctionalTests());
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="space-y-2 max-w-2xl">
          <p className="text-xs text-emerald-400 font-medium">
            05. Automated Functional Verification Suite
          </p>
          <h1 className="text-2xl sm:text-3xl font-semibold text-slate-100 tracking-tight">
            Unit &amp; Integration Tests for Every Module
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            Executes deterministic assertions against the Pure Functional
            Primitives, Error Manager, Route Manager, Sandboxed File Browser
            (CWE-22), Command Dispatcher (CWE-78/CWE-306), C11 Static Auditor,
            and State Manager.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2 text-xs font-mono tabular-nums text-slate-300">
            <span className="text-emerald-400 font-semibold">
              {summary.passed}/{summary.total} Passed
            </span>
            <span aria-hidden="true">·</span>
            <span>{summary.failed} Failed</span>
            <span aria-hidden="true">·</span>
            <span>{summary.totalDurationMs} ms</span>
          </div>

          <button
            type="button"
            onClick={handleRerun}
            className="min-h-[42px] px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg flex items-center gap-2 transition-colors whitespace-nowrap cursor-pointer"
          >
            <Play className="w-4 h-4" />
            <span>Re-run All Tests</span>
          </button>
        </div>
      </div>

      {/* Category Filter Bar */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-slate-900 border border-slate-800 rounded-xl">
        {categories.map((cat) => {
          const isActive = selectedCategory === cat;
          return (
            <button
              key={cat}
              type="button"
              onClick={() => setSelectedCategory(cat)}
              className={`min-h-[38px] px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
              }`}
            >
              {cat}
            </button>
          );
        })}
      </div>

      {/* Test Results Table */}
      <div className="border border-slate-800 rounded-xl bg-slate-900/60 divide-y divide-slate-800">
        {visibleResults.map((test) => (
          <div key={test.id} className="p-4 sm:p-5 space-y-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                {test.passed ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                )}
                <h2 className="text-sm font-semibold text-slate-100">
                  {test.name}
                </h2>
              </div>

              <div className="flex items-center gap-2 text-xs font-mono text-slate-400 tabular-nums">
                <span className="text-emerald-400">{test.category}</span>
                <span aria-hidden="true">·</span>
                <span>{test.id}</span>
                <span aria-hidden="true">·</span>
                <span>{test.durationMs} ms</span>
              </div>
            </div>

            <p className="text-xs text-slate-400 pl-6">
              {test.assertionDescription}
            </p>
            <div className="pl-6 pt-1">
              <code className="block p-2.5 bg-slate-950 border border-slate-800/90 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto">
                {test.details}
              </code>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
