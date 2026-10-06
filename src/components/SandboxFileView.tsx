import React, { useState } from 'react';
import {
  ArrowUpLeft,
  FilePlus2,
  FileText,
  Folder,
  Search,
  ShieldAlert,
} from 'lucide-react';
import {
  FsNodeType,
  JAIL_ROOT,
  selectCurrentDirectoryChildren,
  selectSelectedFileNode,
} from '../core/sandboxFs';
import { ActionType, AppAction, AppState } from '../core/stateManager';

interface SandboxFileViewProps {
  readonly state: AppState;
  readonly dispatch: (action: AppAction) => void;
}

export const SandboxFileView: React.FC<SandboxFileViewProps> = ({
  state,
  dispatch,
}) => {
  const { sandboxFs } = state;
  const children = selectCurrentDirectoryChildren(sandboxFs);
  const selectedFile = selectSelectedFileNode(sandboxFs);

  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');
  const [customPathInput, setCustomPathInput] = useState('');

  const handleNavigateParent = () => {
    if (sandboxFs.currentDir === JAIL_ROOT) return;
    dispatch({
      type: ActionType.ChangeDirectory,
      targetPath: '..',
    });
  };

  const handleCreateNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFileName.trim()) return;
    dispatch({
      type: ActionType.CreateAuditNote,
      filename: newFileName,
      content:
        newFileContent.trim() ||
        `Audit log note created in ${sandboxFs.currentDir} at ${new Date().toISOString()}`,
    });
    setNewFileName('');
    setNewFileContent('');
  };

  const handleCustomPathTest = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPathInput.trim()) return;
    dispatch({
      type: ActionType.ChangeDirectory,
      targetPath: customPathInput,
    });
    setCustomPathInput('');
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="space-y-2 max-w-2xl">
          <p className="text-xs text-emerald-400 font-medium">
            02. Sandboxed Remote File System Browser
          </p>
          <h1 className="text-2xl sm:text-3xl font-semibold text-slate-100 tracking-tight">
            Canonical <code className="text-xl sm:text-2xl">realpath()</code> &{' '}
            <code className="text-xl sm:text-2xl">O_NOFOLLOW</code> Jail
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            Every directory listing and file read resolves canonical paths via{' '}
            <code className="text-slate-200">realpath()</code> and verifies strict
            containment within <code className="text-emerald-400">{JAIL_ROOT}</code>{' '}
            before invoking <code className="text-slate-200">openat(..., O_NOFOLLOW)</code>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
          <span>Jail Root: {sandboxFs.jailRoot}</span>
          <span aria-hidden="true">·</span>
          <span>Total Nodes: {sandboxFs.nodes.length}</span>
          <span aria-hidden="true">·</span>
          <span className="text-emerald-400">
            CWE-22 Escapes Blocked: {sandboxFs.traversalAttemptsBlocked}
          </span>
        </div>
      </div>

      {/* Interactive Path Resolution & CWE-22 Test Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
        <form
          onSubmit={handleCustomPathTest}
          className="lg:col-span-8 flex flex-col sm:flex-row gap-2"
        >
          <div className="flex-1">
            <label
              htmlFor="custom-path-input"
              className="block text-xs font-medium text-slate-300 mb-1.5"
            >
              Test Canonical Path Resolution (Try relative path or{' '}
              <code className="text-amber-300">../../etc/passwd</code> to trigger CWE-22 guard)
            </label>
            <input
              id="custom-path-input"
              type="text"
              value={customPathInput}
              onChange={(e) => setCustomPathInput(e.target.value)}
              placeholder="e.g. /srv/sandbox/logs or ../../etc/shadow"
              className="w-full min-h-[44px] px-3.5 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-400"
            />
          </div>
          <button
            type="submit"
            className="min-h-[44px] sm:self-end px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap cursor-pointer"
          >
            Resolve &amp; Chdir
          </button>
        </form>

        <div className="lg:col-span-4 flex items-center gap-2">
          <button
            type="button"
            onClick={() =>
              dispatch({
                type: ActionType.ChangeDirectory,
                targetPath: '../../../etc/shadow',
              })
            }
            className="w-full min-h-[44px] px-3.5 py-2 bg-slate-900 hover:bg-red-950/50 border border-slate-800 hover:border-red-800/70 text-amber-300 text-xs font-medium rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer"
          >
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>Simulate CWE-22 Traversal Attack</span>
          </button>
        </div>
      </div>

      {/* Main Directory & File Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left 7 Columns: Directory Table */}
        <div className="lg:col-span-7 space-y-4">
          <div className="border border-slate-800 rounded-xl bg-slate-900/60 overflow-hidden">
            {/* Directory Toolbar */}
            <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={sandboxFs.currentDir === JAIL_ROOT}
                  onClick={handleNavigateParent}
                  className="min-h-[40px] px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-xs font-medium text-slate-200 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <ArrowUpLeft className="w-4 h-4" />
                  <span>Up</span>
                </button>
                <span className="font-mono text-xs sm:text-sm text-emerald-400 font-semibold truncate">
                  {sandboxFs.currentDir}
                </span>
              </div>

              <div className="relative w-full sm:w-56">
                <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="search"
                  aria-label="Filter sandbox files"
                  value={sandboxFs.searchQuery}
                  onChange={(e) =>
                    dispatch({
                      type: ActionType.SetFsSearchQuery,
                      query: e.target.value,
                    })
                  }
                  placeholder="Filter nodes..."
                  className="w-full min-h-[38px] pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-400"
                />
              </div>
            </div>

            {/* High-Density POSIX Inode Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-medium">
                    <th className="py-3 px-4">Name</th>
                    <th className="py-3 px-3 font-mono">Mode</th>
                    <th className="py-3 px-3 hidden sm:table-cell">Owner</th>
                    <th className="py-3 px-4 text-right font-mono">Size</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {children.length === 0 ? (
                    <tr>
                      <td
                        colSpan={4}
                        className="py-8 px-4 text-center text-slate-400"
                      >
                        No matching entries inside {sandboxFs.currentDir}.
                      </td>
                    </tr>
                  ) : (
                    children.map((node) => {
                      const isSelected =
                        sandboxFs.selectedFilePath === node.path;
                      return (
                        <tr
                          key={node.path}
                          onClick={() => {
                            if (node.type === FsNodeType.Directory) {
                              dispatch({
                                type: ActionType.ChangeDirectory,
                                targetPath: node.path,
                              });
                            } else {
                              dispatch({
                                type: ActionType.SelectFile,
                                targetPath: node.path,
                              });
                            }
                          }}
                          className={`transition-colors cursor-pointer ${
                            isSelected
                              ? 'bg-emerald-950/40 text-emerald-200'
                              : 'hover:bg-slate-800/60 text-slate-200'
                          }`}
                        >
                          <td className="py-3 px-4 font-mono">
                            <div className="flex items-center gap-2.5">
                              {node.type === FsNodeType.Directory ? (
                                <Folder className="w-4 h-4 text-emerald-400 shrink-0" />
                              ) : (
                                <FileText className="w-4 h-4 text-slate-400 shrink-0" />
                              )}
                              <span className="font-semibold truncate">
                                {node.name}
                                {node.type === FsNodeType.Directory ? '/' : ''}
                              </span>
                            </div>
                          </td>
                          <td className="py-3 px-3 font-mono tabular-nums text-slate-400">
                            {node.permissionsOctal}
                          </td>
                          <td className="py-3 px-3 font-mono text-slate-400 hidden sm:table-cell">
                            {node.owner}
                          </td>
                          <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                            {node.sizeBytes.toLocaleString()} B
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Create Sandboxed Audit Note Form */}
          <form
            onSubmit={handleCreateNote}
            className="border border-slate-800 rounded-xl bg-slate-900/60 p-4 space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-200">
                Write Sandboxed Audit Note in {sandboxFs.currentDir}
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                O_CREAT | O_WRONLY | O_NOFOLLOW
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <input
                type="text"
                value={newFileName}
                onChange={(e) => setNewFileName(e.target.value)}
                placeholder="filename.txt"
                aria-label="New sandboxed filename"
                className="min-h-[42px] px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-400"
              />
              <input
                type="text"
                value={newFileContent}
                onChange={(e) => setNewFileContent(e.target.value)}
                placeholder="File content payload..."
                aria-label="New file content"
                className="sm:col-span-2 min-h-[42px] px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-400"
              />
            </div>
            <button
              type="submit"
              className="min-h-[42px] px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-2 cursor-pointer"
            >
              <FilePlus2 className="w-4 h-4" />
              <span>Create Sandboxed File</span>
            </button>
          </form>
        </div>

        {/* Right 5 Columns: Selected File Inspector */}
        <div className="lg:col-span-5">
          <div className="border border-slate-800 rounded-xl bg-slate-900/60 p-5 space-y-4">
            <div className="space-y-1 border-b border-slate-800 pb-3">
              <p className="text-xs text-emerald-400 font-medium">
                POSIX File Descriptor Inspector
              </p>
              <h2 className="text-lg font-semibold text-slate-100 font-mono truncate">
                {selectedFile ? selectedFile.name : 'No File Selected'}
              </h2>
              {selectedFile && (
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                  <span>{selectedFile.path}</span>
                  <span aria-hidden="true">·</span>
                  <span>{selectedFile.sizeBytes} B</span>
                  <span aria-hidden="true">·</span>
                  <span>SHA256:{selectedFile.sha256Short}</span>
                </div>
              )}
            </div>

            {selectedFile ? (
              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[380px] overflow-y-auto">
                {selectedFile.content ?? '(Empty file)'}
              </pre>
            ) : (
              <p className="text-xs text-slate-400 py-8 text-center">
                Select a file row in the directory table to inspect its verified
                contents and digest.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
