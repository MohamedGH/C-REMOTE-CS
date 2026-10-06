import React, { useState } from 'react';
import {
  CheckCircle2,
  FolderOpen,
  Play,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import { RouteId } from '../core/routeManager';
import { ActionType, AppAction, AppState } from '../core/stateManager';

interface CommandConsoleViewProps {
  readonly state: AppState;
  readonly dispatch: (action: AppAction) => void;
}

const ALLOWLIST_PRESETS: ReadonlyArray<{
  readonly label: string;
  readonly command: string;
  readonly description: string;
}> = [
  {
    label: 'Kernel Identity (uname)',
    command: 'uname',
    description: 'SAC_OP_SYS_UNAME (0x02) -> POSIX uname(&uts)',
  },
  {
    label: 'System Load (sysinfo)',
    command: 'sysinfo',
    description: 'SAC_OP_SYS_UPTIME (0x01) -> POSIX sysinfo(&si)',
  },
  {
    label: 'Volume Free (df)',
    command: 'df',
    description: 'SAC_OP_SYS_STATVFS (0x03) -> POSIX fstatvfs(jail_dirfd)',
  },
  {
    label: 'Change Dir (cd reports)',
    command: 'cd reports',
    description: 'SAC_OP_FS_CHDIR (0x12) -> updates session cwd_rel',
  },
  {
    label: 'List Current Dir (ls .)',
    command: 'ls .',
    description: 'SAC_OP_FS_LISTDIR (0x10) -> openat2(RESOLVE_BENEATH)',
  },
  {
    label: 'Read File (cat)',
    command: 'cat config/tls_policy.conf',
    description: 'SAC_OP_FS_READFILE (0x11) -> openat2(O_RDONLY)',
  },
];

const SECURITY_TEST_PAYLOADS: ReadonlyArray<{
  readonly label: string;
  readonly command: string;
  readonly cwe: string;
}> = [
  {
    label: 'Test CWE-78 Shell Chain (;)',
    command: 'uname; cat /etc/passwd',
    cwe: 'CWE-78',
  },
  {
    label: 'Test Unimplemented Opcode',
    command: 'netstat',
    cwe: 'SAC_ERR_BAD_OPCODE',
  },
  {
    label: 'Test CWE-22 Path Escape (..)',
    command: 'cat ../../../etc/shadow',
    cwe: 'CWE-22',
  },
];

export const CommandConsoleView: React.FC<CommandConsoleViewProps> = ({
  state,
  dispatch,
}) => {
  const [inputCmd, setInputCmd] = useState('');
  const { tlsSession, sandboxFs, commandHistory } = state;
  const latestFrameEntry = [...commandHistory]
    .reverse()
    .find((item) => item.wireFrame);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputCmd.trim()) return;
    dispatch({
      type: ActionType.ExecuteCommand,
      rawCommand: inputCmd,
    });
    setInputCmd('');
  };

  const handleRunPreset = (command: string) => {
    dispatch({
      type: ActionType.ExecuteCommand,
      rawCommand: command,
    });
  };

  return (
    <div className="space-y-8">
      {/* Section Header & Explicit Simulation Notice */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="space-y-2 max-w-2xl">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-amber-300 font-semibold">
              SIMULATED IN-BROWSER UI DEMONSTRATOR
            </span>
            <span aria-hidden="true" className="text-slate-600">
              ·
            </span>
            <span className="text-slate-400">
              Synchronized with 6 real C11 opcodes in{' '}
              <code className="text-slate-200">c_project/protocol.h</code>
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold text-slate-100 tracking-tight">
            Allowlisted POSIX Syscall &amp; Framing Simulator
          </h1>
          <p className="text-sm text-slate-400 leading-relaxed">
            Simulates how <code className="text-slate-200">c_project/managers.c</code>{' '}
            and <code className="text-slate-200">c_project/io_framing.c</code>{' '}
            validate headers before dispatch, frame 12-byte requests and 16-byte
            responses, and maintain stateful relative <code className="text-slate-200">cwd_rel</code>{' '}
            across <code className="text-slate-200">cd</code>,{' '}
            <code className="text-slate-200">ls</code>, and{' '}
            <code className="text-slate-200">cat</code>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
          <span
            className={
              tlsSession.connected
                ? 'text-emerald-400 font-semibold'
                : 'text-amber-400 font-semibold'
            }
          >
            {tlsSession.connected
              ? 'Simulated mTLS 1.3 Active'
              : 'Simulated Session Disconnected'}
          </span>
          <span aria-hidden="true">·</span>
          <span>Seq #{tlsSession.sequenceCounter}</span>
          <span aria-hidden="true">·</span>
          <span>Executed: {tlsSession.commandsExecuted}</span>
          <span aria-hidden="true">·</span>
          <span>Blocked: {tlsSession.securityBlocks}</span>
        </div>
      </div>

      {/* Main Two-Column Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left 7 Columns: Interactive RPC Terminal & Presets */}
        <div className="lg:col-span-7 space-y-6">
          <form onSubmit={handleSubmit} className="space-y-3">
            <label
              htmlFor="rpc-command-input"
              className="block text-xs font-medium text-slate-300"
            >
              Dispatch Simulated Opcode (Session Working Dir:{' '}
              <span className="font-mono text-emerald-400">
                {sandboxFs.currentDir}
              </span>
              )
            </label>
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <input
                  id="rpc-command-input"
                  type="text"
                  value={inputCmd}
                  onChange={(e) => setInputCmd(e.target.value)}
                  placeholder="Enter C11 opcode command (sysinfo, uname, df, cd reports, ls ., cat health_snapshot.txt)"
                  className="w-full min-h-[44px] px-4 py-2.5 bg-slate-900 border border-slate-800 rounded-lg text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-400"
                />
              </div>
              <button
                type="submit"
                className="min-h-[44px] px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Play className="w-4 h-4" />
                <span>Send Simulated Frame</span>
              </button>
            </div>
          </form>

          {/* Allowlisted Quick Actions (Exact 6 C11 Opcodes) */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>
                The 6 Opcodes Implemented in <code>c_project/protocol.h</code>
              </span>
              <button
                type="button"
                onClick={() =>
                  dispatch({
                    type: ActionType.Navigate,
                    routeId: RouteId.FileSandbox,
                  })
                }
                className="text-emerald-400 hover:underline flex items-center gap-1 cursor-pointer"
              >
                <FolderOpen className="w-3.5 h-3.5" />
                <span>Open Sandbox File Browser</span>
              </button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {ALLOWLIST_PRESETS.map((preset) => (
                <button
                  key={preset.command}
                  type="button"
                  onClick={() => handleRunPreset(preset.command)}
                  className="min-h-[44px] px-3.5 py-2.5 text-left bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 rounded-lg transition-colors flex flex-col justify-between cursor-pointer"
                >
                  <span className="text-xs font-semibold text-slate-200 whitespace-nowrap truncate">
                    {preset.label}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                    {preset.description}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Pre-Dispatch Rejection & Security Guard Triggers */}
          <div className="space-y-2 pt-2 border-t border-slate-800/70">
            <span className="block text-xs text-slate-400">
              Test Pre-Dispatch Rejection (Notice: rejected frames do not
              increment Seq # or Executed count)
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {SECURITY_TEST_PAYLOADS.map((test) => (
                <button
                  key={test.command}
                  type="button"
                  onClick={() => handleRunPreset(test.command)}
                  className="min-h-[44px] px-3 py-2 text-left bg-slate-900/60 hover:bg-red-950/40 border border-slate-800 hover:border-red-800/60 rounded-lg transition-colors cursor-pointer"
                >
                  <div className="text-xs font-semibold text-amber-300 whitespace-nowrap truncate">
                    {test.label}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                    {test.command}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Command Execution Log Stream */}
          <div className="border border-slate-800 rounded-xl bg-slate-900/60 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span className="font-semibold text-slate-200">
                  Simulated RPC Session Transcript
                </span>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">
                  {commandHistory.length} entries
                </span>
              </div>
              {commandHistory.length > 0 && (
                <button
                  type="button"
                  onClick={() => dispatch({ type: ActionType.ClearConsole })}
                  className="min-h-[36px] px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 rounded hover:bg-slate-800 transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Clear</span>
                </button>
              )}
            </div>

            <div className="p-4 space-y-4 max-h-[380px] overflow-y-auto font-mono text-xs">
              {commandHistory.length === 0 ? (
                <div className="py-8 text-center space-y-3">
                  <p className="text-slate-400 font-sans text-sm">
                    No simulated RPC frames dispatched yet.
                  </p>
                  <button
                    type="button"
                    onClick={() => handleRunPreset('sysinfo')}
                    className="min-h-[40px] px-4 py-2 bg-emerald-500 text-slate-950 font-sans font-semibold text-xs rounded-lg cursor-pointer"
                  >
                    Run Initial sysinfo Query
                  </button>
                </div>
              ) : (
                commandHistory.map((item) => (
                  <div
                    key={item.id}
                    className="border-b border-slate-800/70 last:border-b-0 pb-3 last:pb-0 space-y-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 text-slate-400">
                      <div className="flex items-center gap-2">
                        {item.status !== 'BLOCKED' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        )}
                        <span className="text-slate-100 font-semibold">
                          $ {item.rawInput}
                        </span>
                      </div>
                      <div className="text-[11px] tabular-nums">
                        <span>
                          {item.status === 'SUCCESS'
                            ? item.wireFrame?.opcodeName
                            : item.status === 'LOCAL_HELP'
                              ? 'LOCAL_CLI_HELP'
                              : `${item.errorDomain} · ${item.errorCode}`}
                        </span>
                        <span aria-hidden="true"> · </span>
                        <span>{item.timestampIso.slice(11, 19)} UTC</span>
                      </div>
                    </div>
                    <pre
                      className={`pl-5 whitespace-pre-wrap leading-relaxed overflow-x-auto ${
                        item.status !== 'BLOCKED'
                          ? 'text-slate-300'
                          : 'text-red-300'
                      }`}
                    >
                      {item.outputLines.join('\n')}
                    </pre>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right 5 Columns: Request & Response Binary Frame Inspector */}
        <div className="lg:col-span-5 space-y-6">
          <div className="border border-slate-800 rounded-xl bg-slate-900/60 p-5 space-y-5">
            <div className="space-y-1">
              <p className="text-xs text-emerald-400 font-medium">
                02. Request &amp; Response Wire Framing (io_framing.c)
              </p>
              <h2 className="text-lg font-semibold text-slate-100">
                <code className="text-sm">sac_frame_header_t</code> (12 B) &amp;{' '}
                <code className="text-sm">sac_resp_header_t</code> (16 B)
              </h2>
              <p className="text-xs text-slate-400">
                Displays the exact packed network headers read/written by{' '}
                <code className="text-slate-300">sac_io_read_exact()</code> and{' '}
                <code className="text-slate-300">sac_io_write_all()</code>.
              </p>
            </div>

            {latestFrameEntry?.wireFrame ? (
              <div className="space-y-4">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs space-y-1">
                  <div className="text-slate-400 text-[11px]">
                    Request Header (12 Bytes, Network Byte Order):
                  </div>
                  <div className="text-emerald-400 font-semibold tracking-wider break-all">
                    {latestFrameEntry.wireFrame.requestRawHex}
                  </div>
                </div>

                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs space-y-1">
                  <div className="text-slate-400 text-[11px]">
                    Response Header (16 Bytes, Network Byte Order):
                  </div>
                  <div className="text-sky-400 font-semibold tracking-wider break-all">
                    {latestFrameEntry.wireFrame.responseRawHex}
                  </div>
                </div>

                <dl className="divide-y divide-slate-800/80 text-xs font-mono tabular-nums">
                  <div className="py-2 flex justify-between gap-4">
                    <dt className="text-slate-400 font-sans">Header Magic</dt>
                    <dd className="text-slate-200">
                      {latestFrameEntry.wireFrame.magicHex}
                    </dd>
                  </div>
                  <div className="py-2 flex justify-between gap-4">
                    <dt className="text-slate-400 font-sans">Opcode Enum</dt>
                    <dd className="text-emerald-400 font-semibold">
                      {latestFrameEntry.wireFrame.opcodeName} (
                      {latestFrameEntry.wireFrame.opcodeHex})
                    </dd>
                  </div>
                  <div className="py-2 flex justify-between gap-4">
                    <dt className="text-slate-400 font-sans">
                      In-Session Sequence #
                    </dt>
                    <dd className="text-slate-200">
                      {latestFrameEntry.wireFrame.sequenceNumber}
                    </dd>
                  </div>
                  <div className="py-2 flex justify-between gap-4">
                    <dt className="text-slate-400 font-sans">
                      Req / Resp Payload Len
                    </dt>
                    <dd className="text-slate-200">
                      {latestFrameEntry.wireFrame.requestPayloadLengthBytes} B
                      req /{' '}
                      {latestFrameEntry.wireFrame.responsePayloadLengthBytes} B
                      resp
                    </dd>
                  </div>
                  <div className="py-2 flex justify-between gap-4">
                    <dt className="text-slate-400 font-sans">
                      Response Domain
                    </dt>
                    <dd className="text-slate-200">
                      {latestFrameEntry.wireFrame.responseDomain}
                    </dd>
                  </div>
                  <div className="py-2 flex justify-between gap-4">
                    <dt className="text-slate-400 font-sans">
                      C11 Server Function
                    </dt>
                    <dd className="text-slate-200 text-right break-all">
                      {latestFrameEntry.wireFrame.cSyscallInvoked}
                    </dd>
                  </div>
                </dl>
              </div>
            ) : (
              <p className="text-xs text-slate-400">
                Execute an allowlisted command to inspect its 12-byte request
                header and 16-byte response header.
              </p>
            )}

            <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 tabular-nums">
              <span>
                CWE-22 Traversal Blocks: {sandboxFs.traversalAttemptsBlocked}
              </span>
              <button
                type="button"
                onClick={() =>
                  dispatch({
                    type: ActionType.Navigate,
                    routeId: RouteId.CArchitecture,
                  })
                }
                className="text-emerald-400 hover:underline font-medium cursor-pointer"
              >
                Inspect Real C11 Codebase →
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
