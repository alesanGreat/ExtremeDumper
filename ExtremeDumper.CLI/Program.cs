using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using dnlib.DotNet;
using dnlib.PE;
using ExtremeDumper;
using ExtremeDumper.AntiAntiDump;
using ExtremeDumper.Diagnostics;
using ExtremeDumper.Dumping;
using ExtremeDumper.Injecting;
using ExtremeDumper.Logging;
using NativeSharp;
using ImageLayout = dnlib.PE.ImageLayout;

namespace ExtremeDumper.CLI;

public static class Program {
	[DllImport("ExtremeDumper.LoaderHook.dll", EntryPoint = "LoaderHookCreateProcess", BestFitMapping = false, CharSet = CharSet.Unicode, SetLastError = true)]
	static extern uint LoaderHookCreateProcess(string applicationName, StringBuilder? commandLine);

	[DllImport("ExtremeDumper.LoaderHook.dll", EntryPoint = "LoaderHookCreateProcessEx", BestFitMapping = false, CharSet = CharSet.Unicode, SetLastError = true)]
	static extern uint LoaderHookCreateProcessEx(string applicationName, StringBuilder? commandLine, string? currentDirectory);

	static readonly HashSet<string> GlobalFlags = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
		"--json",
		"--quiet",
		"--verbose"
	};

	static readonly HashSet<string> GlobalFlagsWithValue = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
		"--verbose-level",
		"--log-file"
	};

	static bool jsonOutput;
	static bool quietOutput;
	static StreamWriter? logFileWriter;

	public static int Main(string[] args) {
		try {
			ConfigureGlobalOptions(args);

			if (args.Length == 0) {
				PrintUsage();
				return (int)ExitCode.InvalidArguments;
			}

			if (!TrySplitCommand(args, out var commandArgs, out var splitError)) {
				throw new CliException(ExitCode.InvalidArguments, splitError);
			}

			if (commandArgs.Length == 0) {
				PrintUsage();
				return (int)ExitCode.InvalidArguments;
			}

			string command = commandArgs[0].ToLowerInvariant();
			return command switch {
				"list-processes" or "ps" => ListProcesses(commandArgs),
				"list-modules" or "modules" => ListModules(commandArgs),
				"dump-process" => DumpProcess(commandArgs),
				"dump-module" => DumpModule(commandArgs),
				"inject" => Inject(commandArgs),
				"loader-hook" => LoaderHook(commandArgs),
				"exports" => Exports(commandArgs),
				"doctor" => Doctor(commandArgs),
				"help" or "--help" or "-h" => Help(),
				_ => UnknownCommand(command)
			};
		}
		catch (CliException ex) {
			EmitError(ex.Code, ex.Message);
			return (int)ex.Code;
		}
		catch (FileNotFoundException ex) {
			EmitError(ExitCode.DependencyMissing, ex.Message);
			return (int)ExitCode.DependencyMissing;
		}
		catch (UnauthorizedAccessException ex) {
			EmitError(ExitCode.AccessDenied, ex.Message);
			return (int)ExitCode.AccessDenied;
		}
		catch (Exception ex) {
			EmitError(ExitCode.UnhandledException, ex.Message, ex);
			return (int)ExitCode.UnhandledException;
		}
		finally {
			logFileWriter?.Flush();
			logFileWriter?.Dispose();
			Console.Out.Flush();
			Console.Error.Flush();
		}
	}

	static int Help() {
		PrintUsage();
		return (int)ExitCode.Success;
	}

	static int UnknownCommand(string cmd) {
		throw new CliException(ExitCode.InvalidArguments, $"Unknown command: {cmd}");
	}

	static void ConfigureGlobalOptions(string[] args) {
		var dict = ParseArgs(args, 0);
		jsonOutput = dict.ContainsKey("--json");
		quietOutput = dict.ContainsKey("--quiet");

		if (dict.ContainsKey("--verbose"))
			Logger.Level = Tool.Logging.LogLevel.Verbose3;

		if (dict.TryGetValue("--verbose-level", out var verboseLevel)) {
			if (!TryParseVerboseLevel(verboseLevel, out var level))
				throw new CliException(ExitCode.InvalidArguments, "--verbose-level acepta: 1,2,3 o verbose1,verbose2,verbose3.");
			Logger.Level = level;
		}

		if (dict.TryGetValue("--log-file", out var logFilePath)) {
			logFilePath = ExpandPath(logFilePath);
			string? dir = Path.GetDirectoryName(logFilePath);
			if (!string.IsNullOrEmpty(dir))
				Directory.CreateDirectory(dir);
			var stream = new FileStream(logFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
			logFileWriter = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };
			WriteLog($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Logging to: {logFilePath}");
		}
	}

	static bool TrySplitCommand(string[] args, out string[] commandArgs, out string error) {
		int idx = 0;
		while (idx < args.Length && args[idx].StartsWith("--", StringComparison.Ordinal)) {
			string opt = args[idx];
			if (GlobalFlags.Contains(opt)) {
				idx++;
				continue;
			}
			if (GlobalFlagsWithValue.Contains(opt)) {
				if (idx + 1 >= args.Length) {
					commandArgs = Array2.Empty<string>();
					error = $"Missing value for global option '{opt}'.";
					return false;
				}
				idx += 2;
				continue;
			}
			break;
		}

		commandArgs = args.Skip(idx).ToArray();
		error = string.Empty;
		return true;
	}

	static void PrintUsage() {
		string usage = @"ExtremeDumper.CLI - .NET Assembly Dumper (Command Line Interface)
Usage: ExtremeDumper.CLI [global-options] <command> [options]

Commands:
  list-processes, ps
    --dotnet-only
    --name <exact-name>
    --contains <substring>

  list-modules, modules
    --pid <id> | --name <exact-name> | --contains <substring>
    --type <unmanaged|managed|aad>
    --dotnet-only
    --domain <contains>
    --clr <contains>
    --in-memory [true|false]
    --path-contains <contains>
    --min-size <bytes|0xHEX|10KB|20MB>
    --max-size <bytes|0xHEX|10KB|20MB>

  dump-process
    --pid <id> | --name <exact-name> | --contains <substring>
    --pid-file <txt>
    --process-list <csv>
    --all-dotnet
    --output <path> (default: .\Dumps)
    --output-template <template>
    --type <normal|antiantidump>

  dump-module
    --pid <id> | --name <exact-name> | --contains <substring>
    --address <hex>
    --output <path>
    --output-template <template>
    --type <normal|antiantidump>
    --layout <auto|file|memory>

  inject
    --pid <id> | --name <exact-name> | --contains <substring>
    --assembly <path>
    --list-entrypoints
    --type-name <name>
    --method-name <name>
    --argument <arg>
    --clr <v2|v4>
    --wait
    --unmanaged

  loader-hook
    --assembly <path>
    --args <argument-string>
    --workdir <path>

  exports
    --pid <id> | --name <exact-name> | --contains <substring>
    --address <hex>

  doctor
    Diagnóstico rápido de entorno CLI.

Global options:
  --json
  --quiet
  --log-file <path>
  --verbose
  --verbose-level <1|2|3|verbose1|verbose2|verbose3>

Output-template placeholders:
  {pid} {process} {module} {address} {ext} {timestamp}
";

		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = true,
				["command"] = "help",
				["usage"] = usage
			});
		}
		else {
			WriteInfoRaw(usage);
		}
	}

	static Dictionary<string, string> ParseArgs(string[] args, int startIndex = 1) {
		var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		for (int i = startIndex; i < args.Length; i++) {
			string current = args[i];
			if (!current.StartsWith("--", StringComparison.Ordinal))
				continue;

			string value = "true";
			if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)) {
				value = args[i + 1];
				i++;
			}
			dict[current] = value;
		}
		return dict;
	}

	static string GetArg(Dictionary<string, string> dict, string key, string defaultValue = "") {
		return dict.TryGetValue(key, out var value) ? value : defaultValue;
	}

	static uint GetPid(Dictionary<string, string> dict, bool required) {
		if (!dict.TryGetValue("--pid", out var pidRaw)) {
			if (required)
				throw new CliException(ExitCode.InvalidArguments, "--pid es requerido.");
			return 0;
		}

		if (!uint.TryParse(pidRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) || pid == 0)
			throw new CliException(ExitCode.InvalidArguments, "--pid no es válido.");

		return pid;
	}

	static nuint GetAddress(Dictionary<string, string> dict) {
		if (!dict.TryGetValue("--address", out var s))
			throw new CliException(ExitCode.InvalidArguments, "--address es requerido.");
		s = s.Trim();
		if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
			s = s.Substring(2);
		if (!ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
			throw new CliException(ExitCode.InvalidArguments, "--address debe ser hexadecimal.");
		return (nuint)value;
	}

	static int ListProcesses(string[] args) {
		var dict = ParseArgs(args);
		bool dotnetOnly = dict.ContainsKey("--dotnet-only");
		string exactName = GetArg(dict, "--name");
		string containsName = GetArg(dict, "--contains");

		var provider = ProcessesProviderFactory.Create();
		var processes = provider.EnumerateProcesses()
			.Where(p => !dotnetOnly || p is DotNetProcessInfo)
			.Where(p => string.IsNullOrEmpty(exactName) || string.Equals(p.Name, exactName, StringComparison.OrdinalIgnoreCase))
			.Where(p => string.IsNullOrEmpty(containsName) || p.Name.IndexOf(containsName, StringComparison.OrdinalIgnoreCase) >= 0)
			.OrderBy(p => p.Id)
			.ToArray();

		if (jsonOutput) {
			var items = new List<object>(processes.Length);
			foreach (var process in processes) {
				items.Add(new Dictionary<string, object?> {
					["id"] = process.Id,
					["name"] = process.Name,
					["filePath"] = process.FilePath,
					["is64Bit"] = process.Is64Bit,
					["isDotNet"] = process is DotNetProcessInfo,
					["clrModules"] = process is DotNetProcessInfo dn ? dn.CLRModules.Select(m => m.Name).ToArray() : Array2.Empty<string>()
				});
			}

			EmitJson(new Dictionary<string, object?> {
				["ok"] = true,
				["command"] = "list-processes",
				["count"] = items.Count,
				["processes"] = items
			});
			return (int)ExitCode.Success;
		}

		foreach (var process in processes) {
			string clr = process is DotNetProcessInfo dn
				? string.Join(", ", dn.CLRModules.Select(m => m.Name))
				: string.Empty;
			string bitness = process.Is64Bit ? "x64" : "x86";
			WriteInfo($"{process.Id,-8} {bitness,-4} {process.Name,-30} {clr}");
			if (!string.IsNullOrEmpty(process.FilePath))
				WriteInfo($"         Path: {process.FilePath}");
		}

		return (int)ExitCode.Success;
	}

	static int ListModules(string[] args) {
		var dict = ParseArgs(args);
		uint pid = ResolveSingleProcessId(dict);
		bool dotnetOnly = dict.ContainsKey("--dotnet-only");
		string typeStr = GetArg(dict, "--type", "unmanaged").ToLowerInvariant();
		string domainFilter = GetArg(dict, "--domain");
		string clrFilter = GetArg(dict, "--clr");
		string pathFilter = GetArg(dict, "--path-contains");
		bool? inMemoryFilter = GetOptionalBool(dict, "--in-memory");
		uint? minSize = GetOptionalSize(dict, "--min-size");
		uint? maxSize = GetOptionalSize(dict, "--max-size");

		ModulesProviderType providerType = typeStr switch {
			"managed" => ModulesProviderType.Managed,
			"aad" => ModulesProviderType.ManagedAAD,
			"unmanaged" => ModulesProviderType.Unmanaged,
			_ => throw new CliException(ExitCode.InvalidArguments, "--type debe ser unmanaged, managed o aad.")
		};

		IEnumerable<ExtremeDumper.Diagnostics.ModuleInfo> modules;
		if (providerType == ModulesProviderType.ManagedAAD) {
			modules = AADExtensions.EnumerateAADClients(pid).SelectMany(c => c.EnumerateModules()).Cast<ExtremeDumper.Diagnostics.ModuleInfo>();
		}
		else {
			modules = ModulesProviderFactory.Create(pid, providerType).EnumerateModules();
		}

		var filteredModules = modules.Where(m => ModuleMatchesFilters(m, dotnetOnly, domainFilter, clrFilter, inMemoryFilter, pathFilter, minSize, maxSize)).ToArray();

		if (jsonOutput) {
			var items = new List<object>(filteredModules.Length);
			foreach (var module in filteredModules) {
				items.Add(new Dictionary<string, object?> {
					["name"] = module.Name,
					["imageBase"] = Formatter.FormatHex(module.ImageBase),
					["imageSize"] = module.ImageSize,
					["filePath"] = module.FilePath,
					["isDotNet"] = module is DotNetModuleInfo,
					["domain"] = module is DotNetModuleInfo dn ? dn.DomainName : string.Empty,
					["clr"] = module is DotNetModuleInfo dn2 ? dn2.CLRVersion : string.Empty,
					["inMemory"] = module is DotNetModuleInfo dn3 && dn3.InMemory
				});
			}

			EmitJson(new Dictionary<string, object?> {
				["ok"] = true,
				["command"] = "list-modules",
				["pid"] = pid,
				["provider"] = providerType.ToString(),
				["count"] = items.Count,
				["modules"] = items
			});
			return (int)ExitCode.Success;
		}

		foreach (var module in filteredModules) {
			string addr = Formatter.FormatHex(module.ImageBase);
			string size = Formatter.FormatHex(module.ImageSize);
			string path = string.IsNullOrEmpty(module.FilePath) ? "InMemory" : module.FilePath;

			if (module is DotNetModuleInfo dn) {
				WriteInfo($"[.NET]   {addr} {size,-18} {dn.DomainName,-20} {dn.CLRVersion,-12} {module.Name}");
				WriteInfo($"         Path: {path}");
			}
			else {
				WriteInfo($"[Native] {addr} {size,-18} {module.Name}");
				WriteInfo($"         Path: {path}");
			}
		}

		return (int)ExitCode.Success;
	}

	static int DumpProcess(string[] args) {
		var dict = ParseArgs(args);
		string outputRoot = ExpandPath(GetArg(dict, "--output", Path.Combine(Directory.GetCurrentDirectory(), "Dumps")));
		string outputTemplate = GetArg(dict, "--output-template");
		string typeStr = GetArg(dict, "--type", "normal").ToLowerInvariant();
		var dumperType = ParseDumperType(typeStr);

		var pidSet = ResolveBatchProcessIds(dict);
		if (pidSet.Count == 0) {
			uint singlePid = ResolveSingleProcessId(dict);
			pidSet.Add(singlePid);
		}

		var results = new List<Dictionary<string, object?>>();
		int totalDumped = 0;
		int failures = 0;

		foreach (uint pid in pidSet.OrderBy(p => p)) {
			try {
				var process = GetProcessById(pid) ?? throw new CliException(ExitCode.ProcessNotFound, $"No se encontró proceso con PID {pid}.");
				string processName = string.IsNullOrWhiteSpace(process.Name) ? $"pid_{pid}" : process.Name;
				string dumpDirectory = ResolveDumpProcessDirectory(outputRoot, outputTemplate, process);
				Directory.CreateDirectory(dumpDirectory);

				var beforeFiles = new HashSet<string>(Directory.GetFiles(dumpDirectory), StringComparer.OrdinalIgnoreCase);

				using var dumper = DumperFactory.Create(pid, dumperType);
				int count = dumper.DumpProcess(dumpDirectory);

				var afterFiles = Directory.GetFiles(dumpDirectory).Where(f => !beforeFiles.Contains(f)).ToArray();
				totalDumped += count;

				results.Add(new Dictionary<string, object?> {
					["pid"] = pid,
					["process"] = processName,
					["ok"] = true,
					["dumpedCount"] = count,
					["output"] = dumpDirectory,
					["newFiles"] = afterFiles
				});

				if (!jsonOutput)
					WriteInfo($"PID {pid} ({processName}): dumped {count} module(s) -> {dumpDirectory}");
			}
			catch (Exception ex) {
				failures++;
				results.Add(new Dictionary<string, object?> {
					["pid"] = pid,
					["ok"] = false,
					["error"] = ex.Message
				});
				if (!jsonOutput)
					WriteErrorRaw($"PID {pid}: {ex.Message}");
			}
		}

		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = failures == 0,
				["command"] = "dump-process",
				["totalProcesses"] = pidSet.Count,
				["failedProcesses"] = failures,
				["totalDumped"] = totalDumped,
				["results"] = results
			});
		}
		else if (pidSet.Count > 1) {
			WriteInfo($"Batch finalizado. procesos={pidSet.Count} fallos={failures} dumps={totalDumped}");
		}

		if (failures > 0)
			return (int)ExitCode.BatchPartialFailure;

		return (int)ExitCode.Success;
	}

	static int DumpModule(string[] args) {
		var dict = ParseArgs(args);
		uint pid = ResolveSingleProcessId(dict);
		nuint address = GetAddress(dict);
		string typeStr = GetArg(dict, "--type", "normal").ToLowerInvariant();
		var dumperType = ParseDumperType(typeStr);
		string layoutStr = GetArg(dict, "--layout", "auto").ToLowerInvariant();
		string outputTemplate = GetArg(dict, "--output-template");

		var process = GetProcessById(pid) ?? throw new CliException(ExitCode.ProcessNotFound, $"No se encontró proceso con PID {pid}.");
		ExtremeDumper.Diagnostics.ModuleInfo? moduleInfo = TryGetModuleByAddress(pid, address);
		string moduleName = moduleInfo?.Name ?? $"module_{address:X}";

		string outputPath = ResolveDumpModuleOutputPath(dict, process, moduleName, address, outputTemplate);
		string? outputDir = Path.GetDirectoryName(outputPath);
		if (!string.IsNullOrEmpty(outputDir))
			Directory.CreateDirectory(outputDir);

		ImageLayout imageLayout = layoutStr switch {
			"file" => ImageLayout.File,
			"memory" => ImageLayout.Memory,
			"auto" => ResolveAutoImageLayout(pid, address),
			_ => throw new CliException(ExitCode.InvalidArguments, "--layout debe ser auto, file o memory.")
		};

		using var dumper = DumperFactory.Create(pid, dumperType);
		bool ok = dumper.DumpModule(address, imageLayout, outputPath);
		if (!ok)
			throw new CliException(ExitCode.DumpFailed, "No se pudo dumpear el módulo.");

		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = true,
				["command"] = "dump-module",
				["pid"] = pid,
				["address"] = Formatter.FormatHex(address),
				["output"] = outputPath
			});
		}
		else {
			WriteInfo($"Dumped module to: {outputPath}");
		}

		return (int)ExitCode.Success;
	}

	static int Inject(string[] args) {
		var dict = ParseArgs(args);
		uint pid = ResolveSingleProcessId(dict);
		string assemblyPath = ExpandPath(GetArg(dict, "--assembly"));
		if (string.IsNullOrWhiteSpace(assemblyPath))
			throw new CliException(ExitCode.InvalidArguments, "--assembly es requerido.");
		if (!File.Exists(assemblyPath))
			throw new CliException(ExitCode.InvalidArguments, $"Assembly no encontrado: {assemblyPath}");

		using var module = ModuleDefMD.Load(File.ReadAllBytes(assemblyPath));
		var candidates = FindManagedEntryPoints(module).ToArray();

		if (dict.ContainsKey("--list-entrypoints")) {
			if (jsonOutput) {
				EmitJson(new Dictionary<string, object?> {
					["ok"] = true,
					["command"] = "inject",
					["assembly"] = assemblyPath,
					["entrypointCount"] = candidates.Length,
					["entrypoints"] = candidates.Select(c => new Dictionary<string, object?> {
						["type"] = c.DeclaringTypeName,
						["method"] = c.MethodName,
						["signature"] = "static int Method(string)"
					}).ToArray()
				});
			}
			else {
				if (candidates.Length == 0) {
					WriteInfo("No se encontraron entrypoints válidos.");
				}
				else {
					WriteInfo("Entrypoints válidos:");
					foreach (var c in candidates)
						WriteInfo($"  {c.DeclaringTypeName}::{c.MethodName}(string) -> int");
				}
			}
			return (int)ExitCode.Success;
		}

		bool unmanaged = dict.ContainsKey("--unmanaged");
		if (unmanaged) {
			bool unmanagedOk = Injector.InjectUnmanaged(pid, assemblyPath);
			if (!unmanagedOk)
				throw new CliException(ExitCode.InjectionFailed, "Falló la inyección unmanaged.");

			if (jsonOutput) {
				EmitJson(new Dictionary<string, object?> {
					["ok"] = true,
					["command"] = "inject",
					["pid"] = pid,
					["mode"] = "unmanaged",
					["assembly"] = assemblyPath
				});
			}
			else {
				WriteInfo("Injected successfully.");
			}

			return (int)ExitCode.Success;
		}

		string typeName = GetArg(dict, "--type-name");
		string methodName = GetArg(dict, "--method-name");
		string argument = GetArg(dict, "--argument");
		bool wait = dict.ContainsKey("--wait");

		if (string.IsNullOrEmpty(typeName) || string.IsNullOrEmpty(methodName)) {
			if (candidates.Length == 0)
				throw new CliException(ExitCode.InvalidArguments, "No hay entrypoint compatible (static int Method(string)).");

			if (!string.IsNullOrEmpty(methodName)) {
				var byName = candidates.Where(c => string.Equals(c.MethodName, methodName, StringComparison.Ordinal)).ToArray();
				if (byName.Length == 0)
					throw new CliException(ExitCode.InvalidArguments, $"No se encontró método '{methodName}' con firma válida.");
				if (byName.Length > 1 && string.IsNullOrEmpty(typeName))
					throw new CliException(ExitCode.InvalidArguments, $"Método '{methodName}' ambiguo. Especifica --type-name.");
				typeName = byName[0].DeclaringTypeName;
				methodName = byName[0].MethodName;
			}
			else {
				typeName = candidates[0].DeclaringTypeName;
				methodName = candidates[0].MethodName;
			}
		}

		ExtremeDumper.Injecting.InjectionClrVersion clrVersion = ResolveClrVersion(module, dict);
		bool managedOk;
		int returnValue = 0;

		if (wait) {
			managedOk = Injector.InjectManagedAndWait(pid, assemblyPath, typeName, methodName, argument, clrVersion, out returnValue);
		}
		else {
			managedOk = Injector.InjectManaged(pid, assemblyPath, typeName, methodName, argument, clrVersion);
		}

		if (!managedOk)
			throw new CliException(ExitCode.InjectionFailed, "Falló la inyección managed.");

		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = true,
				["command"] = "inject",
				["pid"] = pid,
				["mode"] = "managed",
				["assembly"] = assemblyPath,
				["typeName"] = typeName,
				["methodName"] = methodName,
				["wait"] = wait,
				["returnValue"] = wait ? returnValue : (object?)null
			});
		}
		else {
			WriteInfo(wait ? $"Injected successfully. Return value: 0x{returnValue:X}" : "Injected successfully.");
		}

		return (int)ExitCode.Success;
	}

	static int LoaderHook(string[] args) {
		var dict = ParseArgs(args);
		string assemblyPath = ExpandPath(GetArg(dict, "--assembly"));
		if (string.IsNullOrWhiteSpace(assemblyPath))
			throw new CliException(ExitCode.InvalidArguments, "--assembly es requerido.");
		if (!File.Exists(assemblyPath))
			throw new CliException(ExitCode.InvalidArguments, $"Executable not found: {assemblyPath}");

		string extraArgs = GetArg(dict, "--args");
		string workdir = GetArg(dict, "--workdir");
		if (!string.IsNullOrWhiteSpace(workdir)) {
			workdir = ExpandPath(workdir);
			if (!Directory.Exists(workdir))
				throw new CliException(ExitCode.InvalidArguments, $"--workdir no existe: {workdir}");
		}

		string commandLineText = BuildCommandLine(assemblyPath, extraArgs);
		var commandLine = new StringBuilder(commandLineText);

		uint hr;
		if (!string.IsNullOrWhiteSpace(workdir)) {
			try {
				hr = LoaderHookCreateProcessEx(assemblyPath, commandLine, workdir);
			}
			catch (EntryPointNotFoundException) {
				WriteErrorRaw("Warning: LoaderHookCreateProcessEx no está disponible. Se usa LoaderHookCreateProcess sin --workdir.");
				hr = LoaderHookCreateProcess(assemblyPath, commandLine);
			}
		}
		else {
			hr = LoaderHookCreateProcess(assemblyPath, commandLine);
		}

		if (hr != 0)
			throw new CliException(ExitCode.LoaderHookFailed, $"LoaderHookCreateProcess failed with HRESULT 0x{hr:X8}.");

		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = true,
				["command"] = "loader-hook",
				["assembly"] = assemblyPath,
				["args"] = extraArgs,
				["workdir"] = string.IsNullOrWhiteSpace(workdir) ? null : workdir
			});
		}
		else {
			WriteInfo("Process created with loader hook.");
		}

		return (int)ExitCode.Success;
	}

	static unsafe int Exports(string[] args) {
		var dict = ParseArgs(args);
		uint pid = ResolveSingleProcessId(dict);
		nuint address = GetAddress(dict);
		using var process = NativeProcess.Open(pid);
		if (process.IsInvalid)
			throw new CliException(ExitCode.AccessDenied, "Failed to open process.");
		var module = process.UnsafeGetModule((void*)address);

		var exports = module.EnumerateFunctionInfos()
			.Select(func => new Dictionary<string, object?> {
				["address"] = Formatter.FormatHex((nuint)func.Address),
				["ordinal"] = func.Ordinal,
				["name"] = func.Name
			})
			.ToArray();

		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = true,
				["command"] = "exports",
				["pid"] = pid,
				["address"] = Formatter.FormatHex(address),
				["count"] = exports.Length,
				["exports"] = exports
			});
		}
		else {
			foreach (var export in exports)
				WriteInfo($"{export["address"],-20} {export["ordinal"],-6} {export["name"]}");
		}

		return (int)ExitCode.Success;
	}

	static int Doctor(string[] args) {
		var checks = new List<Dictionary<string, object?>>();

		void AddCheck(string name, bool ok, string detail) {
			checks.Add(new Dictionary<string, object?> {
				["name"] = name,
				["ok"] = ok,
				["detail"] = detail
			});
		}

		AddCheck(".NET Runtime", true, Environment.Version.ToString());
		AddCheck("OS Architecture", true, Environment.Is64BitOperatingSystem ? "x64" : "x86");
		AddCheck("Process Architecture", true, Environment.Is64BitProcess ? "x64" : "x86");

		bool isAdmin = false;
		try {
			using var identity = WindowsIdentity.GetCurrent();
			var principal = new WindowsPrincipal(identity);
			isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch {
		}
		AddCheck("Administrator", isAdmin, isAdmin ? "Elevated token detected." : "No elevated token.");

		string baseDir = AppDomain.CurrentDomain.BaseDirectory;
		string loaderHookPath = Path.Combine(baseDir, "ExtremeDumper.LoaderHook.dll");
		string loaderHookX86Path = Path.Combine(baseDir, "costura32", "ExtremeDumper.LoaderHook.dll");
		string loaderHookX64Path = Path.Combine(baseDir, "costura64", "ExtremeDumper.LoaderHook.dll");
		bool loaderHookPresent = File.Exists(loaderHookPath) || File.Exists(loaderHookX86Path) || File.Exists(loaderHookX64Path);
		AddCheck("LoaderHook DLL", loaderHookPresent, loaderHookPresent ? "Found." : "Missing ExtremeDumper.LoaderHook.dll.");

		try {
			var provider = ProcessesProviderFactory.Create();
			int processCount = provider.EnumerateProcesses().Count();
			AddCheck("Process enumeration", processCount > 0, $"Found {processCount} processes.");
		}
		catch (Exception ex) {
			AddCheck("Process enumeration", false, ex.Message);
		}

		try {
			string tempFile = Path.Combine(Path.GetTempPath(), $"ExtremeDumper.CLI.doctor.{Guid.NewGuid():N}.tmp");
			File.WriteAllText(tempFile, "ok");
			File.Delete(tempFile);
			AddCheck("Filesystem write", true, Path.GetTempPath());
		}
		catch (Exception ex) {
			AddCheck("Filesystem write", false, ex.Message);
		}

		bool allOk = checks.All(c => c.TryGetValue("ok", out var okObj) && okObj is bool ok && ok);

		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = allOk,
				["command"] = "doctor",
				["checks"] = checks
			});
		}
		else {
			foreach (var check in checks) {
				bool ok = check["ok"] is bool b && b;
				string status = ok ? "[OK]  " : "[FAIL]";
				WriteInfo($"{status} {check["name"]}: {check["detail"]}");
			}
		}

		return allOk ? (int)ExitCode.Success : (int)ExitCode.OperationFailed;
	}

	static bool ModuleMatchesFilters(ExtremeDumper.Diagnostics.ModuleInfo module, bool dotnetOnly, string domainFilter, string clrFilter, bool? inMemoryFilter, string pathFilter, uint? minSize, uint? maxSize) {
		if (dotnetOnly && module is not DotNetModuleInfo)
			return false;

		if (!string.IsNullOrEmpty(pathFilter)) {
			string filePath = module.FilePath ?? string.Empty;
			if (filePath.IndexOf(pathFilter, StringComparison.OrdinalIgnoreCase) < 0)
				return false;
		}

		if (minSize.HasValue && module.ImageSize < minSize.Value)
			return false;
		if (maxSize.HasValue && module.ImageSize > maxSize.Value)
			return false;

		if (module is DotNetModuleInfo dn) {
			if (!string.IsNullOrEmpty(domainFilter) && dn.DomainName.IndexOf(domainFilter, StringComparison.OrdinalIgnoreCase) < 0)
				return false;
			if (!string.IsNullOrEmpty(clrFilter) && dn.CLRVersion.IndexOf(clrFilter, StringComparison.OrdinalIgnoreCase) < 0)
				return false;
			if (inMemoryFilter.HasValue && dn.InMemory != inMemoryFilter.Value)
				return false;
		}
		else {
			if (!string.IsNullOrEmpty(domainFilter) || !string.IsNullOrEmpty(clrFilter))
				return false;
			if (inMemoryFilter.HasValue && inMemoryFilter.Value)
				return false;
		}

		return true;
	}

	static ExtremeDumper.Diagnostics.ModuleInfo? TryGetModuleByAddress(uint pid, nuint address) {
		var unmanaged = ModulesProviderFactory.Create(pid, ModulesProviderType.Unmanaged).EnumerateModules();
		var managed = ModulesProviderFactory.Create(pid, ModulesProviderType.Managed).EnumerateModules();
		return unmanaged.Concat(managed).FirstOrDefault(m => m.ImageBase == address);
	}

	static ImageLayout ResolveAutoImageLayout(uint pid, nuint address) {
		try {
			var managed = ModulesProviderFactory.Create(pid, ModulesProviderType.Managed).EnumerateModules();
			var mod = managed.FirstOrDefault(m => m.ImageBase == address);
			if (mod is DotNetModuleInfo dn && dn.InMemory)
				return ImageLayout.Memory;
		}
		catch {
		}
		return ImageLayout.File;
	}

	static string ResolveDumpProcessDirectory(string outputRoot, string outputTemplate, ProcessInfo process) {
		if (string.IsNullOrWhiteSpace(outputTemplate))
			return outputRoot;

		var context = CreateTemplateContext(process.Id, process.Name, string.Empty, 0, ".dump");
		string relative = ApplyOutputTemplate(outputTemplate, context);
		return Path.IsPathRooted(relative) ? relative : Path.Combine(outputRoot, relative);
	}

	static string ResolveDumpModuleOutputPath(Dictionary<string, string> dict, ProcessInfo process, string moduleName, nuint address, string outputTemplate) {
		if (dict.TryGetValue("--output", out var outputRaw) && !string.IsNullOrWhiteSpace(outputRaw)) {
			string output = ExpandPath(outputRaw);
			if (!string.IsNullOrWhiteSpace(outputTemplate)) {
				var ctx = CreateTemplateContext(process.Id, process.Name, moduleName, address, ".dll");
				string fileName = ApplyOutputTemplate(outputTemplate, ctx);
				if (Path.IsPathRooted(fileName))
					return fileName;
				if (Directory.Exists(output) || output.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal) || output.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal))
					return Path.Combine(output, fileName);
				string? parent = Path.GetDirectoryName(output);
				if (string.IsNullOrEmpty(parent))
					parent = Directory.GetCurrentDirectory();
				return Path.Combine(parent, fileName);
			}

			if (Directory.Exists(output) || output.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal) || output.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal)) {
				string defaultName = BuildDefaultDumpModuleFileName(moduleName, address);
				return Path.Combine(output, defaultName);
			}

			return output;
		}

		if (!string.IsNullOrWhiteSpace(outputTemplate)) {
			var ctx = CreateTemplateContext(process.Id, process.Name, moduleName, address, ".dll");
			string fromTemplate = ApplyOutputTemplate(outputTemplate, ctx);
			if (Path.IsPathRooted(fromTemplate))
				return fromTemplate;
			return Path.Combine(Directory.GetCurrentDirectory(), fromTemplate);
		}

		string name = BuildDefaultDumpModuleFileName(moduleName, address);
		return Path.Combine(Directory.GetCurrentDirectory(), name);
	}

	static string BuildDefaultDumpModuleFileName(string moduleName, nuint address) {
		string name = string.IsNullOrWhiteSpace(moduleName) ? $"module_{address:X}" : moduleName;
		name = EnsureValidFileName(name);
		if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
			name = PathInsertPostfix(name, ".dump");
		else
			name += ".dump.dll";
		return name;
	}

	static Dictionary<string, string> CreateTemplateContext(uint pid, string processName, string moduleName, nuint address, string ext) {
		return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
			["pid"] = pid.ToString(CultureInfo.InvariantCulture),
			["process"] = EnsureValidFileName(processName ?? string.Empty),
			["module"] = EnsureValidFileName(moduleName ?? string.Empty),
			["address"] = ((ulong)address).ToString("X", CultureInfo.InvariantCulture),
			["ext"] = ext.StartsWith(".", StringComparison.Ordinal) ? ext : "." + ext,
			["timestamp"] = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture)
		};
	}

	static string ApplyOutputTemplate(string template, Dictionary<string, string> context) {
		string result = template;
		foreach (var kv in context)
			result = ReplaceIgnoreCase(result, "{" + kv.Key + "}", kv.Value);
		return result;
	}

	static string ReplaceIgnoreCase(string input, string oldValue, string newValue) {
		if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(oldValue))
			return input;

		var sb = new StringBuilder(input.Length);
		int start = 0;
		while (true) {
			int index = input.IndexOf(oldValue, start, StringComparison.OrdinalIgnoreCase);
			if (index < 0) {
				sb.Append(input, start, input.Length - start);
				break;
			}

			sb.Append(input, start, index - start);
			sb.Append(newValue);
			start = index + oldValue.Length;
		}
		return sb.ToString();
	}

	static bool TryParseVerboseLevel(string raw, out Tool.Logging.LogLevel level) {
		switch (raw.Trim().ToLowerInvariant()) {
		case "1":
		case "v1":
		case "verbose1":
			level = Tool.Logging.LogLevel.Verbose1;
			return true;
		case "2":
		case "v2":
		case "verbose2":
			level = Tool.Logging.LogLevel.Verbose2;
			return true;
		case "3":
		case "v3":
		case "verbose3":
			level = Tool.Logging.LogLevel.Verbose3;
			return true;
		default:
			level = Tool.Logging.LogLevel.Verbose3;
			return false;
		}
	}

	static DumperType ParseDumperType(string typeStr) {
		return typeStr switch {
			"normal" => DumperType.Normal,
			"antiantidump" => DumperType.AntiAntiDump,
			_ => throw new CliException(ExitCode.InvalidArguments, "--type debe ser normal o antiantidump.")
		};
	}

	static bool? GetOptionalBool(Dictionary<string, string> dict, string key) {
		if (!dict.TryGetValue(key, out var raw))
			return null;

		if (string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase))
			return true;
		if (string.Equals(raw, "false", StringComparison.OrdinalIgnoreCase) || string.Equals(raw, "0", StringComparison.OrdinalIgnoreCase))
			return false;
		if (string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase))
			return true;
		if (string.Equals(raw, "no", StringComparison.OrdinalIgnoreCase))
			return false;

		throw new CliException(ExitCode.InvalidArguments, $"{key} acepta true/false.");
	}

	static uint? GetOptionalSize(Dictionary<string, string> dict, string key) {
		if (!dict.TryGetValue(key, out var raw))
			return null;
		return ParseSize(raw);
	}

	static uint ParseSize(string raw) {
		string s = raw.Trim();
		if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) {
			if (!uint.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
				throw new CliException(ExitCode.InvalidArguments, $"Tamaño inválido: {raw}");
			return hex;
		}

		uint multiplier = 1;
		if (s.EndsWith("KB", StringComparison.OrdinalIgnoreCase)) {
			multiplier = 1024;
			s = s.Substring(0, s.Length - 2);
		}
		else if (s.EndsWith("MB", StringComparison.OrdinalIgnoreCase)) {
			multiplier = 1024 * 1024;
			s = s.Substring(0, s.Length - 2);
		}
		else if (s.EndsWith("B", StringComparison.OrdinalIgnoreCase)) {
			s = s.Substring(0, s.Length - 1);
		}

		if (!uint.TryParse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
			throw new CliException(ExitCode.InvalidArguments, $"Tamaño inválido: {raw}");
		return checked(value * multiplier);
	}

	static uint ResolveSingleProcessId(Dictionary<string, string> dict) {
		uint pid = GetPid(dict, false);
		string name = GetArg(dict, "--name");
		string contains = GetArg(dict, "--contains");

		int selectorCount = 0;
		if (pid != 0)
			selectorCount++;
		if (!string.IsNullOrWhiteSpace(name))
			selectorCount++;
		if (!string.IsNullOrWhiteSpace(contains))
			selectorCount++;
		if (selectorCount == 0)
			throw new CliException(ExitCode.InvalidArguments, "Debes especificar --pid o --name o --contains.");
		if (selectorCount > 1)
			throw new CliException(ExitCode.InvalidArguments, "Usa un solo selector de proceso: --pid o --name o --contains.");

		if (pid != 0)
			return pid;

		var provider = ProcessesProviderFactory.Create();
		var matches = provider.EnumerateProcesses()
			.Where(p => string.IsNullOrWhiteSpace(name) || string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
			.Where(p => string.IsNullOrWhiteSpace(contains) || p.Name.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0)
			.ToArray();

		if (matches.Length == 0)
			throw new CliException(ExitCode.ProcessNotFound, "No se encontró proceso con ese selector.");
		if (matches.Length > 1) {
			string candidates = string.Join(", ", matches.Take(8).Select(m => $"{m.Id}:{m.Name}"));
			throw new CliException(ExitCode.InvalidArguments, $"Selector ambiguo. Coincidencias: {candidates}. Usa --pid.");
		}

		return matches[0].Id;
	}

	static HashSet<uint> ResolveBatchProcessIds(Dictionary<string, string> dict) {
		var pidSet = new HashSet<uint>();

		if (dict.TryGetValue("--pid-file", out var pidFileRaw)) {
			string pidFile = ExpandPath(pidFileRaw);
			if (!File.Exists(pidFile))
				throw new CliException(ExitCode.InvalidArguments, $"--pid-file no existe: {pidFile}");
			foreach (string line in File.ReadAllLines(pidFile)) {
				string token = line.Trim();
				if (token.Length == 0 || token.StartsWith("#", StringComparison.Ordinal))
					continue;
				foreach (uint pid in ResolvePidToken(token))
					pidSet.Add(pid);
			}
		}

		if (dict.TryGetValue("--process-list", out var processListRaw)) {
			var tokens = processListRaw.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
			foreach (string token in tokens) {
				foreach (uint pid in ResolvePidToken(token.Trim()))
					pidSet.Add(pid);
			}
		}

		if (dict.ContainsKey("--all-dotnet")) {
			var provider = ProcessesProviderFactory.Create();
			foreach (var process in provider.EnumerateProcesses())
				if (process is DotNetProcessInfo)
					pidSet.Add(process.Id);
		}

		return pidSet;
	}

	static IEnumerable<uint> ResolvePidToken(string token) {
		if (uint.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) && pid != 0) {
			yield return pid;
			yield break;
		}

		var provider = ProcessesProviderFactory.Create();
		var matches = provider.EnumerateProcesses()
			.Where(p => string.Equals(p.Name, token, StringComparison.OrdinalIgnoreCase))
			.Select(p => p.Id)
			.ToArray();

		if (matches.Length == 0)
			throw new CliException(ExitCode.ProcessNotFound, $"No se encontró proceso para token: {token}");

		foreach (var id in matches)
			yield return id;
	}

	static ProcessInfo? GetProcessById(uint pid) {
		var provider = ProcessesProviderFactory.Create();
		return provider.EnumerateProcesses().FirstOrDefault(p => p.Id == pid);
	}

	static ExtremeDumper.Injecting.InjectionClrVersion ResolveClrVersion(ModuleDefMD module, Dictionary<string, string> dict) {
		if (dict.TryGetValue("--clr", out var clrStr)) {
			return clrStr.ToLowerInvariant() switch {
				"v2" or "2" => ExtremeDumper.Injecting.InjectionClrVersion.V2,
				"v4" or "4" => ExtremeDumper.Injecting.InjectionClrVersion.V4,
				_ => throw new CliException(ExitCode.InvalidArguments, "CLR inválido. Usa v2 o v4.")
			};
		}
		return module.CorLibTypes.AssemblyRef.Version.Major == 4 ? ExtremeDumper.Injecting.InjectionClrVersion.V4 : ExtremeDumper.Injecting.InjectionClrVersion.V2;
	}

	static IEnumerable<EntryPointInfo> FindManagedEntryPoints(ModuleDefMD module) {
		foreach (var type in module.GetTypes()) {
			foreach (var method in type.Methods) {
				if (!method.IsStatic || method.IsGetter || method.IsSetter)
					continue;
				if (method.Signature is not MethodSig sig)
					continue;
				if (sig.Params.Count != 1 || sig.Params[0].FullName != "System.String")
					continue;
				if (sig.RetType.FullName != "System.Int32")
					continue;

				yield return new EntryPointInfo(type.FullName, method.Name);
			}
		}
	}

	static string BuildCommandLine(string executablePath, string args) {
		string exeQuoted = QuoteArgument(executablePath);
		if (string.IsNullOrWhiteSpace(args))
			return exeQuoted;
		return exeQuoted + " " + args.Trim();
	}

	static string QuoteArgument(string value) {
		if (string.IsNullOrEmpty(value))
			return "\"\"";
		if (value.IndexOf(' ') < 0 && value.IndexOf('\t') < 0 && value.IndexOf('"') < 0)
			return value;
		return "\"" + value.Replace("\"", "\\\"") + "\"";
	}

	static string ExpandPath(string path) {
		return Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
	}

	static void EmitError(ExitCode code, string message, Exception? ex = null) {
		if (jsonOutput) {
			EmitJson(new Dictionary<string, object?> {
				["ok"] = false,
				["error"] = new Dictionary<string, object?> {
					["code"] = (int)code,
					["name"] = code.ToString(),
					["message"] = message
				}
			});
		}
		else {
			WriteErrorRaw($"[{code}] {message}");
			if (ex is not null && Logger.Level >= Tool.Logging.LogLevel.Verbose3)
				WriteErrorRaw(ex.ToString());
		}
	}

	static void EmitJson(Dictionary<string, object?> payload) {
		string json = SerializeJson(payload);
		Console.WriteLine(json);
		WriteLog(json);
	}

	static void WriteInfo(string message) {
		if (jsonOutput)
			return;
		if (!quietOutput)
			Console.WriteLine(message);
		WriteLog(message);
	}

	static void WriteInfoRaw(string message) {
		if (!quietOutput)
			Console.WriteLine(message);
		WriteLog(message);
	}

	static void WriteErrorRaw(string message) {
		Console.Error.WriteLine(message);
		WriteLog(message);
	}

	static void WriteLog(string message) {
		if (logFileWriter is null)
			return;
		logFileWriter.WriteLine(message);
	}

	static string SerializeJson(object? value) {
		var sb = new StringBuilder();
		AppendJsonValue(sb, value);
		return sb.ToString();
	}

	static void AppendJsonValue(StringBuilder sb, object? value) {
		if (value is null) {
			sb.Append("null");
			return;
		}

		switch (value) {
		case string s:
			AppendJsonString(sb, s);
			return;
		case bool b:
			sb.Append(b ? "true" : "false");
			return;
		case byte or sbyte or short or ushort or int or uint or long or ulong:
			sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
			return;
		case float f:
			sb.Append(float.IsNaN(f) || float.IsInfinity(f) ? "null" : f.ToString(CultureInfo.InvariantCulture));
			return;
		case double d:
			sb.Append(double.IsNaN(d) || double.IsInfinity(d) ? "null" : d.ToString(CultureInfo.InvariantCulture));
			return;
		case decimal m:
			sb.Append(m.ToString(CultureInfo.InvariantCulture));
			return;
		case IDictionary<string, object?> dict:
			AppendJsonObject(sb, dict);
			return;
		case IEnumerable<object?> enumerable:
			AppendJsonArray(sb, enumerable);
			return;
		case System.Collections.IEnumerable nonGeneric when value is not string:
			var list = new List<object?>();
			foreach (var item in nonGeneric)
				list.Add(item);
			AppendJsonArray(sb, list);
			return;
		default:
			AppendJsonString(sb, value.ToString() ?? string.Empty);
			return;
		}
	}

	static void AppendJsonObject(StringBuilder sb, IDictionary<string, object?> dict) {
		sb.Append('{');
		bool first = true;
		foreach (var kv in dict) {
			if (!first)
				sb.Append(',');
			first = false;
			AppendJsonString(sb, kv.Key);
			sb.Append(':');
			AppendJsonValue(sb, kv.Value);
		}
		sb.Append('}');
	}

	static void AppendJsonArray(StringBuilder sb, IEnumerable<object?> values) {
		sb.Append('[');
		bool first = true;
		foreach (var value in values) {
			if (!first)
				sb.Append(',');
			first = false;
			AppendJsonValue(sb, value);
		}
		sb.Append(']');
	}

	static void AppendJsonString(StringBuilder sb, string s) {
		sb.Append('"');
		foreach (char c in s) {
			switch (c) {
			case '"':
				sb.Append("\\\"");
				break;
			case '\\':
				sb.Append("\\\\");
				break;
			case '\b':
				sb.Append("\\b");
				break;
			case '\f':
				sb.Append("\\f");
				break;
			case '\n':
				sb.Append("\\n");
				break;
			case '\r':
				sb.Append("\\r");
				break;
			case '\t':
				sb.Append("\\t");
				break;
			default:
				if (c < 32)
					sb.Append("\\u").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
				else
					sb.Append(c);
				break;
			}
		}
		sb.Append('"');
	}

	static string EnsureValidFileName(string fileName) {
		if (string.IsNullOrEmpty(fileName))
			return string.Empty;
		var invalid = Path.GetInvalidFileNameChars();
		var sb = new StringBuilder(fileName.Length);
		foreach (char c in fileName)
			if (!invalid.Contains(c))
				sb.Append(c);
		return sb.ToString();
	}

	static string PathInsertPostfix(string path, string postfix) {
		string? directory = Path.GetDirectoryName(path);
		string name = Path.GetFileNameWithoutExtension(path) + postfix + Path.GetExtension(path);
		return string.IsNullOrEmpty(directory) ? name : Path.Combine(directory, name);
	}

	enum ExitCode {
		Success = 0,
		InvalidArguments = 2,
		ProcessNotFound = 3,
		AccessDenied = 4,
		ModuleNotFound = 5,
		DumpFailed = 6,
		InjectionFailed = 7,
		LoaderHookFailed = 8,
		DependencyMissing = 9,
		OperationFailed = 10,
		BatchPartialFailure = 11,
		UnhandledException = 99
	}

	sealed class CliException : Exception {
		public ExitCode Code { get; }

		public CliException(ExitCode code, string message) : base(message) {
			Code = code;
		}
	}

	readonly struct EntryPointInfo {
		public string DeclaringTypeName { get; }
		public string MethodName { get; }

		public EntryPointInfo(string declaringTypeName, string methodName) {
			DeclaringTypeName = declaringTypeName;
			MethodName = methodName;
		}
	}
}
