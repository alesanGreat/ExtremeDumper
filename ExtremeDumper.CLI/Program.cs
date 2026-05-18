using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
using NativeInjectionClrVersion = NativeSharp.InjectionClrVersion;

namespace ExtremeDumper.CLI;

public static class Program {
	[DllImport("ExtremeDumper.LoaderHook.dll", BestFitMapping = false, CharSet = CharSet.Unicode, SetLastError = true)]
	static extern uint LoaderHookCreateProcess(string applicationName, StringBuilder? commandLine);

	public static int Main(string[] args) {
		if (args.Length == 0) {
			PrintUsage();
			return 1;
		}
		ConfigureGlobalOptions(args);
		int commandIndex = Array.FindIndex(args, arg => !arg.StartsWith("--", StringComparison.Ordinal));
		if (commandIndex < 0) {
			PrintUsage();
			return 1;
		}
		if (commandIndex > 0)
			args = args.Skip(commandIndex).ToArray();

		try {
			return args[0].ToLowerInvariant() switch {
				"list-processes" or "ps" => ListProcesses(args),
				"list-modules" or "modules" => ListModules(args),
				"dump-process" => DumpProcess(args),
				"dump-module" => DumpModule(args),
				"inject" => Inject(args),
				"loader-hook" => LoaderHook(args),
				"exports" => Exports(args),
				_ => UnknownCommand(args[0])
			};
		}
		catch (Exception ex) {
			Console.Error.WriteLine($"Error: {ex.Message}");
			Console.Error.WriteLine(ex.StackTrace);
			Console.Out.Flush();
			Console.Error.Flush();
			return 1;
		}
		finally {
			Console.Out.Flush();
			Console.Error.Flush();
		}
	}

	static void ConfigureGlobalOptions(string[] args) {
		if (!args.Any(arg => string.Equals(arg, "--verbose", StringComparison.OrdinalIgnoreCase)))
			return;
		Logger.Level = Tool.Logging.LogLevel.Verbose3;
		Logger.Info("Verbose logging enabled.");
	}

	static int UnknownCommand(string cmd) {
		Console.Error.WriteLine($"Unknown command: {cmd}");
		PrintUsage();
		return 1;
	}

	static void PrintUsage() {
		Console.WriteLine(@"ExtremeDumper.CLI - .NET Assembly Dumper (Command Line Interface)
Usage: ExtremeDumper.CLI <command> [options]

Commands:
  list-processes, ps          List all processes
    --dotnet-only             Show only .NET processes

  list-modules, modules       List modules of a process
    --pid <id>                Process ID (required)
    --type <type>             Provider type: unmanaged (default), managed, aad
    --dotnet-only             Show only .NET modules (applies to unmanaged provider)

  dump-process                Dump all .NET assemblies from a process
    --pid <id>                Process ID (required)
    --output <path>           Output directory (default: .\Dumps)
    --type <type>             Dumper type: normal (default), antiantidump

  dump-module                 Dump a specific module
    --pid <id>                Process ID (required)
    --address <hex>           Module base address, e.g. 0x7FF123450000 (required)
    --output <path>           Output file path (default: auto-generated)
    --type <type>             Dumper type: normal (default), antiantidump
    --layout <layout>         Image layout: file or memory (default: auto)

  inject                      Inject an assembly into a process
    --pid <id>                Process ID (required)
    --assembly <path>         Assembly/DLL path (required)
    --type-name <name>        Full type name for managed injection
    --method-name <name>      Method name for managed injection
    --argument <arg>          Argument string for managed injection
    --clr <version>           CLR version: v2 or v4 (auto-detected if omitted)
    --wait                    Wait for method return value (managed only)
    --unmanaged               Inject as unmanaged DLL

  loader-hook                 Run an executable with the .NET loader hook
    --assembly <path>         Executable path to run (required)

  exports                     List exported functions of a module
    --pid <id>                Process ID (required)
    --address <hex>           Module base address (required)

Global options:
  --verbose                   Enable verbose logging
");
	}

	static Dictionary<string, string> ParseArgs(string[] args) {
		var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		for (int i = 1; i < args.Length; i++) {
			if (args[i].StartsWith("--")) {
				string key = args[i];
				string value = "true";
				if (i + 1 < args.Length && !args[i + 1].StartsWith("--")) {
					value = args[i + 1];
					i++;
				}
				dict[key] = value;
			}
		}
		return dict;
	}

	static string GetArg(Dictionary<string, string> dict, string key, string defaultValue = "") {
		return dict.TryGetValue(key, out var value) ? value : defaultValue;
	}

	static uint GetPid(Dictionary<string, string> dict) {
		if (!dict.TryGetValue("--pid", out var s) || !uint.TryParse(s, out var pid))
			throw new ArgumentException("--pid is required and must be a valid process ID.");
		return pid;
	}

	static nuint GetAddress(Dictionary<string, string> dict) {
		if (!dict.TryGetValue("--address", out var s))
			throw new ArgumentException("--address is required.");
		s = s.Trim();
		if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
			s = s.Substring(2);
		return (nuint)ulong.Parse(s, NumberStyles.HexNumber);
	}

	static int ListProcesses(string[] args) {
		var dict = ParseArgs(args);
		bool dotnetOnly = dict.ContainsKey("--dotnet-only");
		var provider = ProcessesProviderFactory.Create();
		foreach (var process in provider.EnumerateProcesses()) {
			if (dotnetOnly && process is not DotNetProcessInfo)
				continue;
			string clr = process is DotNetProcessInfo dn
				? string.Join(", ", dn.CLRModules.Select(m => m.Name))
				: "";
			string bitness = process.Is64Bit ? "x64" : "x86";
			Console.WriteLine($"{process.Id,-8} {bitness,-4} {process.Name,-30} {clr}");
			if (!string.IsNullOrEmpty(process.FilePath))
				Console.WriteLine($"         Path: {process.FilePath}");
		}
		return 0;
	}

	static int ListModules(string[] args) {
		var dict = ParseArgs(args);
		uint pid = GetPid(dict);
		bool dotnetOnly = dict.ContainsKey("--dotnet-only");
		string typeStr = GetArg(dict, "--type", "unmanaged").ToLowerInvariant();
		ModulesProviderType providerType = typeStr switch {
			"managed" => ModulesProviderType.Managed,
			"aad" => ModulesProviderType.ManagedAAD,
			_ => ModulesProviderType.Unmanaged
		};

		IEnumerable<ExtremeDumper.Diagnostics.ModuleInfo> modules;
		if (providerType == ModulesProviderType.ManagedAAD) {
			modules = AADExtensions.EnumerateAADClients(pid).SelectMany(c => c.EnumerateModules()).Cast<ExtremeDumper.Diagnostics.ModuleInfo>();
		}
		else {
			modules = ModulesProviderFactory.Create(pid, providerType).EnumerateModules();
		}

		foreach (var module in modules) {
			if (dotnetOnly && module is not DotNetModuleInfo)
				continue;
			string addr = Formatter.FormatHex(module.ImageBase);
			string size = Formatter.FormatHex(module.ImageSize);
			if (module is DotNetModuleInfo dn) {
				string path = string.IsNullOrEmpty(module.FilePath) ? "InMemory" : module.FilePath;
				Console.WriteLine($"[.NET]   {addr} {size,-18} {dn.DomainName,-20} {dn.CLRVersion,-12} {module.Name}");
				Console.WriteLine($"         Path: {path}");
			}
			else {
				string path = string.IsNullOrEmpty(module.FilePath) ? "InMemory" : module.FilePath;
				Console.WriteLine($"[Native] {addr} {size,-18} {module.Name}");
				Console.WriteLine($"         Path: {path}");
			}
		}
		return 0;
	}

	static int DumpProcess(string[] args) {
		var dict = ParseArgs(args);
		uint pid = GetPid(dict);
		string output = GetArg(dict, "--output", Path.Combine(Directory.GetCurrentDirectory(), "Dumps"));
		string typeStr = GetArg(dict, "--type", "normal").ToLowerInvariant();
		var dumperType = typeStr == "antiantidump" ? DumperType.AntiAntiDump : DumperType.Normal;

		if (!Directory.Exists(output))
			Directory.CreateDirectory(output);

		using var dumper = DumperFactory.Create(pid, dumperType);
		int count = dumper.DumpProcess(output);
		Console.WriteLine($"Dumped {count} image(s) to: {output}");
		return 0;
	}

	static int DumpModule(string[] args) {
		var dict = ParseArgs(args);
		uint pid = GetPid(dict);
		nuint address = GetAddress(dict);
		string typeStr = GetArg(dict, "--type", "normal").ToLowerInvariant();
		var dumperType = typeStr == "antiantidump" ? DumperType.AntiAntiDump : DumperType.Normal;
		string layoutStr = GetArg(dict, "--layout", "auto").ToLowerInvariant();

		string outputPath;
		if (dict.TryGetValue("--output", out var outVal)) {
			outputPath = outVal;
		}
		else {
			string? name = null;
			try {
				var allModules = ModulesProviderFactory.Create(pid, ModulesProviderType.Unmanaged).EnumerateModules()
					.Concat(ModulesProviderFactory.Create(pid, ModulesProviderType.Managed).EnumerateModules());
				name = allModules.FirstOrDefault(m => m.ImageBase == address)?.Name;
			}
			catch { }
			name ??= $"module_{address:X}";
			name = EnsureValidFileName(name);
			if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
				name = PathInsertPostfix(name, ".dump");
			else
				name += ".dump.dll";
			outputPath = Path.Combine(Directory.GetCurrentDirectory(), name);
		}

		ImageLayout imageLayout = ImageLayout.File;
		if (layoutStr == "memory")
			imageLayout = ImageLayout.Memory;
		else if (layoutStr == "auto") {
			try {
				var managed = ModulesProviderFactory.Create(pid, ModulesProviderType.Managed).EnumerateModules();
				var mod = managed.FirstOrDefault(m => m.ImageBase == address);
				if (mod is DotNetModuleInfo dn && dn.InMemory)
					imageLayout = ImageLayout.Memory;
			}
			catch { }
		}

		using var dumper = DumperFactory.Create(pid, dumperType);
		bool ok = dumper.DumpModule(address, imageLayout, outputPath);
		if (ok)
			Console.WriteLine($"Dumped module to: {outputPath}");
		else
			throw new InvalidOperationException("Failed to dump module.");
		return 0;
	}

	static int Inject(string[] args) {
		var dict = ParseArgs(args);
		uint pid = GetPid(dict);
		string assemblyPath = GetArg(dict, "--assembly", "");
		if (!File.Exists(assemblyPath))
			throw new FileNotFoundException("Assembly not found.", assemblyPath);

		bool unmanaged = dict.ContainsKey("--unmanaged");
		if (unmanaged) {
			bool ok = ExtremeDumper.Injecting.Injector.InjectUnmanaged(pid, assemblyPath);
			Console.WriteLine(ok ? "Injected successfully." : "Failed to inject.");
			return ok ? 0 : 1;
		}

		string typeName = GetArg(dict, "--type-name", "");
		string methodName = GetArg(dict, "--method-name", "");
		string argument = GetArg(dict, "--argument", "");
		bool wait = dict.ContainsKey("--wait");

		using var module = ModuleDefMD.Load(File.ReadAllBytes(assemblyPath));
		if (string.IsNullOrEmpty(typeName) || string.IsNullOrEmpty(methodName)) {
			var candidates = new List<MethodDef>();
			foreach (var type in module.GetTypes()) {
				foreach (var method in type.Methods) {
					if (!method.IsStatic || method.IsGetter || method.IsSetter)
						continue;
					var sig = method.Signature as MethodSig;
					if (sig is null || sig.Params.Count != 1 || sig.Params[0].FullName != "System.String")
						continue;
					if (sig.RetType.FullName != "System.Int32")
						continue;
					candidates.Add(method);
				}
			}
			if (candidates.Count == 0)
				throw new InvalidOperationException("No suitable static entry point found (signature: static int Method(string)).");
			if (candidates.Count == 1 || string.IsNullOrEmpty(methodName)) {
				var ep = candidates[0];
				typeName = ep.DeclaringType.FullName;
				methodName = ep.Name;
			}
			else if (!string.IsNullOrEmpty(methodName)) {
				var ep = candidates.FirstOrDefault(m => m.Name == methodName);
				if (ep is null)
					throw new InvalidOperationException($"Method '{methodName}' not found with valid signature.");
				typeName = ep.DeclaringType.FullName;
				methodName = ep.Name;
			}
		}

		ExtremeDumper.Injecting.InjectionClrVersion clrVersion;
		if (dict.TryGetValue("--clr", out var clrStr)) {
			clrVersion = clrStr.ToLowerInvariant() switch {
				"v2" or "2" => ExtremeDumper.Injecting.InjectionClrVersion.V2,
				"v4" or "4" => ExtremeDumper.Injecting.InjectionClrVersion.V4,
				_ => throw new ArgumentException("Invalid CLR version. Use v2 or v4.")
			};
		}
		else {
			clrVersion = module.CorLibTypes.AssemblyRef.Version.Major == 4 ? ExtremeDumper.Injecting.InjectionClrVersion.V4 : ExtremeDumper.Injecting.InjectionClrVersion.V2;
		}

		bool ok2;
		if (wait) {
			ok2 = ExtremeDumper.Injecting.Injector.InjectManagedAndWait(pid, assemblyPath, typeName, methodName, argument, clrVersion, out int ret);
			if (ok2)
				Console.WriteLine($"Injected successfully. Return value: 0x{ret:X}");
			else
				Console.WriteLine("Failed to inject.");
		}
		else {
			ok2 = ExtremeDumper.Injecting.Injector.InjectManaged(pid, assemblyPath, typeName, methodName, argument, clrVersion);
			Console.WriteLine(ok2 ? "Injected successfully." : "Failed to inject.");
		}
		return ok2 ? 0 : 1;
	}

	static int LoaderHook(string[] args) {
		var dict = ParseArgs(args);
		string assemblyPath = GetArg(dict, "--assembly", "");
		if (!File.Exists(assemblyPath))
			throw new FileNotFoundException("Executable not found.", assemblyPath);

		uint hr = LoaderHookCreateProcess(assemblyPath, null);
		if (hr == 0) {
			Console.WriteLine("Process created with loader hook.");
			return 0;
		}
		else {
			Console.Error.WriteLine($"LoaderHookCreateProcess failed with HRESULT 0x{hr:X8}. Try using the x86 build if target is 32-bit.");
			return 1;
		}
	}

	static unsafe int Exports(string[] args) {
		var dict = ParseArgs(args);
		uint pid = GetPid(dict);
		nuint address = GetAddress(dict);
		using var process = NativeProcess.Open(pid);
		if (process.IsInvalid)
			throw new InvalidOperationException("Failed to open process.");
		var module = process.UnsafeGetModule((void*)address);
		foreach (var func in module.EnumerateFunctionInfos()) {
			Console.WriteLine($"{Formatter.FormatHex((nuint)func.Address),-20} {func.Ordinal,-6} {func.Name}");
		}
		return 0;
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
		return Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + postfix + Path.GetExtension(path));
	}
}
