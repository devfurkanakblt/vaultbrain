import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const supportedPlatforms = new Set(["windows", "macos", "linux"]);
const hostPlatforms = { win32: "windows", darwin: "macos", linux: "linux" };

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined)
      throw new Error(`Expected --option value, received ${flag ?? "nothing"}`);
    const key = flag.slice(2).replace(/-([a-z])/gu, (_, letter) => letter.toUpperCase());
    options[key] = value;
  }
  return options;
}

function readConfig() {
  return JSON.parse(fs.readFileSync(path.join(root, "src-tauri", "tauri.conf.json"), "utf8"));
}

function relative(bundleDir, item) {
  return path.relative(bundleDir, item).split(path.sep).join("/");
}

function matchingFiles(directory, predicate) {
  if (!fs.existsSync(directory)) return [];
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && predicate(entry.name))
    .map((entry) => path.join(directory, entry.name))
    .sort((left, right) => left.localeCompare(right));
}

function exactlyOne(items, label) {
  if (items.length === 0) throw new Error(`Missing required ${label}`);
  if (items.length > 1)
    throw new Error(`Expected one ${label}, found ${items.map((item) => path.basename(item)).join(", ")}`);
  return items[0];
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function plistValue(contents, key) {
  const expression = new RegExp(`<key>${key}</key>\\s*<string>([^<]+)</string>`, "u");
  return contents.match(expression)?.[1];
}

function machArchitecture(file) {
  const header = fs.readFileSync(file).subarray(0, 8);
  if (header.length < 8) throw new Error(`Cannot read Mach-O header from ${file}`);
  const magic = header.readUInt32LE(0);
  if (magic !== 0xfeedfacf && magic !== 0xfeedface) throw new Error(`Expected Mach-O executable: ${file}`);
  const cpuType = header.readUInt32LE(4);
  if (cpuType === 0x0100000c) return "arm64";
  if (cpuType === 0x01000007) return "x64";
  return `cpu-${cpuType.toString(16)}`;
}

function peArchitecture(file) {
  const contents = fs.readFileSync(file);
  if (contents.subarray(0, 2).toString("ascii") !== "MZ") throw new Error(`Expected PE executable: ${file}`);
  const offset = contents.readUInt32LE(0x3c);
  if (contents.subarray(offset, offset + 4).toString("ascii") !== "PE\0\0")
    throw new Error(`Expected PE header: ${file}`);
  const machine = contents.readUInt16LE(offset + 4);
  if (machine === 0x8664) return "x64";
  if (machine === 0xaa64) return "arm64";
  if (machine === 0x014c) return "x86";
  return `machine-${machine.toString(16)}`;
}

function tarHeader(name, stat, type = "0", linkName = "") {
  const header = Buffer.alloc(512);
  const write = (value, offset, length) => header.write(value, offset, length, "utf8");
  const octal = (value, offset, length) => write(`${value.toString(8).padStart(length - 1, "0")}\0`, offset, length);
  let headerName = name;
  let prefix = "";
  if (Buffer.byteLength(headerName) > 100) {
    const separator = headerName.lastIndexOf("/");
    prefix = headerName.slice(0, separator);
    headerName = headerName.slice(separator + 1);
    if (separator < 1 || Buffer.byteLength(prefix) > 155 || Buffer.byteLength(headerName) > 100)
      throw new Error(`App bundle path is too long to archive portably: ${name}`);
  }
  write(headerName, 0, 100);
  octal(stat.mode & 0o777, 100, 8);
  octal(0, 108, 8);
  octal(0, 116, 8);
  octal(type === "0" || type === "x" ? stat.size : 0, 124, 12);
  octal(0, 136, 12);
  header.fill(0x20, 148, 156);
  write(type, 156, 1);
  write(linkName, 157, 100);
  write("ustar\0", 257, 6);
  write("00", 263, 2);
  write(prefix, 345, 155);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8);
  return header;
}

function paxRecord(key, value) {
  const body = ` ${key}=${value}\n`;
  let length = Buffer.byteLength(body) + 1;
  while (length !== Buffer.byteLength(`${length}${body}`)) length = Buffer.byteLength(`${length}${body}`);
  return `${length}${body}`;
}

function archiveApp(app, archive) {
  const files = [];
  function visit(directory, archiveDirectory) {
    const directoryStat = fs.lstatSync(directory);
    files.push({ archivePath: `${archiveDirectory}/`, stat: directoryStat, type: "5", contents: Buffer.alloc(0) });
    for (const entry of fs.readdirSync(directory).sort((left, right) => left.localeCompare(right))) {
      const item = path.join(directory, entry);
      const archivePath = `${archiveDirectory}/${entry}`;
      const stat = fs.lstatSync(item);
      if (stat.isDirectory()) visit(item, archivePath);
      else if (stat.isFile()) files.push({ item, archivePath, stat, type: "0", contents: fs.readFileSync(item) });
      else if (stat.isSymbolicLink())
        files.push({ item, archivePath, stat, type: "2", linkName: fs.readlinkSync(item), contents: Buffer.alloc(0) });
      else throw new Error(`App bundle contains an unsupported file type: ${item}`);
    }
  }
  visit(app, path.basename(app));
  const entries = files.flatMap(({ archivePath, stat, type, linkName = "", contents }) => {
    const attributes = [];
    const needsPaxPath = Buffer.byteLength(archivePath) > 100;
    if (needsPaxPath) attributes.push(paxRecord("path", archivePath));
    if (Buffer.byteLength(linkName) > 100) attributes.push(paxRecord("linkpath", linkName));
    const paxContents = Buffer.from(attributes.join(""), "utf8");
    const pax = attributes.length
      ? [
          tarHeader("PaxHeader", { mode: stat.mode, size: paxContents.length }, "x"),
          paxContents,
          Buffer.alloc((512 - (paxContents.length % 512)) % 512),
        ]
      : [];
    const padding = Buffer.alloc((512 - (contents.length % 512)) % 512);
    return [
      ...pax,
      tarHeader(
        needsPaxPath ? "PaxPayload" : archivePath,
        stat,
        type,
        Buffer.byteLength(linkName) > 100 ? "" : linkName,
      ),
      contents,
      padding,
    ];
  });
  fs.mkdirSync(path.dirname(archive), { recursive: true });
  fs.writeFileSync(archive, zlib.gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]), { mtime: 0 }));
}

function validateMacApp(app, expected) {
  const info = fs.readFileSync(path.join(app, "Contents", "Info.plist"), "utf8");
  const identifier = plistValue(info, "CFBundleIdentifier");
  const version = plistValue(info, "CFBundleShortVersionString");
  if (identifier !== expected.identifier)
    throw new Error(`macOS identifier mismatch: expected ${expected.identifier}, found ${identifier ?? "missing"}`);
  if (version !== expected.version)
    throw new Error(`macOS version mismatch: expected ${expected.version}, found ${version ?? "missing"}`);
  const executable = exactlyOne(
    matchingFiles(path.join(app, "Contents", "MacOS"), () => true),
    "macOS app executable",
  );
  const architecture = machArchitecture(executable);
  if (architecture !== "arm64") throw new Error(`macOS architecture mismatch: expected arm64, found ${architecture}`);
  return architecture;
}

function validateDmg(dmg, expected) {
  if (process.platform !== "darwin") return "unverified (requires macOS hdiutil)";
  const attached = execFileSync("hdiutil", ["attach", "-nobrowse", "-readonly", "-plist", dmg], { encoding: "utf8" });
  const mountPoint = plistValue(attached, "mount-point");
  if (!mountPoint) throw new Error(`Could not determine the mounted volume for ${dmg}`);
  try {
    const app = exactlyOne(
      fs
        .readdirSync(mountPoint, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && entry.name.endsWith(".app"))
        .map((entry) => path.join(mountPoint, entry.name)),
      "macOS app inside DMG",
    );
    validateMacApp(app, expected);
  } finally {
    execFileSync("hdiutil", ["detach", mountPoint], { stdio: "ignore" });
  }
  return "verified";
}

function validateMacos(bundleDir, outputDir, expected) {
  const app = exactlyOne(
    fs.existsSync(path.join(bundleDir, "macos"))
      ? fs
          .readdirSync(path.join(bundleDir, "macos"), { withFileTypes: true })
          .filter((entry) => entry.isDirectory() && entry.name.endsWith(".app"))
          .map((entry) => path.join(bundleDir, "macos", entry.name))
      : [],
    "macOS artifact: *.app",
  );
  const dmg = exactlyOne(
    matchingFiles(path.join(bundleDir, "dmg"), (name) => name.endsWith(".dmg")),
    "macOS artifact: *.dmg",
  );
  const architecture = validateMacApp(app, expected);
  const dmgValidation = validateDmg(dmg, expected);
  const archive = path.join(outputDir, "macos", `${path.basename(app)}.tar.gz`);
  archiveApp(app, archive);
  return [
    {
      path: relative(bundleDir, dmg),
      kind: "dmg",
      nativeIdentity: expected.identifier,
      architecture: "arm64",
      sha256: sha256(dmg),
      checksumEntries: [{ path: relative(bundleDir, dmg), sha256: sha256(dmg) }],
      validation: dmgValidation,
    },
    {
      path: relative(bundleDir, archive),
      kind: "app-tar-gz",
      nativeIdentity: expected.identifier,
      architecture,
      sha256: sha256(archive),
      checksumEntries: [{ path: relative(bundleDir, archive), sha256: sha256(archive) }],
    },
  ];
}

function validateWindows(bundleDir, expected, installedExecutable) {
  const msi = exactlyOne(
    matchingFiles(path.join(bundleDir, "msi"), (name) => name.endsWith(".msi")),
    "Windows artifact: *.msi",
  );
  const nsis = exactlyOne(
    matchingFiles(path.join(bundleDir, "nsis"), (name) => name.endsWith("-setup.exe")),
    "Windows artifact: *-setup.exe",
  );
  const bootstrapArchitecture = peArchitecture(nsis);
  if (bootstrapArchitecture !== "x86" && bootstrapArchitecture !== "x64")
    throw new Error(`Windows NSIS bootstrap architecture is unsupported: ${bootstrapArchitecture}`);
  const details = JSON.parse(
    execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "param($p) $i=New-Object -ComObject WindowsInstaller.Installer; $d=$i.OpenDatabase($p,0); $v=@{}; 'ProductName','ProductVersion'|%{$q=$d.OpenView(\"SELECT `Value` FROM `Property` WHERE `Property`='$_'\");$q.Execute();$r=$q.Fetch();$v[$_]=$r.StringData(1)}; $s=$d.SummaryInformation(0); @{name=$v.ProductName;version=$v.ProductVersion;template=$s.Property(7)}|ConvertTo-Json -Compress",
        msi,
      ],
      { encoding: "utf8" },
    ),
  );
  if (details.name !== expected.productName)
    throw new Error(
      `Windows identifier mismatch: expected ${expected.productName}, found ${details.name ?? "missing"}`,
    );
  if (details.version !== expected.version)
    throw new Error(`Windows version mismatch: expected ${expected.version}, found ${details.version ?? "missing"}`);
  if (!/x64/iu.test(details.template ?? ""))
    throw new Error(`Windows MSI architecture mismatch: expected x64, found ${details.template ?? "missing"}`);
  const payloadArchitecture = installedExecutable
    ? peArchitecture(installedExecutable)
    : "unverified (requires --installed-executable)";
  if (payloadArchitecture !== "x64" && !payloadArchitecture.startsWith("unverified"))
    throw new Error(`Windows installed payload architecture mismatch: expected x64, found ${payloadArchitecture}`);
  return [
    {
      path: relative(bundleDir, msi),
      kind: "msi",
      nativeIdentity: expected.productName,
      architecture: "x64",
      sha256: sha256(msi),
      checksumEntries: [{ path: relative(bundleDir, msi), sha256: sha256(msi) }],
    },
    {
      path: relative(bundleDir, nsis),
      kind: "nsis",
      nativeIdentity: expected.productName,
      bootstrapArchitecture,
      payloadArchitecture,
      sha256: sha256(nsis),
      checksumEntries: [{ path: relative(bundleDir, nsis), sha256: sha256(nsis) }],
    },
  ];
}

function validateLinux(bundleDir, expected) {
  const deb = exactlyOne(
    matchingFiles(path.join(bundleDir, "deb"), (name) => name.endsWith(".deb")),
    "Linux artifact: *.deb",
  );
  const field = (name) => execFileSync("dpkg-deb", ["--field", deb, name], { encoding: "utf8" }).trim();
  const packageName = field("Package");
  const version = field("Version");
  const architecture = field("Architecture");
  const expectedPackage = expected.productName
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-|-$/gu, "");
  if (packageName !== expectedPackage)
    throw new Error(`Linux identifier mismatch: expected ${expectedPackage}, found ${packageName ?? "missing"}`);
  if (version !== expected.version)
    throw new Error(`Linux version mismatch: expected ${expected.version}, found ${version ?? "missing"}`);
  if (architecture !== "amd64")
    throw new Error(`Linux architecture mismatch: expected amd64, found ${architecture ?? "missing"}`);
  return [
    {
      path: relative(bundleDir, deb),
      kind: "deb",
      nativeIdentity: packageName,
      architecture: "amd64",
      sha256: sha256(deb),
      checksumEntries: [{ path: relative(bundleDir, deb), sha256: sha256(deb) }],
    },
  ];
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const config = readConfig();
  const platform = options.platform ?? hostPlatforms[process.platform];
  if (!supportedPlatforms.has(platform)) throw new Error(`Unsupported platform: ${platform ?? process.platform}`);
  if (options.identifier && platform !== "macos")
    throw new Error("--identifier is only supported for macos; Windows and Linux verify native package identity");
  const bundleDir = path.resolve(options.bundleDir ?? path.join(root, "src-tauri", "target", "release", "bundle"));
  const outputDir = path.resolve(options.outputDir ?? bundleDir);
  if (path.relative(bundleDir, outputDir).startsWith(".."))
    throw new Error("--output-dir must be inside --bundle-dir so manifest paths stay portable");
  const expected = {
    version: options.version ?? config.version,
    identifier: options.identifier ?? config.identifier,
    productName: config.productName,
  };
  const artifacts =
    platform === "macos"
      ? validateMacos(bundleDir, outputDir, expected)
      : platform === "windows"
        ? validateWindows(bundleDir, expected, options.installedExecutable)
        : validateLinux(bundleDir, expected);
  const checksumEntries = artifacts
    .flatMap((artifact) => artifact.checksumEntries)
    .sort((left, right) => left.path.localeCompare(right.path));
  fs.mkdirSync(outputDir, { recursive: true });
  const checksumManifest = path.join(outputDir, "checksums.sha256");
  const uploadManifest = path.join(outputDir, "upload-artifacts.json");
  fs.writeFileSync(
    checksumManifest,
    `${checksumEntries.map((entry) => `${entry.sha256}  ${entry.path}`).join("\n")}\n`,
  );
  fs.writeFileSync(
    uploadManifest,
    `${JSON.stringify({ platform, version: expected.version, configuredIdentifier: expected.identifier, artifacts: artifacts.map(({ checksumEntries: _entries, ...artifact }) => artifact) }, null, 2)}\n`,
  );
  process.stdout.write(
    `${JSON.stringify({ platform, version: expected.version, configuredIdentifier: expected.identifier, artifacts: artifacts.map((artifact) => artifact.path), checksumManifest: relative(bundleDir, checksumManifest), uploadManifest: relative(bundleDir, uploadManifest) })}\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
