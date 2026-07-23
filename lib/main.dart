import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:network_info_plus/network_info_plus.dart';
import 'package:device_info_plus/device_info_plus.dart';

void main() {
  runApp(const CyberDiagnosticsApp());
}

class CyberDiagnosticsApp extends StatelessWidget {
  const CyberDiagnosticsApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NET_DIAG // CYBERPUNK',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0B0E14),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00F0FF),
          secondary: Color(0xFFFF0055),
          surface: Color(0xFF121824),
        ),
        cardTheme: const CardTheme(
          color: Color(0xFF121824),
          elevation: 4,
          margin: EdgeInsets.symmetric(vertical: 6, horizontal: 10),
        ),
      ),
      home: const DashboardScreen(),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  int _selectedIndex = 0;

  final List<Widget> _pages = const [
    PortScannerView(),
    DnsLookupView(),
    PingToolView(),
    WifiInfoView(),
    CryptoToolsView(),
    SslInspectorView(),
    DeviceInfoView(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF121824),
        title: const Text(
          '⚡ NET_DIAG // SENTINEL',
          style: TextStyle(
            color: Color(0xFF00F0FF),
            fontWeight: FontWeight.bold,
            fontFamily: 'monospace',
            letterSpacing: 1.5,
          ),
        ),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(2.0),
          child: Container(color: const Color(0xFF00F0FF), height: 2),
        ),
      ),
      body: _pages[_selectedIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _selectedIndex,
        onTap: (index) => setState(() => _selectedIndex = index),
        selectedItemColor: const Color(0xFF00F0FF),
        unselectedItemColor: Colors.grey,
        backgroundColor: const Color(0xFF121824),
        type: BottomNavigationBarType.fixed,
        items: const [
          BottomNavigationBarItem(icon: Icon(Icons.radar), label: 'Ports'),
          BottomNavigationBarItem(icon: Icon(Icons.dns), label: 'DNS'),
          BottomNavigationBarItem(icon: Icon(Icons.network_ping), label: 'Ping'),
          BottomNavigationBarItem(icon: Icon(Icons.wifi), label: 'Wi-Fi'),
          BottomNavigationBarItem(icon: Icon(Icons.security), label: 'Crypto'),
          BottomNavigationBarItem(icon: Icon(Icons.lock_clock), label: 'SSL'),
          BottomNavigationBarItem(icon: Icon(Icons.perm_device_information), label: 'System'),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// 1. PORT SCANNER VIEW
// -----------------------------------------------------------------------------
class PortScannerView extends StatefulWidget {
  const PortScannerView({super.key});

  @override
  State<PortScannerView> createState() => _PortScannerViewState();
}

class _PortScannerViewState extends State<PortScannerView> {
  final _hostController = TextEditingController(text: '127.0.0.1');
  final List<String> _logs = [];
  bool _isScanning = false;

  final List<int> _commonPorts = [21, 22, 53, 80, 443, 8080, 8443];

  Future<void> _scanPorts() async {
    setState(() {
      _isScanning = true;
      _logs.clear();
      _logs.add('[+] INITIALIZING TCP PORT SCAN: ${_hostController.text}');
    });

    final host = _hostController.text.trim();
    for (int port in _commonPorts) {
      if (!_isScanning) break;
      try {
        final socket = await Socket.connect(host, port, timeout: const Duration(milliseconds: 500));
        setState(() => _logs.add('[OPEN] Port $port/TCP is ACTIVE'));
        await socket.close();
      } catch (_) {
        setState(() => _logs.add('[CLOSED] Port $port/TCP is UNREACHABLE'));
      }
    }

    setState(() {
      _logs.add('[+] SCAN SEQUENCE COMPLETE.');
      _isScanning = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12.0),
      child: Column(
        children: [
          TextField(
            controller: _hostController,
            style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              labelText: 'TARGET HOST / IP',
              labelStyle: TextStyle(color: Color(0xFF00F0FF)),
              enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00F0FF))),
              focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFFFF0055))),
            ),
          ),
          const SizedBox(height: 10),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00F0FF),
              foregroundColor: Colors.black,
              minimumSize: const Size.fromHeight(45),
            ),
            onPressed: _isScanning ? null : _scanPorts,
            child: Text(_isScanning ? 'SCANNING...' : 'EXECUTE PORT SCAN'),
          ),
          const SizedBox(height: 10),
          Expanded(child: ConsoleOutputWidget(logs: _logs, isLoading: _isScanning)),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// 2. DNS LOOKUP VIEW
// -----------------------------------------------------------------------------
class DnsLookupView extends StatefulWidget {
  const DnsLookupView({super.key});

  @override
  State<DnsLookupView> createState() => _DnsLookupViewState();
}

class _DnsLookupViewState extends State<DnsLookupView> {
  final _domainController = TextEditingController(text: 'google.com');
  final List<String> _logs = [];
  bool _isLoading = false;

  Future<void> _lookupDns() async {
    setState(() {
      _isLoading = true;
      _logs.clear();
      _logs.add('[+] RESOLVING DNS RECORDS FOR: ${_domainController.text}');
    });

    try {
      final records = await InternetAddress.lookup(_domainController.text.trim());
      for (var record in records) {
        setState(() => _logs.add(' -> TYPE: ${record.type.name} | ADDRESS: ${record.address}'));
      }
    } catch (e) {
      setState(() => _logs.add('[!] DNS RESOLUTION FAILED: $e'));
    }

    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12.0),
      child: Column(
        children: [
          TextField(
            controller: _domainController,
            style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              labelText: 'DOMAIN NAME',
              labelStyle: TextStyle(color: Color(0xFF00F0FF)),
              enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00F0FF))),
              focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFFFF0055))),
            ),
          ),
          const SizedBox(height: 10),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00F0FF),
              foregroundColor: Colors.black,
              minimumSize: const Size.fromHeight(45),
            ),
            onPressed: _isLoading ? null : _lookupDns,
            child: const Text('LOOKUP DNS RECORDS'),
          ),
          const SizedBox(height: 10),
          Expanded(child: ConsoleOutputWidget(logs: _logs, isLoading: _isLoading)),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// 3. PING & LATENCY CHECKER VIEW
// -----------------------------------------------------------------------------
class PingToolView extends StatefulWidget {
  const PingToolView({super.key});

  @override
  State<PingToolView> createState() => _PingToolViewState();
}

class _PingToolViewState extends State<PingToolView> {
  final _hostController = TextEditingController(text: '8.8.8.8');
  final List<String> _logs = [];
  bool _isPinging = false;

  Future<void> _executePing() async {
    setState(() {
      _isPinging = true;
      _logs.clear();
      _logs.add('[+] PING LATENCY CHECK: ${_hostController.text}');
    });

    final host = _hostController.text.trim();
    for (int i = 1; i <= 4; i++) {
      final stopwatch = Stopwatch()..start();
      try {
        final socket = await Socket.connect(host, 80, timeout: const Duration(seconds: 2));
        stopwatch.stop();
        await socket.close();
        setState(() => _logs.add('SEQ=$i | LATENCY=${stopwatch.elapsedMilliseconds} ms | STATUS=REACHABLE'));
      } catch (_) {
        stopwatch.stop();
        setState(() => _logs.add('SEQ=$i | STATUS=TIMEOUT / UNREACHABLE'));
      }
      await Future.delayed(const Duration(milliseconds: 500));
    }

    setState(() => _isPinging = false);
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12.0),
      child: Column(
        children: [
          TextField(
            controller: _hostController,
            style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              labelText: 'TARGET IP / HOST',
              labelStyle: TextStyle(color: Color(0xFF00F0FF)),
              enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00F0FF))),
              focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFFFF0055))),
            ),
          ),
          const SizedBox(height: 10),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00F0FF),
              foregroundColor: Colors.black,
              minimumSize: const Size.fromHeight(45),
            ),
            onPressed: _isPinging ? null : _executePing,
            child: const Text('EXECUTE LATENCY TEST'),
          ),
          const SizedBox(height: 10),
          Expanded(child: ConsoleOutputWidget(logs: _logs, isLoading: _isPinging)),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// 4. WI-FI & NETWORK INFO VIEW
// -----------------------------------------------------------------------------
class WifiInfoView extends StatefulWidget {
  const WifiInfoView({super.key});

  @override
  State<WifiInfoView> createState() => _WifiInfoViewState();
}

class _WifiInfoViewState extends State<WifiInfoView> {
  final List<String> _logs = [];
  bool _isLoading = false;

  Future<void> _fetchNetworkInfo() async {
    setState(() {
      _isLoading = true;
      _logs.clear();
      _logs.add('[+] READING LOCAL NETWORK INTERFACES...');
    });

    final info = NetworkInfo();
    try {
      final wifiName = await info.getWifiName();
      final wifiBSSID = await info.getWifiBSSID();
      final wifiIP = await info.getWifiIP();

      setState(() {
        _logs.add(' -> SSID: ${wifiName ?? "UNAVAILABLE / NO PERMISSION"}');
        _logs.add(' -> BSSID: ${wifiBSSID ?? "UNAVAILABLE"}');
        _logs.add(' -> LOCAL IP: ${wifiIP ?? "NOT CONNECTED"}');
      });
    } catch (e) {
      setState(() => _logs.add('[!] ERROR READING WI-FI DATA: $e'));
    }

    setState(() => _isLoading = false);
  }

  @override
  void initState() {
    super.initState();
    _fetchNetworkInfo();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12.0),
      child: Column(
        children: [
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00F0FF),
              foregroundColor: Colors.black,
              minimumSize: const Size.fromHeight(45),
            ),
            onPressed: _isLoading ? null : _fetchNetworkInfo,
            child: const Text('REFRESH NETWORK DATA'),
          ),
          const SizedBox(height: 10),
          Expanded(child: ConsoleOutputWidget(logs: _logs, isLoading: _isLoading)),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// 5. CRYPTO & HASHING VIEW
// -----------------------------------------------------------------------------
class CryptoToolsView extends StatefulWidget {
  const CryptoToolsView({super.key});

  @override
  State<CryptoToolsView> createState() => _CryptoToolsViewState();
}

class _CryptoToolsViewState extends State<CryptoToolsView> {
  final _inputController = TextEditingController(text: 'NetSecSentinel');
  final List<String> _logs = [];

  void _generateHashes() {
    final text = _inputController.text;
    final bytes = utf8.encode(text);

    final md5Hash = md5.convert(bytes).toString();
    final sha256Hash = sha256.convert(bytes).toString();
    final base64Encoded = base64.encode(bytes);

    setState(() {
      _logs.clear();
      _logs.add('[+] CRYPTOGRAPHIC HASH RESULTS:');
      _logs.add(' -> RAW INPUT: $text');
      _logs.add(' -> MD5: $md5Hash');
      _logs.add(' -> SHA-256: $sha256Hash');
      _logs.add(' -> BASE64 ENCODED: $base64Encoded');
    });
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12.0),
      child: Column(
        children: [
          TextField(
            controller: _inputController,
            style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              labelText: 'INPUT STRING',
              labelStyle: TextStyle(color: Color(0xFF00F0FF)),
              enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00F0FF))),
              focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFFFF0055))),
            ),
          ),
          const SizedBox(height: 10),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFFF0055),
              foregroundColor: Colors.white,
              minimumSize: const Size.fromHeight(45),
            ),
            onPressed: _generateHashes,
            child: const Text('GENERATE HASHES & BASE64'),
          ),
          const SizedBox(height: 10),
          Expanded(child: ConsoleOutputWidget(logs: _logs, isLoading: false)),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// 6. SSL / TLS INSPECTOR VIEW
// -----------------------------------------------------------------------------
class SslInspectorView extends StatefulWidget {
  const SslInspectorView({super.key});

  @override
  State<SslInspectorView> createState() => _SslInspectorViewState();
}

class _SslInspectorViewState extends State<SslInspectorView> {
  final _urlController = TextEditingController(text: 'https://google.com');
  final List<String> _logs = [];
  bool _isLoading = false;

  Future<void> _inspectSsl() async {
    setState(() {
      _isLoading = true;
      _logs.clear();
      _logs.add('[+] INSPECTING SSL/TLS HANDSHAKE: ${_urlController.text}');
    });

    try {
      final uri = Uri.parse(_urlController.text.trim());
      final client = HttpClient();
      client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;

      final request = await client.getUrl(uri);
      final response = await request.close();
      final cert = response.certificate;

      if (cert != null) {
        setState(() {
          _logs.add(' -> SUBJECT: ${cert.subject}');
          _logs.add(' -> ISSUER: ${cert.issuer}');
          _logs.add(' -> VALID START: ${cert.startValidity}');
          _logs.add(' -> VALID END: ${cert.endValidity}');
          _logs.add(' -> SHA1 FINGERPRINT: ${cert.sha1.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':')}');
        });
      } else {
        setState(() => _logs.add('[!] NO CERTIFICATE RETURNED BY SERVER.'));
      }
      client.close();
    } catch (e) {
      setState(() => _logs.add('[!] HANDSHAKE ERROR: $e'));
    }

    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12.0),
      child: Column(
        children: [
          TextField(
            controller: _urlController,
            style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              labelText: 'TARGET URL (HTTPS)',
              labelStyle: TextStyle(color: Color(0xFF00F0FF)),
              enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00F0FF))),
              focusedBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFFFF0055))),
            ),
          ),
          const SizedBox(height: 10),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00F0FF),
              foregroundColor: Colors.black,
              minimumSize: const Size.fromHeight(45),
            ),
            onPressed: _isLoading ? null : _inspectSsl,
            child: const Text('INSPECT SSL CERTIFICATE'),
          ),
          const SizedBox(height: 10),
          Expanded(child: ConsoleOutputWidget(logs: _logs, isLoading: _isLoading)),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// 7. DEVICE & SYSTEM INFO VIEW
// -----------------------------------------------------------------------------
class DeviceInfoView extends StatefulWidget {
  const DeviceInfoView({super.key});

  @override
  State<DeviceInfoView> createState() => _DeviceInfoViewState();
}

class _DeviceInfoViewState extends State<DeviceInfoView> {
  final List<String> _logs = [];
  bool _isLoading = false;

  Future<void> _fetchDeviceInfo() async {
    setState(() {
      _isLoading = true;
      _logs.clear();
      _logs.add('[+] READING DEVICE HARDWARE SPECIFICATIONS...');
    });

    final deviceInfo = DeviceInfoPlugin();
    try {
      if (Platform.isAndroid) {
        final android = await deviceInfo.androidInfo;
        setState(() {
          _logs.add(' -> BRAND: ${android.brand}');
          _logs.add(' -> MODEL: ${android.model}');
          _logs.add(' -> DEVICE: ${android.device}');
          _logs.add(' -> ANDROID VERSION: ${android.version.release} (SDK ${android.version.sdkInt})');
          _logs.add(' -> HARDWARE: ${android.hardware}');
        });
      } else if (Platform.isIOS) {
        final ios = await deviceInfo.iosInfo;
        setState(() {
          _logs.add(' -> NAME: ${ios.name}');
          _logs.add(' -> MODEL: ${ios.model}');
          _logs.add(' -> SYSTEM VERSION: ${ios.systemVersion}');
        });
      } else {
        setState(() => _logs.add(' -> PLATFORM: ${Platform.operatingSystem}'));
      }
    } catch (e) {
      setState(() => _logs.add('[!] DEVICE INFO ERROR: $e'));
    }

    setState(() => _isLoading = false);
  }

  @override
  void initState() {
    super.initState();
    _fetchDeviceInfo();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12.0),
      child: Column(
        children: [
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF00F0FF),
              foregroundColor: Colors.black,
              minimumSize: const Size.fromHeight(45),
            ),
            onPressed: _isLoading ? null : _fetchDeviceInfo,
            child: const Text('REFRESH SYSTEM INFO'),
          ),
          const SizedBox(height: 10),
          Expanded(child: ConsoleOutputWidget(logs: _logs, isLoading: _isLoading)),
        ],
      ),
    );
  }
}

// -----------------------------------------------------------------------------
// REUSABLE CONSOLE OUTPUT CARD (CYBERPUNK STYLE)
// -----------------------------------------------------------------------------
class ConsoleOutputWidget extends StatelessWidget {
  final List<String> logs;
  final bool isLoading;

  const ConsoleOutputWidget({
    super.key,
    required this.logs,
    required this.isLoading,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12.0),
      decoration: BoxDecoration(
        color: const Color(0xFF0F141C),
        borderRadius: BorderRadius.circular(8.0),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Stack(
        children: [
          ListView.builder(
            itemCount: logs.length,
            itemBuilder: (context, index) {
              final log = logs[index];
              Color textColor = Colors.grey;
              if (log.contains('[OPEN]') || log.contains('STATUS=REACHABLE')) {
                textColor = const Color(0xFF00F0FF);
              } else if (log.contains('[!]') || log.contains('[CLOSED]')) {
                textColor = const Color(0xFFFF0055);
              } else if (log.contains('[+]')) {
                textColor = const Color(0xFF00FF66);
              }

              return Padding(
                padding: const EdgeInsets.symmetric(vertical: 2.0),
                child: Text(
                  log,
                  style: TextStyle(
                    color: textColor,
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              );
            },
          ),
          if (isLoading)
            const Positioned(
              top: 10,
              right: 10,
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  valueColor: AlwaysStoppedAnimation<Color>(Color(0xFF00F0FF)),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
