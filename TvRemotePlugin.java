package com.miremoto.tv;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.io.*;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;

/** Android TV Remote v2: emparejamiento (6467) y control (6466). */
@CapacitorPlugin(name = "TvRemote")
public class TvRemotePlugin extends Plugin {
  private final ExecutorService exec = Executors.newCachedThreadPool();
  private SSLSocket ps, rs;
  private InputStream pi;
  private OutputStream po, ro;
  private X509Certificate srvCert;
  private static final Map<String, Integer> K = new HashMap<>();
  static {
    Object[] a = {"DPAD_UP",19,"DPAD_DOWN",20,"DPAD_LEFT",21,"DPAD_RIGHT",22,"DPAD_CENTER",23,"BACK",4,"HOME",3,
      "MENU",82,"POWER",26,"MUTE",164,"VOLUME_UP",24,"VOLUME_DOWN",25,"CHANNEL_UP",166,"CHANNEL_DOWN",167,
      "MEDIA_PLAY_PAUSE",85,"MEDIA_STOP",86,"MEDIA_REWIND",89,"MEDIA_FAST_FORWARD",90,"TV_INPUT",178,"DEL",67,"ENTER",66};
    for (int i = 0; i < a.length; i += 2) K.put((String) a[i], (Integer) a[i + 1]);
  }

  // ---- protobuf mínimo ----
  static byte[] vi(long v) { ByteArrayOutputStream b = new ByteArrayOutputStream(); while (v >= 0x80) { b.write((int) (v & 0x7f) | 0x80); v >>>= 7; } b.write((int) v); return b.toByteArray(); }
  static byte[] cat(byte[]... p) { ByteArrayOutputStream b = new ByteArrayOutputStream(); for (byte[] x : p) b.write(x, 0, x.length); return b.toByteArray(); }
  static byte[] vf(int f, long v) { return cat(vi((long) f << 3), vi(v)); }
  static byte[] ld(int f, byte[] d) { return cat(vi(((long) f << 3) | 2), vi(d.length), d); }
  static byte[] ld(int f, String s) { return ld(f, s.getBytes()); }
  static long rv(InputStream in) throws IOException { long r = 0; int s = 0; while (true) { int c = in.read(); if (c < 0) throw new EOFException(); r |= (long) (c & 0x7f) << s; if ((c & 0x80) == 0) return r; s += 7; } }
  static byte[] rf(InputStream in) throws IOException { int n = (int) rv(in); byte[] b = new byte[n]; int o = 0; while (o < n) { int k = in.read(b, o, n - o); if (k < 0) throw new EOFException(); o += k; } return b; }
  static void send(OutputStream o, byte[] m) throws IOException { synchronized (o) { o.write(cat(vi(m.length), m)); o.flush(); } }
  static Map<Integer, Object> parse(byte[] d) {
    Map<Integer, Object> m = new HashMap<>(); ByteArrayInputStream in = new ByteArrayInputStream(d);
    try { while (in.available() > 0) { long t = rv(in); int f = (int) (t >> 3), w = (int) (t & 7); if (w == 0) m.put(f, rv(in)); else if (w == 2) m.put(f, rf(in)); else break; } } catch (IOException e) { }
    return m;
  }
  static byte[] outer(int f, byte[] body) { return cat(vf(1, 2), vf(2, 200), ld(f, body)); }
  static byte[] un(BigInteger b) { byte[] x = b.toByteArray(); return (x.length > 1 && x[0] == 0) ? Arrays.copyOfRange(x, 1, x.length) : x; }
  static byte[] hex(String s) { byte[] r = new byte[s.length() / 2]; for (int i = 0; i < r.length; i++) r[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16); return r; }
  static void close(Closeable c) { try { if (c != null) c.close(); } catch (Exception e) { } }

  // ---- TLS con certificado propio (Android Keystore) ----
  private KeyStore ks() throws Exception { KeyStore k = KeyStore.getInstance("AndroidKeyStore"); k.load(null); return k; }
  private SSLSocketFactory factory() throws Exception {
    KeyStore k = ks();
    if (!k.containsAlias("tvremote")) {
      long now = System.currentTimeMillis(), day = 86400000L;
      KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
      g.initialize(new KeyGenParameterSpec.Builder("tvremote", KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        .setKeySize(2048).setCertificateSubject(new X500Principal("CN=control-remoto"))
        .setCertificateNotBefore(new Date(now - day)).setCertificateNotAfter(new Date(now + 3650 * day)).build());
      g.generateKeyPair();
    }
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(k, null);
    TrustManager[] tm = {new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] c, String a) { }
      public void checkServerTrusted(X509Certificate[] c, String a) { }
      public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; } }};
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf.getKeyManagers(), tm, null);
    return ctx.getSocketFactory();
  }
  private SSLSocket open(String host, int port) throws Exception {
    SSLSocket s = (SSLSocket) factory().createSocket();
    s.connect(new java.net.InetSocketAddress(host, port), 5000);
    s.startHandshake();
    return s;
  }

  // ---- descubrimiento automático (mDNS) ----
  @PluginMethod
  public void discover(PluginCall call) {
    NsdManager nsd = (NsdManager) getContext().getSystemService(Context.NSD_SERVICE);
    final JSArray out = new JSArray(); final Set<String> seen = new HashSet<>();
    final NsdManager.DiscoveryListener dl = new NsdManager.DiscoveryListener() {
      public void onServiceFound(NsdServiceInfo s) {
        nsd.resolveService(s, new NsdManager.ResolveListener() {
          public void onServiceResolved(NsdServiceInfo r) {
            if (!(r.getHost() instanceof Inet4Address)) return;
            synchronized (out) { if (seen.add(r.getHost().getHostAddress())) { JSObject o = new JSObject(); o.put("name", r.getServiceName()); o.put("host", r.getHost().getHostAddress()); out.put(o); } }
          }
          public void onResolveFailed(NsdServiceInfo s2, int e) { }
        });
      }
      public void onServiceLost(NsdServiceInfo s) { }
      public void onDiscoveryStarted(String t) { }
      public void onDiscoveryStopped(String t) { }
      public void onStartDiscoveryFailed(String t, int e) { }
      public void onStopDiscoveryFailed(String t, int e) { }
    };
    nsd.discoverServices("_androidtvremote2._tcp.", NsdManager.PROTOCOL_DNS_SD, dl);
    exec.execute(() -> {
      try { Thread.sleep(4000); } catch (Exception e) { }
      try { nsd.stopServiceDiscovery(dl); } catch (Exception e) { }
      JSObject r = new JSObject(); synchronized (out) { r.put("devices", out); } call.resolve(r);
    });
  }

  // ---- emparejamiento por código ----
  @PluginMethod
  public void startPairing(PluginCall call) {
    final String host = call.getString("host");
    exec.execute(() -> {
      try {
        close(ps); ps = open(host, 6467);
        pi = ps.getInputStream(); po = ps.getOutputStream();
        srvCert = (X509Certificate) ps.getSession().getPeerCertificates()[0];
        byte[] enc = cat(vf(1, 3), vf(2, 6));
        send(po, outer(10, cat(ld(1, "atvremote"), ld(2, "Control Remoto")))); rf(pi);
        send(po, outer(20, cat(ld(1, enc), vf(3, 1)))); rf(pi);
        send(po, outer(30, cat(ld(1, enc), vf(2, 1)))); rf(pi);
        call.resolve();
      } catch (Exception e) { call.reject(String.valueOf(e)); }
    });
  }

  @PluginMethod
  public void finishPairing(PluginCall call) {
    final String code = call.getString("code", "").trim().toUpperCase();
    exec.execute(() -> {
      try {
        byte[] cb = hex(code);
        RSAPublicKey c = (RSAPublicKey) ks().getCertificate("tvremote").getPublicKey();
        RSAPublicKey s = (RSAPublicKey) srvCert.getPublicKey();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(un(c.getModulus())); md.update(un(c.getPublicExponent()));
        md.update(un(s.getModulus())); md.update(un(s.getPublicExponent()));
        md.update(cb, 1, cb.length - 1);
        byte[] h = md.digest();
        if (h[0] != cb[0]) throw new Exception("Código incorrecto");
        send(po, outer(40, ld(1, h))); rf(pi);
        close(ps); call.resolve();
      } catch (Exception e) { call.reject(String.valueOf(e)); }
    });
  }

  // ---- control ----
  @PluginMethod
  public void connect(PluginCall call) {
    final String host = call.getString("host");
    exec.execute(() -> {
      try {
        close(rs); rs = open(host, 6466);
        final InputStream in = rs.getInputStream(); final OutputStream out = rs.getOutputStream(); ro = out;
        final CountDownLatch ready = new CountDownLatch(1);
        new Thread(() -> {
          try {
            while (true) {
              Map<Integer, Object> m = parse(rf(in));
              if (m.containsKey(1)) send(out, ld(1, cat(vf(1, 622), ld(2, cat(ld(1, "Control Remoto"), ld(2, "Android"), vf(3, 1), ld(4, "1"), ld(5, "com.miremoto.tv"), ld(6, "1.0.0"))))));
              else if (m.containsKey(2)) { send(out, ld(2, vf(1, 622))); ready.countDown(); }
              else if (m.containsKey(8)) { Object v = parse((byte[]) m.get(8)).get(1); send(out, ld(9, vf(1, v instanceof Long ? (Long) v : 0L))); }
            }
          } catch (Exception e) { ro = null; }
        }).start();
        if (ready.await(6, TimeUnit.SECONDS)) call.resolve(); else { close(rs); call.reject("La TV no respondió"); }
      } catch (Exception e) { call.reject(String.valueOf(e)); }
    });
  }

  private void key(int code) throws IOException { OutputStream o = ro; if (o == null) throw new IOException("No conectado"); send(o, ld(10, cat(vf(1, code), vf(2, 3)))); }

  @PluginMethod
  public void sendKey(PluginCall call) {
    final Integer c = K.get(call.getString("key", ""));
    if (c == null) { call.reject("Tecla desconocida"); return; }
    exec.execute(() -> { try { key(c); call.resolve(); } catch (Exception e) { call.reject(String.valueOf(e)); } });
  }

  @PluginMethod
  public void sendText(PluginCall call) {
    final String t = call.getString("text", "");
    exec.execute(() -> {
      try {
        for (char ch : t.toCharArray()) {
          char c = Character.toLowerCase(ch); int k = -1;
          if (c >= 'a' && c <= 'z') k = 29 + (c - 'a'); else if (c >= '0' && c <= '9') k = 7 + (c - '0');
          else if (c == ' ') k = 62; else if (c == '.') k = 56; else if (c == ',') k = 55; else if (c == '-') k = 69;
          if (k > 0) key(k);
        }
        call.resolve();
      } catch (Exception e) { call.reject(String.valueOf(e)); }
    });
  }

  @PluginMethod
  public void openApp(PluginCall call) {
    final String a = call.getString("app", "");
    final String link = a.equals("youtube") ? "https://www.youtube.com" : a.equals("netflix") ? "https://www.netflix.com"
      : a.equals("prime") ? "https://app.primevideo.com" : "https://www.disneyplus.com";
    exec.execute(() -> {
      try { OutputStream o = ro; if (o == null) throw new IOException("No conectado"); send(o, ld(90, ld(1, link))); call.resolve(); }
      catch (Exception e) { call.reject(String.valueOf(e)); }
    });
  }
}
