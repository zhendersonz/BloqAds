package com.henderson.adblock;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Cliente DoH (DNS over HTTPS) para o AdGuard, em HTTP/1.1 puro sobre SSLSocket.
 * Vantagem: trafega pela porta 443, então provedoras que interceptam UDP/53
 * (DNS transparente) não conseguem burlar o bloqueio.
 * O IP do servidor é resolvido via UDP direto para um IP fixo (bootstrap),
 * sem depender do DNS do sistema.
 */
public class DohClient {

    static final String HOST = "dns.adguard-dns.com";
    private static final int PORT = 443;
    private static final byte[][] BOOTSTRAP = {
            { 94, (byte) 140, 14, 14 },
            { 94, (byte) 140, 15, 15 }
    };

    private final VpnBloqService svc;
    private SSLSocket sock;
    private volatile boolean closed = false;
    private InetAddress serverIp;

    public DohClient(VpnBloqService svc) {
        this.svc = svc;
    }

    /** Uma consulta DNS via DoH. Retorna os bytes da resposta ou null. */
    public synchronized byte[] query(byte[] dns) {
        if (closed) return null;
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                ensureConnected();
                sendRequest(dns);
                byte[] resp = readResponse();
                if (resp != null && resp.length >= 12) return resp;
                closeSocket();
            } catch (Exception e) {
                closeSocket();
            }
        }
        return null;
    }

    public void close() {
        closed = true;
        closeSocket();
    }

    private void closeSocket() {
        if (sock != null) {
            try { sock.close(); } catch (Exception ignored) {}
            sock = null;
        }
    }

    private void ensureConnected() throws Exception {
        if (sock != null && sock.isConnected() && !sock.isClosed()) return;
        if (serverIp == null) serverIp = bootstrap();
        Socket plain = new Socket();
        svc.protect(plain);
        plain.connect(new InetSocketAddress(serverIp, PORT), 4000);
        SSLSocketFactory f = sslFactory();
        SSLSocket ssl = (SSLSocket) f.createSocket(plain, HOST, PORT, true);
        ssl.setSoTimeout(3500);
        ssl.startHandshake();
        verifyHost(ssl);
        sock = ssl;
    }

    private static SSLSocketFactory sslFactory() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((java.security.KeyStore) null);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx.getSocketFactory();
    }

    private static void verifyHost(SSLSocket ssl) throws IOException {
        HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
        if (hv == null || !hv.verify(HOST, ssl.getSession())) {
            throw new IOException("certificado nao confere");
        }
    }

    private void sendRequest(byte[] dns) throws IOException {
        OutputStream os = sock.getOutputStream();
        String head = "POST /dns-query HTTP/1.1\r\n"
                + "Host: " + HOST + "\r\n"
                + "Content-Type: application/dns-message\r\n"
                + "Accept: application/dns-message\r\n"
                + "Content-Length: " + dns.length + "\r\n"
                + "\r\n";
        os.write(head.getBytes("ISO-8859-1"));
        os.write(dns);
        os.flush();
    }

    private byte[] readResponse() throws IOException {
        InputStream is = sock.getInputStream();
        String status = readLine(is);
        if (status == null || status.length() < 12) throw new EOFException();
        if (!status.contains(" 200 ")) {
            closeSocket();
            throw new IOException("http: " + status.trim());
        }
        int contentLength = -1;
        boolean chunked = false;
        boolean closeConn = false;
        String line;
        while (true) {
            line = readLine(is);
            if (line == null) throw new EOFException();
            if (line.length() == 0) break;
            String l = line.toLowerCase(java.util.Locale.US);
            if (l.startsWith("content-length:")) {
                try { contentLength = Integer.parseInt(l.substring(15).trim()); } catch (Exception ignored) {}
            } else if (l.startsWith("transfer-encoding:") && l.contains("chunked")) {
                chunked = true;
            } else if (l.startsWith("connection:") && l.contains("close")) {
                closeConn = true;
            }
        }
        byte[] body;
        if (chunked) body = readChunked(is);
        else if (contentLength >= 0) body = readFully(is, contentLength);
        else body = null;
        if (closeConn) closeSocket();
        return body;
    }

    private static byte[] readChunked(InputStream is) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(is);
            if (sizeLine == null) throw new EOFException();
            int semi = sizeLine.indexOf(';');
            String hex = (semi >= 0 ? sizeLine.substring(0, semi) : sizeLine).trim();
            int size;
            try { size = Integer.parseInt(hex, 16); } catch (Exception e) { throw new IOException("chunk invalido"); }
            if (size == 0) {
                while (true) {
                    String t = readLine(is);
                    if (t == null || t.length() == 0) break;
                }
                return out.toByteArray();
            }
            out.write(readFully(is, size));
            readLine(is); // CRLF após o chunk
        }
    }

    private static byte[] readFully(InputStream is, int len) throws IOException {
        byte[] buf = new byte[len];
        int off = 0;
        while (off < len) {
            int n = is.read(buf, off, len - off);
            if (n < 0) throw new EOFException();
            off += n;
        }
        return buf;
    }

    private static String readLine(InputStream is) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        while (true) {
            int c = is.read();
            if (c < 0) {
                if (b.size() == 0) return null;
                break;
            }
            if (c == '\n') break;
            if (c != '\r') b.write(c);
        }
        return new String(b.toByteArray(), "ISO-8859-1");
    }

    /** Resolve o IP do servidor DoH via UDP direto para IP fixo (sem depender do DNS do sistema). */
    private InetAddress bootstrap() {
        try {
            byte[] q = buildQuery(HOST);
            for (byte[] srv : BOOTSTRAP) {
                DatagramSocket s = null;
                try {
                    s = new DatagramSocket();
                    svc.protect(s);
                    s.setSoTimeout(3000);
                    s.connect(new InetSocketAddress(InetAddress.getByAddress(srv), 53));
                    s.send(new DatagramPacket(q, q.length));
                    byte[] buf = new byte[1500];
                    DatagramPacket rp = new DatagramPacket(buf, buf.length);
                    s.receive(rp);
                    InetAddress ip = firstA(buf, rp.getLength());
                    if (ip != null) return ip;
                } catch (Exception ignored) {
                } finally {
                    if (s != null) s.close();
                }
            }
        } catch (Exception ignored) {}
        try {
            return InetAddress.getByAddress(BOOTSTRAP[0]); // o próprio IP anycast também serve DoH
        } catch (Exception e) {
            return null;
        }
    }

    /** Monta uma consulta DNS do tipo A para um nome. */
    static byte[] buildQuery(String name) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] hdr = { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        o.write(hdr);
        String[] labels = name.split("\\.");
        for (String lbl : labels) {
            o.write(lbl.length());
            o.write(lbl.getBytes("ISO-8859-1"));
        }
        o.write(0);
        o.write(0); o.write(1);  // QTYPE = A
        o.write(0); o.write(1);  // QCLASS = IN
        return o.toByteArray();
    }

    /** Primeiro registro A de uma resposta DNS; usado no bootstrap. */
    static InetAddress firstA(byte[] r, int len) {
        try {
            if (len < 12) return null;
            int qd = u16(r, 4);
            int an = u16(r, 6);
            int i = 12;
            for (int k = 0; k < qd; k++) {
                i = skipName(r, i, len);
                if (i < 0) return null;
                i += 4;
            }
            for (int k = 0; k < an; k++) {
                i = skipName(r, i, len);
                if (i < 0) return null;
                if (i + 10 > len) return null;
                int type = u16(r, i);
                int rdlen = u16(r, i + 8);
                i += 10;
                if (i + rdlen > len) return null;
                if (type == 1 && rdlen == 4) {
                    return InetAddress.getByAddress(Arrays.copyOfRange(r, i, i + 4));
                }
                i += rdlen;
            }
        } catch (Exception ignored) {}
        return null;
    }

    static int u16(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF);
    }

    static int skipName(byte[] b, int i, int len) {
        while (true) {
            if (i >= len) return -1;
            int v = b[i] & 0xFF;
            if ((v & 0xC0) == 0xC0) return i + 2;
            if (v == 0) return i + 1;
            i += 1 + v;
        }
    }
}
