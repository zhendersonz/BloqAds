package com.henderson.adblock;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * BloqAds - bloqueio de anúncios por DNS.
 *
 * Cria uma VPN local cuja única rota é o IP do "DNS falso" (10.111.222.3).
 * O Android usa o DNS declarado pela VPN, então TODAS as consultas de DNS
 * do aparelho passam por este serviço. Cada consulta é reenviada ao
 * AdGuard DNS — preferindo DoH (HTTPS:443, imune a interceptação da
 * operadora) com fallback UDP — que filtra anúncios e rastreadores.
 * A resposta é reescrita como se viesse do DNS local e devolvida ao app.
 */
public class VpnBloqService extends VpnService {

    private static final String FAKE_DNS = "10.111.222.3";
    private static final byte[] FAKE_IP = { 10, (byte) 111, (byte) 222, 3 };
    private static final byte[][] UPSTREAM = {
            { 94, (byte) 140, 14, 14 },   // AdGuard DNS "Default" (anúncios + rastreadores)
            { 94, (byte) 140, 15, 15 }
    };

    /** Bloqueio local (além do AdGuard): API de anúncios em apps e redes agressivas de sites piratas. */
    private static final String[] LOCAL_BLOCK = {
            "googlemobileads.googleapis.com",   // AdMob: anúncios dentro de jogos e apps
            "srv224.com",                       // popunder/overlay invisível (Pobreflix e similares)
            "waust.at",                         // anúncio com áudio de sites piratas
            "acscdn.com",                       // Adsterra popunder: clique em qualquer lugar → redirect
            "taigasginep.com",                  // click-under rotativa (Pobreflix)
            "servetraff.com",                   // carregador de redirecionamento (Pobreflix)
            "asiafilm.org"                      // página de propaganda reportada pelo usuário
    };

    /** Estatísticas exibidas na tela principal. */
    public static final AtomicInteger STAT_SEEN = new AtomicInteger();
    public static final AtomicInteger STAT_ANSWERED = new AtomicInteger();
    public static final AtomicInteger STAT_BLOCKED = new AtomicInteger();

    /** Preferências compartilhadas (decisão do usuário sobrevive a reinícios do processo). */
    public static final String PREFS_NAME = "bloqads";
    public static final String KEY_USER_STOPPED = "user_stopped";
    public static final String KEY_LAST_RUNNING = "last_running";

    /** Ação para recarregar a lista externa (blocks.txt) sem recriar a VPN. */
    public static final String ACTION_RELOAD = "com.henderson.adblock.RELOAD";

    private static volatile boolean running = false;
    private static VpnBloqService instance;

    static boolean isRunning() {
        return running;
    }

    public static VpnBloqService getInstance() {
        return instance;
    }

    private ParcelFileDescriptor tun;
    private volatile boolean quit = false;
    private ExecutorService pool;
    private DohClient doh;
    private SharedPreferences prefs;
    private volatile java.util.HashSet<String> extraBlocks = new java.util.HashSet<>();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Recarregar lista externa sem recriar a VPN
        if (intent != null && ACTION_RELOAD.equals(intent.getAction())) {
            loadExtraBlocks();
            return running ? START_STICKY : START_NOT_STICKY;
        }
        if (running) return START_STICKY;

        if (prefs == null) {
            prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        }
        // Se o usuário desligou o bloqueio, nenhum reinício automático pode religar
        if (intent == null && prefs.getBoolean(KEY_USER_STOPPED, false)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        prefs.edit().putBoolean(KEY_USER_STOPPED, false).putBoolean(KEY_LAST_RUNNING, true).apply();
        instance = this;
        loadExtraBlocks();

        startForegroundCompat();
        quit = false;
        STAT_SEEN.set(0);
        STAT_ANSWERED.set(0);
        STAT_BLOCKED.set(0);
        doh = new DohClient(this);
        pool = Executors.newFixedThreadPool(4);

        try {
            tun = new Builder()
                    .addAddress("10.111.222.1", 32)
                    .addDnsServer(FAKE_DNS)
                    .addRoute(FAKE_DNS, 32)
                    .setMtu(1500)
                    .setSession("BloqAds")
                    .establish();
        } catch (Exception e) {
            tun = null;
        }
        if (tun == null) {
            stopSelf();
            return START_NOT_STICKY;
        }

        running = true;
        Thread reader = new Thread(new Runnable() {
            @Override
            public void run() {
                readLoop();
            }
        }, "bloqads-reader");
        reader.start();
        return START_STICKY;
    }

    private void startForegroundCompat() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        String channelId = "bloqads";
        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new NotificationChannel(
                    channelId, "BloqAds", NotificationManager.IMPORTANCE_LOW));
            nb = new Notification.Builder(this, channelId);
        } else {
            nb = new Notification.Builder(this);
        }
        nb.setContentTitle("BloqAds ativo")
                .setContentText("Bloqueando anúncios via DNS do AdGuard")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true);
        Notification n = nb.build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(1, n);
        }
    }

    private void readLoop() {
        FileInputStream in = null;
        FileOutputStream out = null;
        try {
            in = new FileInputStream(tun.getFileDescriptor());
            out = new FileOutputStream(tun.getFileDescriptor());
            byte[] pkt = new byte[32767];
            while (!quit) {
                int len = in.read(pkt);
                if (len < 0) break;
                handlePacket(pkt, len, out);
            }
        } catch (Exception ignored) {
            // túnel fechado
        } finally {
            try { if (in != null) in.close(); } catch (Exception ignored) {}
            try { if (out != null) out.close(); } catch (Exception ignored) {}
        }
    }

    /** Lê um pacote IP do túnel; se for consulta DNS (UDP:53), reenvia ao AdGuard. */
    private void handlePacket(final byte[] b, final int len, final OutputStream out) {
        if (len < 20) return;
        if ((b[0] & 0xF0) != 0x40) return;                 // apenas IPv4
        int ihl = (b[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl + 8) return;
        int proto = b[9] & 0xFF;
        if (proto == 6) return;                            // DNS via TCP: ignorar (o cliente volta para UDP)
        if (proto != 17) return;                           // apenas UDP
        boolean fragmented = ((b[6] & 0x1F) != 0) || (b[7] != 0);
        if (fragmented) return;                            // fragmentos: ignorar
        int off = ihl;
        int sport = u16(b, off);
        int dport = u16(b, off + 2);
        if (dport != 53) return;
        int udpLen = u16(b, off + 4);
        int total = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        int dnsLen = udpLen - 8;
        if (dnsLen < 12) return;
        if (off + 8 + dnsLen > total) dnsLen = total - off - 8;
        if (dnsLen < 12) return;

        STAT_SEEN.incrementAndGet();

        final byte[] dns = Arrays.copyOfRange(b, off + 8, off + 8 + dnsLen);
        final byte[] srcIp = Arrays.copyOfRange(b, 12, 16);
        final int fSport = sport;
        final OutputStream fOut = out;

        // Bloqueio local: responde direto (NXDOMAIN), sem consultar o AdGuard
        String qname = decodeQname(dns);
        if (qname != null && isLocallyBlocked(qname)) {
            STAT_BLOCKED.incrementAndGet();
            try {
                fOut.write(buildResponse(nxDomain(dns), srcIp, fSport));
            } catch (Exception ignored) {
            }
            return;
        }

        try {
            pool.execute(new Runnable() {
                @Override
                public void run() {
                    answer(dns, srcIp, fSport, fOut);
                }
            });
        } catch (Exception ignored) {
            // serviço sendo desligado
        }
    }

    private void answer(byte[] dns, byte[] srcIp, int sport, OutputStream out) {
        byte[] resp = queryUpstream(dns);
        if (resp == null) return;
        STAT_ANSWERED.incrementAndGet();
        if (isBlocked(resp)) STAT_BLOCKED.incrementAndGet();
        try {
            out.write(buildResponse(resp, srcIp, sport));
        } catch (Exception ignored) {
        }
    }

    /** DoH primeiro (HTTPS:443, não é interceptado); UDP como fallback. */
    private byte[] queryUpstream(byte[] dns) {
        DohClient d = doh;
        if (d != null) {
            byte[] r = d.query(dns);
            if (r != null) return r;
        }
        return udpQuery(dns);
    }

    /** Consulta os servidores do AdGuard via UDP direto. */
    private byte[] udpQuery(byte[] dns) {
        for (byte[] server : UPSTREAM) {
            DatagramSocket s = null;
            try {
                s = new DatagramSocket();
                protect(s);
                s.setSoTimeout(2500);
                s.connect(new InetSocketAddress(InetAddress.getByAddress(server), 53));
                s.send(new DatagramPacket(dns, dns.length));
                byte[] buf = new byte[4096];
                DatagramPacket rp = new DatagramPacket(buf, buf.length);
                s.receive(rp);
                if (rp.getLength() >= 12) return Arrays.copyOf(buf, rp.getLength());
            } catch (Exception ignored) {
            } finally {
                if (s != null) s.close();
            }
        }
        return null;
    }

    /** Detecta resposta de bloqueio do AdGuard: A=0.0.0.0 ou AAAA=::. */
    private static boolean isBlocked(byte[] r) {
        int len = r.length;
        if (len < 12) return false;
        int qd = u16(r, 4);
        int an = u16(r, 6);
        int i = 12;
        for (int k = 0; k < qd; k++) {
            i = DohClient.skipName(r, i, len);
            if (i < 0) return false;
            i += 4;
        }
        for (int k = 0; k < an; k++) {
            i = DohClient.skipName(r, i, len);
            if (i < 0) return false;
            if (i + 10 > len) return false;
            int type = u16(r, i);
            int rdlen = u16(r, i + 8);
            i += 10;
            if (i + rdlen > len) return false;
            if (type == 1 && rdlen == 4) {
                if (r[i] == 0 && r[i + 1] == 0 && r[i + 2] == 0 && r[i + 3] == 0) return true;
            } else if (type == 28 && rdlen == 16) {
                boolean zero = true;
                for (int m = 0; m < 16; m++) {
                    if (r[i + m] != 0) { zero = false; break; }
                }
                if (zero) return true;
            }
            i += rdlen;
        }
        return false;
    }

    /** Decodifica o QNAME (nome consultado) de um pacote DNS. */
    private static String decodeQname(byte[] d) {
        try {
            int i = 12;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (i >= d.length) return null;
                int l = d[i] & 0xFF;
                if (l == 0) break;
                if ((l & 0xC0) != 0) return null;
                if (i + 1 + l > d.length) return null;
                for (int j = 0; j < l; j++) sb.append((char) (d[i + 1 + j] & 0xFF));
                sb.append('.');
                i += 1 + l;
            }
            String q = sb.toString().toLowerCase(java.util.Locale.US);
            if (q.length() <= 1) return null;
            return q.substring(0, q.length() - 1);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isLocallyBlocked(String qname) {
        for (String s : LOCAL_BLOCK) {
            if (qname.equals(s) || qname.endsWith("." + s)) return true;
        }
        return inSuffixSet(qname, extraBlocks);
    }

    /** true se qname ou qualquer sufixo dele está no conjunto (cdn77.srv224.com casa com srv224.com). */
    private static boolean inSuffixSet(String qname, java.util.HashSet<String> set) {
        if (set.isEmpty()) return false;
        int i = 0;
        while (i < qname.length()) {
            if (set.contains(qname.substring(i))) return true;
            int dot = qname.indexOf('.', i);
            if (dot < 0) break;
            i = dot + 1;
        }
        return false;
    }

    /** Carrega a lista externa: <app files>/blocks.txt — um domínio por linha, # = comentário.
     *  Aceita também o formato hosts "0.0.0.0 dominio". Atualizável via USB sem reinstalar. */
    private void loadExtraBlocks() {
        try {
            java.io.File f = new java.io.File(getExternalFilesDir(null), "blocks.txt");
            if (!f.exists()) return;
            java.util.HashSet<String> set = new java.util.HashSet<>();
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(f));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim().toLowerCase(java.util.Locale.US);
                if (line.isEmpty() || line.startsWith("#")) continue;
                int sp = line.indexOf(' ');
                if (sp > 0) line = line.substring(sp).trim();   // formato "0.0.0.0 dominio"
                if (line.isEmpty() || line.startsWith("#")) continue;
                set.add(line);
            }
            r.close();
            if (!set.isEmpty()) extraBlocks = set;
        } catch (Exception ignored) {
        }
    }

    /** Resposta NXDOMAIN (RCODE=3) construída a partir da consulta original. */
    private static byte[] nxDomain(byte[] query) {
        try {
            int i = 12;
            while (true) {
                if (i >= query.length) throw new RuntimeException("qname invalido");
                int l = query[i] & 0xFF;
                if (l == 0) { i++; break; }
                if ((l & 0xC0) != 0) { i += 2; break; }
                i += 1 + l;
            }
            i += 4; // QTYPE + QCLASS
            if (i > query.length) throw new RuntimeException("consulta truncada");
            byte[] r = Arrays.copyOf(query, i);
            r[2] |= (byte) 0x80;                          // QR = 1 (é resposta)
            r[3] = (byte) ((r[3] & 0xF0) | 0x80 | 0x03);  // RA = 1, RCODE = 3 (NXDOMAIN)
            r[6] = 0; r[7] = 0;                           // ANCOUNT
            r[8] = 0; r[9] = 0;                           // NSCOUNT
            r[10] = 0; r[11] = 0;                         // ARCOUNT
            return r;
        } catch (Exception e) {
            byte[] f = { 0, 0, (byte) 0x81, (byte) 0x83, 0, 0, 0, 0, 0, 0, 0, 0 };
            return f;
        }
    }

    /** Monta o pacote de resposta (IP+UDP) como se viesse do DNS local 10.111.222.3. */
    private static byte[] buildResponse(byte[] resp, byte[] srcIp, int sport) {
        int udpLen = 8 + resp.length;
        int total = 20 + udpLen;
        byte[] o = new byte[total];

        // Cabeçalho IPv4
        o[0] = 0x45;
        o[1] = 0;
        o[2] = (byte) (total >> 8);
        o[3] = (byte) total;
        o[4] = 0; o[5] = 0;                                 // ID
        o[6] = 0; o[7] = 0;                                 // flags/fragmento
        o[8] = 64;                                          // TTL
        o[9] = 17;                                          // UDP
        o[10] = 0; o[11] = 0;                               // checksum (provisório)
        o[12] = FAKE_IP[0]; o[13] = FAKE_IP[1];
        o[14] = FAKE_IP[2]; o[15] = FAKE_IP[3];
        o[16] = srcIp[0]; o[17] = srcIp[1];
        o[18] = srcIp[2]; o[19] = srcIp[3];
        int cs = fold(rawSum(o, 0, 20));
        o[10] = (byte) (cs >> 8);
        o[11] = (byte) cs;

        // Cabeçalho UDP
        o[20] = 0; o[21] = 53;                              // porta de origem = 53
        o[22] = (byte) (sport >> 8);
        o[23] = (byte) sport;
        o[24] = (byte) (udpLen >> 8);
        o[25] = (byte) udpLen;
        o[26] = 0; o[27] = 0;                               // checksum (provisório)
        System.arraycopy(resp, 0, o, 28, resp.length);

        cs = fold(rawSum(FAKE_IP, 0, 4) + rawSum(srcIp, 0, 4) + 17 + udpLen + rawSum(o, 20, udpLen));
        if (cs == 0) cs = 0xFFFF;
        o[26] = (byte) (cs >> 8);
        o[27] = (byte) cs;
        return o;
    }

    /** Desliga já: fecha o túnel — o sistema desanexa o bind e então destrói o serviço. */
    public void disconnectNow() {
        if (prefs != null) {
            prefs.edit().putBoolean(KEY_USER_STOPPED, true).putBoolean(KEY_LAST_RUNNING, false).apply();
        }
        quit = true;
        running = false;
        ParcelFileDescriptor t = tun;
        tun = null;
        if (t != null) {
            try { t.close(); } catch (Exception ignored) {}
        }
        stopSelf();
    }

    @Override
    public void onRevoke() {
        stopSelf();
    }

    @Override
    public void onDestroy() {
        quit = true;
        running = false;
        instance = null;
        if (tun != null) {
            try { tun.close(); } catch (Exception ignored) {}
        }
        if (doh != null) doh.close();
        if (pool != null) pool.shutdownNow();
        super.onDestroy();
    }

    private static int u16(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF);
    }

    private static int rawSum(byte[] b, int off, int len) {
        int sum = 0;
        int i = 0;
        for (; i + 1 < len; i += 2) {
            sum += ((b[off + i] & 0xFF) << 8) | (b[off + i + 1] & 0xFF);
        }
        if ((len & 1) != 0) sum += (b[off + i] & 0xFF) << 8;
        return sum;
    }

    private static int fold(int sum) {
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~sum & 0xFFFF;
    }
}
