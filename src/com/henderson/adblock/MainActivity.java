package com.henderson.adblock;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final int VPN_REQUEST = 7;
    private static final int RED = 0xFFFF5555;

    private TextView status;
    private TextView stats;
    private TextView warn;
    private Button toggle;
    private Handler handler;
    private boolean captureWarnShown = false;

    private final Runnable refresh = new Runnable() {
        @Override
        public void run() {
            boolean on = VpnBloqService.isRunning();
            if (on) {
                int seen = VpnBloqService.STAT_SEEN.get();
                int blocked = VpnBloqService.STAT_BLOCKED.get();
                stats.setText("Consultas: " + seen + "   •   Bloqueadas: " + blocked);
                if (seen == 0 && !captureWarnShown) {
                    captureWarnShown = true;
                    warn.setTextColor(RED);
                    warn.setText("⚠️ Nenhuma consulta está chegando ao BloqAds.\n"
                            + "Causa provável: \"DNS privado\" ativado no Android.\n"
                            + "Desative em: Configurações → Rede e Internet → DNS privado.");
                }
            }
            updateUi();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        handler = new Handler(Looper.getMainLooper());
        if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{ Manifest.permission.POST_NOTIFICATIONS }, 3);
        }

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad * 2, pad, pad);

        TextView title = new TextView(this);
        title.setText("BloqAds");
        title.setTextSize(30);
        title.setGravity(Gravity.CENTER);

        status = new TextView(this);
        status.setTextSize(17);
        status.setGravity(Gravity.CENTER);
        status.setPadding(0, pad, 0, 0);

        stats = new TextView(this);
        stats.setTextSize(15);
        stats.setGravity(Gravity.CENTER);
        stats.setPadding(0, 8, 0, 0);

        warn = new TextView(this);
        warn.setTextSize(13);
        warn.setPadding(0, pad / 2, 0, 0);

        toggle = new Button(this);
        toggle.setTextSize(18);
        toggle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleVpn();
            }
        });

        Button battery = new Button(this);
        battery.setTextSize(14);
        battery.setText("Permitir em segundo plano");
        battery.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestBatteryIgnore();
            }
        });
        if (Build.VERSION.SDK_INT < 23) battery.setVisibility(View.GONE);

        TextView info = new TextView(this);
        info.setTextSize(14);
        info.setPadding(0, pad, 0, 0);
        info.setText("Bloqueia anúncios e rastreadores no navegador e na maioria dos apps, "
                + "usando o DNS do AdGuard (DoH) através de uma VPN local no próprio aparelho.\n\n"
                + "• Anúncios dentro do app oficial do YouTube não são bloqueáveis por DNS. "
                + "Para YouTube sem anúncios, assista pelo navegador com o BloqAds ligado.\n"
                + "• Não use \"DNS privado\" no Android enquanto o BloqAds estiver ativo.");

        root.addView(title);
        root.addView(status);
        root.addView(stats);
        root.addView(warn);
        root.addView(toggle);
        root.addView(battery);

        Button reload = new Button(this);
        reload.setTextSize(14);
        reload.setText("Recarregar lista de bloqueio");
        reload.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startService(new Intent(MainActivity.this, VpnBloqService.class)
                        .setAction(VpnBloqService.ACTION_RELOAD));
                updateStatusText("Lista de bloqueio recarregada.");
            }
        });
        root.addView(reload);

        root.addView(info);
        setContentView(root);
        updateUi();
        checkPrivateDnsSetting();

        // Reconecta sozinho SOMENTE se estava ativo antes (ex.: após atualização)
        SharedPreferences p = getSharedPreferences(VpnBloqService.PREFS_NAME, MODE_PRIVATE);
        if (!VpnBloqService.isRunning() && VpnService.prepare(this) == null
                && p.getBoolean(VpnBloqService.KEY_LAST_RUNNING, false)) {
            startVpn();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(refresh);
        // Recarrega a lista externa ao abrir o app (para atualizações via USB)
        if (VpnBloqService.isRunning()) {
            startService(new Intent(this, VpnBloqService.class).setAction(VpnBloqService.ACTION_RELOAD));
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(refresh);
    }

    /** Avisa se o aparelho tem DNS privado em modo restrito (burla o BloqAds). */
    private void checkPrivateDnsSetting() {
        if (Build.VERSION.SDK_INT < 28) return;
        try {
            String mode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
            if ("hostname".equalsIgnoreCase(mode)) {
                warn.setTextColor(RED);
                warn.setText("⚠️ Você tem \"DNS privado\" em modo restrito configurado. "
                        + "Ele desliga o BloqAds! Desative em: Configurações → Rede e Internet → DNS privado.");
            }
        } catch (Exception ignored) {
        }
    }

    private void updateUi() {
        boolean on = VpnBloqService.isRunning();
        status.setText(on ? "🟢 Bloqueio LIGADO" : "🔴 Bloqueio desligado");
        toggle.setText(on ? "Desligar bloqueio" : "Ligar bloqueio");
    }

    private void requestBatteryIgnore() {
        if (Build.VERSION.SDK_INT < 23) return;
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm.isIgnoringBatteryOptimizations(getPackageName())) {
            updateStatusText("Já está otimizado para segundo plano.");
            return;
        }
        try {
            startActivity(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:" + getPackageName())));
        } catch (Exception e) {
            updateStatusText("Não foi possível abrir as configurações.");
        }
    }

    private void updateStatusText(String s) {
        status.setText(s);
    }

    private void toggleVpn() {
        SharedPreferences p = getSharedPreferences(VpnBloqService.PREFS_NAME, MODE_PRIVATE);
        if (VpnBloqService.isRunning()) {
            // Registrar a decisão ANTES de tudo: nenhum reinício automático reverte
            p.edit().putBoolean(VpnBloqService.KEY_USER_STOPPED, true)
                    .putBoolean(VpnBloqService.KEY_LAST_RUNNING, false).apply();
            VpnBloqService svc = VpnBloqService.getInstance();
            if (svc != null) svc.disconnectNow();
            stopService(new Intent(this, VpnBloqService.class));
            updateUi();
            return;
        }
        p.edit().putBoolean(VpnBloqService.KEY_USER_STOPPED, false).apply();
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, VPN_REQUEST);
        } else {
            startVpn();
        }
    }

    private void startVpn() {
        Intent i = new Intent(this, VpnBloqService.class);
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(i);
        } else {
            startService(i);
        }
        updateUi();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) {
                startVpn();
            } else {
                status.setText("Permissão de VPN negada");
            }
        }
    }
}
