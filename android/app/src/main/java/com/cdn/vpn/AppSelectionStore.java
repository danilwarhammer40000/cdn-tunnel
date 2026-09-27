package com.cdn.vpn;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

/**
 * Какие приложения гонять через туннель. Три режима:
 *   ALL     — как раньше, весь трафик устройства (кроме самого клиента);
 *   ONLY    — в туннель идут ТОЛЬКО выбранные приложения, у остальных обычный интернет;
 *   EXCEPT  — в туннель идёт всё, КРОМЕ выбранных (они работают в обход VPN).
 *
 * Список хранит имена пакетов (например "com.android.chrome"), а не отображаемые
 * названия — они не меняются при переустановке/обновлении приложения.
 */
public class AppSelectionStore {

    public enum Mode { ALL, ONLY, EXCEPT }

    private static final String PREFS = "cdntunnel_apps";
    private static final String KEY_MODE = "mode";
    private static final String KEY_PKGS = "packages";

    public Mode mode = Mode.ALL;
    public Set<String> packages = new HashSet<>();

    public static AppSelectionStore load(Context ctx) {
        SharedPreferences p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        AppSelectionStore s = new AppSelectionStore();
        String m = p.getString(KEY_MODE, Mode.ALL.name());
        try { s.mode = Mode.valueOf(m); } catch (IllegalArgumentException ignored) { s.mode = Mode.ALL; }
        s.packages = new HashSet<>(p.getStringSet(KEY_PKGS, new HashSet<>()));
        return s;
    }

    public void save(Context ctx) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_MODE, mode.name())
                .putStringSet(KEY_PKGS, packages)
                .apply();
    }

    /** Короткая подпись для кнопки на главном экране. */
    public String summary() {
        switch (mode) {
            case ONLY:   return "только выбранные (" + packages.size() + ")";
            case EXCEPT: return "все, кроме " + packages.size();
            default:     return "все";
        }
    }
}
