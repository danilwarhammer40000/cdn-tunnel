package com.cdn.vpn;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.text.Collator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Выбор приложений для туннеля: «Все», «Только выбранные» или «Все, кроме
 * выбранных». Список показывает установленные приложения с иконкой лаунчера
 * (только те, что можно запустить, — системные службы без своего значка в
 * списке не нужны). Выбор действует со следующего запуска VPN.
 */
public class AppSelectionActivity extends AppCompatActivity {

    /** Одна строка списка. */
    private static class AppEntry {
        String pkg, label;
        Drawable icon;
    }

    private MaterialButtonToggleGroup group;
    private MaterialButton btnAll, btnOnly, btnExcept;
    private TextView tvHint;
    private View searchBox;
    private EditText etSearch;
    private ListView list;
    private LinearProgressIndicator progress;
    private Adapter adapter;

    private AppSelectionStore.Mode mode = AppSelectionStore.Mode.ALL;
    private final Set<String> selected = new HashSet<>();
    private List<AppEntry> all = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_selection);
        setTitle("Приложения в туннеле");

        group = findViewById(R.id.toggle_mode);
        btnAll = findViewById(R.id.btn_mode_all);
        btnOnly = findViewById(R.id.btn_mode_only);
        btnExcept = findViewById(R.id.btn_mode_except);
        tvHint = findViewById(R.id.tv_mode_hint);
        searchBox = findViewById(R.id.til_search);
        etSearch = findViewById(R.id.et_search);
        list = findViewById(R.id.list_apps);
        progress = findViewById(R.id.progress_apps);

        AppSelectionStore store = AppSelectionStore.load(this);
        mode = store.mode;
        selected.addAll(store.packages);

        group.addOnButtonCheckedListener((g, checkedId, isChecked) -> {
            if (!isChecked) return;
            if (checkedId == R.id.btn_mode_all) mode = AppSelectionStore.Mode.ALL;
            else if (checkedId == R.id.btn_mode_only) mode = AppSelectionStore.Mode.ONLY;
            else mode = AppSelectionStore.Mode.EXCEPT;
            renderMode();
        });
        checkModeButton();
        renderMode();

        adapter = new Adapter();
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, v, position, id) -> {
            AppEntry e = (AppEntry) adapter.getItem(position);
            if (e == null) return;
            if (selected.contains(e.pkg)) selected.remove(e.pkg); else selected.add(e.pkg);
            CheckBox cb = v.findViewById(R.id.cb_app);
            if (cb != null) cb.setChecked(selected.contains(e.pkg));
        });
        etSearch.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(android.text.Editable s) { adapter.getFilter().filter(s); }
        });

        loadApps();
    }

    @Override
    protected void onPause() {
        super.onPause();
        AppSelectionStore store = new AppSelectionStore();
        store.mode = mode;
        store.packages = new HashSet<>(selected);
        store.save(this);
    }

    private void checkModeButton() {
        int id = mode == AppSelectionStore.Mode.ONLY ? R.id.btn_mode_only
                : mode == AppSelectionStore.Mode.EXCEPT ? R.id.btn_mode_except : R.id.btn_mode_all;
        group.check(id);
    }

    private void renderMode() {
        boolean pick = mode != AppSelectionStore.Mode.ALL;
        list.setVisibility(pick ? View.VISIBLE : View.GONE);
        searchBox.setVisibility(pick ? View.VISIBLE : View.GONE);
        switch (mode) {
            case ONLY:
                tvHint.setText("Через туннель пойдут только отмеченные приложения. Остальные будут работать через обычный интернет, в обход VPN.");
                break;
            case EXCEPT:
                tvHint.setText("Через туннель пойдёт весь трафик, КРОМЕ отмеченных приложений — они будут работать в обход VPN.");
                break;
            default:
                tvHint.setText("Через туннель идёт весь трафик устройства (как раньше). Собственный трафик приложения — всегда в обход VPN.");
        }
    }

    /** Список приложений — тяжёлая операция (PackageManager), делаем в фоне. */
    private void loadApps() {
        progress.setVisibility(View.VISIBLE);
        new AsyncTask<Void, Void, List<AppEntry>>() {
            @Override protected List<AppEntry> doInBackground(Void... v) {
                PackageManager pm = getPackageManager();
                Intent launchable = new Intent(Intent.ACTION_MAIN);
                launchable.addCategory(Intent.CATEGORY_LAUNCHER);
                List<ResolveInfo> ri = pm.queryIntentActivities(launchable, 0);
                List<AppEntry> out = new ArrayList<>();
                String self = getPackageName();
                Set<String> seen = new HashSet<>();
                for (ResolveInfo r : ri) {
                    ApplicationInfo ai = r.activityInfo.applicationInfo;
                    if (ai.packageName.equals(self)) continue; // свой трафик и так всегда в обход
                    if (!seen.add(ai.packageName)) continue;
                    AppEntry e = new AppEntry();
                    e.pkg = ai.packageName;
                    e.label = String.valueOf(pm.getApplicationLabel(ai));
                    try { e.icon = pm.getApplicationIcon(ai); } catch (Exception ignored) {}
                    out.add(e);
                }
                Collator col = Collator.getInstance(Locale.getDefault());
                out.sort((a, b) -> col.compare(a.label, b.label));
                return out;
            }
            @Override protected void onPostExecute(List<AppEntry> result) {
                if (isFinishing()) return;
                all = result;
                progress.setVisibility(View.GONE);
                adapter.setData(all);
                if (all.isEmpty()) {
                    Toast.makeText(AppSelectionActivity.this, "Не удалось получить список приложений", Toast.LENGTH_SHORT).show();
                }
            }
        }.execute();
    }

    /** Простой адаптер: иконка, название, пакет мельче под ним, чекбокс. */
    private class Adapter extends android.widget.BaseAdapter implements Filterable {
        private List<AppEntry> shown = new ArrayList<>();

        void setData(List<AppEntry> data) { shown = data; notifyDataSetChanged(); }

        @Override public int getCount() { return shown.size(); }
        @Override public Object getItem(int i) { return shown.get(i); }
        @Override public long getItemId(int i) { return i; }

        @Override public View getView(int i, View convertView, ViewGroup parent) {
            View v = convertView;
            if (v == null) {
                v = LayoutInflater.from(AppSelectionActivity.this).inflate(R.layout.item_app, parent, false);
            }
            AppEntry e = shown.get(i);
            ((ImageView) v.findViewById(R.id.iv_icon)).setImageDrawable(e.icon);
            ((TextView) v.findViewById(R.id.tv_label)).setText(e.label);
            ((TextView) v.findViewById(R.id.tv_pkg)).setText(e.pkg);
            ((CheckBox) v.findViewById(R.id.cb_app)).setChecked(selected.contains(e.pkg));
            return v;
        }

        @Override public Filter getFilter() {
            return new Filter() {
                @Override protected FilterResults performFiltering(CharSequence q) {
                    String needle = q == null ? "" : q.toString().trim().toLowerCase(Locale.getDefault());
                    List<AppEntry> out = new ArrayList<>();
                    for (AppEntry e : all) {
                        if (needle.isEmpty()
                                || e.label.toLowerCase(Locale.getDefault()).contains(needle)
                                || e.pkg.toLowerCase(Locale.getDefault()).contains(needle)) {
                            out.add(e);
                        }
                    }
                    FilterResults r = new FilterResults();
                    r.values = out;
                    r.count = out.size();
                    return r;
                }
                @SuppressWarnings("unchecked")
                @Override protected void publishResults(CharSequence q, FilterResults r) {
                    shown = (List<AppEntry>) r.values;
                    notifyDataSetChanged();
                }
            };
        }
    }
}
