package io.github.yunyizea.xsofprivacy;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Switch;

/** Launcher and LSPosed settings entry. Intents never change preferences. */
public final class SettingsActivity extends Activity {
    private Switch detailedLogging;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_settings);
        android.view.View root = findViewById(R.id.settings_root);
        int padding = getResources().getDimensionPixelSize(R.dimen.settings_padding);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(padding + insets.getSystemWindowInsetLeft(),
                    padding + insets.getSystemWindowInsetTop(),
                    padding + insets.getSystemWindowInsetRight(),
                    padding + insets.getSystemWindowInsetBottom());
            return insets;
        });
        root.requestApplyInsets();
        detailedLogging = findViewById(R.id.detailed_logging);
        detailedLogging.setChecked(LoggingSettings.readLocal(this));
        detailedLogging.setOnCheckedChangeListener((button, enabled) ->
                LoggingSettings.preferences(this).edit()
                        .putBoolean(LoggingSettings.ENABLED, enabled).apply());
    }

    @Override protected void onResume() {
        super.onResume();
        detailedLogging.setChecked(LoggingSettings.readLocal(this));
    }
}
