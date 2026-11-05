package io.github.yunyizea.xsofprivacy;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;

/** Private settings; the provider exposes only the non-sensitive logging flag. */
final class LoggingSettings {
    static final String AUTHORITY = "io.github.yunyizea.xsofprivacy.settings";
    static final String READ = "getDetailedLogging";
    static final String ENABLED = "detailed_logging";
    private static final Uri URI = Uri.parse("content://" + AUTHORITY);

    private LoggingSettings() {}

    static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences("logging", Context.MODE_PRIVATE);
    }

    static boolean readLocal(Context context) {
        return preferences(context).getBoolean(ENABLED, false);
    }

    static boolean readRemote(Context context) {
        // Hooks may run inside someone else's Binder transaction. Read as the host process.
        long identity = Binder.clearCallingIdentity();
        try {
            Bundle reply = context.getContentResolver().call(URI, READ, null, null);
            return reply != null && reply.getBoolean(ENABLED, false);
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }
}
